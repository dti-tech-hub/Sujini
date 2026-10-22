"""Transparent, weighted risk scoring.

The formula is deliberately visible:

    score = 100 * Σ(weight_i * normalized_factor_i)

Every factor's raw value, normalization, weight, and contribution is recorded
so analysts can audit the result. Thresholds and weights are project
parameters and are not claimed to be universal cybersecurity standards.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from src.database.models import Incident
from src.risk.severity import risk_level_for
from src.utils.config import get_risk_rules
from src.utils.helpers import clamp, ensure_utc, utcnow
from src.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RiskResult:
    score: float
    level: str
    factors: dict[str, Any]
    weights: dict[str, float]
    explanation: str
    recurrence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "level": self.level,
            "factors": self.factors,
            "weights": self.weights,
            "explanation": self.explanation,
            "recurrence_count": self.recurrence_count,
        }


class RiskScorer:
    def __init__(self, session: Session | None = None) -> None:
        self.rules = get_risk_rules()
        self.session = session
        self.weights = {key: float(value) for key, value in self.rules.get("weights", {}).items()}
        total = sum(self.weights.values())
        if total <= 0:
            raise ValueError("Risk weights must sum to a positive value")
        # Normalize weights defensively if configuration drifts from 1.0.
        if abs(total - 1.0) > 1e-6:
            logger.warning("Risk weights sum to %.4f; normalizing", total)
            self.weights = {key: value / total for key, value in self.weights.items()}

    def _asset_criticality(self, endpoints: list[str]) -> tuple[float, str]:
        mapping = self.rules.get("asset_criticality", {})
        best = float(mapping.get("/", 0.4))
        best_prefix = "/"
        for endpoint in endpoints:
            path = (endpoint or "/").split("?", 1)[0]
            for prefix, value in mapping.items():
                if path.startswith(prefix) and float(value) > best:
                    best = float(value)
                    best_prefix = prefix
        return best, best_prefix

    def _recurrence(self, incident_id: str, source_ip: str | None, username: str | None) -> int:
        if not self.session:
            return 0
        cap = int(self.rules.get("recurrence_window_days", 30))
        cutoff = utcnow() - timedelta(days=cap)
        clauses = []
        if source_ip:
            clauses.append(Incident.source_ip == source_ip)
        if username:
            clauses.append(Incident.username == username)
        if not clauses:
            return 0
        query = select(func.count(Incident.id)).where(
            Incident.id != incident_id,
            Incident.created_at >= cutoff,
            or_(*clauses),
        )
        return int(self.session.scalar(query) or 0)

    def score(
        self,
        *,
        incident_id: str,
        severity: str,
        confidence: float,
        category: str,
        event_count: int,
        source_ip: str | None = None,
        username: str | None = None,
        endpoints: list[str] | None = None,
        threat_intel: dict[str, Any] | None = None,
    ) -> RiskResult:
        endpoints = endpoints or []
        severity_map = self.rules.get("severity_scores", {})
        impact_map = self.rules.get("impact_weights", {})
        ti_map = self.rules.get("threat_intel_risk", {})

        severity_norm = float(severity_map.get((severity or "MEDIUM").upper(), 0.5))
        confidence_norm = clamp(float(confidence), 0.0, 1.0)
        asset_norm, asset_prefix = self._asset_criticality(endpoints)
        intel = threat_intel or {}
        ti_verdict = str(intel.get("verdict", "unknown")).lower()
        ti_norm = float(ti_map.get(ti_verdict, ti_map.get("unknown", 0.3)))
        volume_cap = max(1, int(self.rules.get("event_volume_cap", 20)))
        volume_norm = clamp(event_count / volume_cap, 0.0, 1.0)
        impact_norm = float(impact_map.get(category, impact_map.get("suspicious_activity", 0.35)))
        recurrence_count = self._recurrence(incident_id, source_ip, username)
        recurrence_cap = max(1, int(self.rules.get("recurrence_cap", 5)))
        recurrence_norm = clamp(recurrence_count / recurrence_cap, 0.0, 1.0)

        normalized = {
            "severity": severity_norm,
            "confidence": confidence_norm,
            "asset_criticality": asset_norm,
            "threat_intel": ti_norm,
            "event_volume": volume_norm,
            "attack_impact": impact_norm,
            "recurrence": recurrence_norm,
        }
        factors: dict[str, Any] = {}
        total = 0.0
        for key, norm in normalized.items():
            weight = self.weights.get(key, 0.0)
            contribution = weight * norm
            total += contribution
            factors[key] = {
                "normalized": round(norm, 4),
                "weight": round(weight, 4),
                "contribution": round(contribution, 4),
            }
        factors["severity"]["raw"] = severity
        factors["confidence"]["raw"] = round(float(confidence), 4)
        factors["asset_criticality"]["raw"] = {"prefix": asset_prefix, "endpoints": endpoints[:10]}
        factors["threat_intel"]["raw"] = {
            "verdict": ti_verdict,
            "mode": intel.get("mode", "NOT_QUERIED"),
            "is_mock": intel.get("is_mock", None),
        }
        factors["event_volume"]["raw"] = event_count
        factors["attack_impact"]["raw"] = category
        factors["recurrence"]["raw"] = {"prior_incidents_30d": recurrence_count}
        score = round(clamp(total * 100.0, 0.0, 100.0), 2)
        level = risk_level_for(score)

        parts = [
            f"Risk score {score:.2f}/100 ({level}).",
            f"Severity '{severity}' contributes {factors['severity']['contribution'] * 100:.2f}.",
            f"Investigation confidence {confidence_norm:.2f} contributes {factors['confidence']['contribution'] * 100:.2f}.",
            f"Asset criticality {asset_norm:.2f} (prefix {asset_prefix}) contributes {factors['asset_criticality']['contribution'] * 100:.2f}.",
            f"Threat-intel verdict '{ti_verdict}' contributes {factors['threat_intel']['contribution'] * 100:.2f}.",
            f"Event volume {event_count} (normalized {volume_norm:.2f}) contributes {factors['event_volume']['contribution'] * 100:.2f}.",
            f"Attack impact '{category}' contributes {factors['attack_impact']['contribution'] * 100:.2f}.",
            f"Recurrence {recurrence_count} prior incident(s) contributes {factors['recurrence']['contribution'] * 100:.2f}.",
            "Threat-intel factor is DEMO/MOCK data." if intel.get("is_mock") else "",
            "Weights and thresholds are project-defined parameters.",
        ]
        explanation = " ".join(part for part in parts if part)
        return RiskResult(
            score=score,
            level=level,
            factors=factors,
            weights=self.weights,
            explanation=explanation,
            recurrence_count=recurrence_count,
        )


def explain_formula() -> dict[str, Any]:
    rules = get_risk_rules()
    return {
        "formula": "score = 100 * sum(weight_i * normalized_factor_i)",
        "weights": rules.get("weights", {}),
        "thresholds": rules.get("thresholds", {}),
        "note": "Project-defined parameters; not universal cybersecurity standards.",
    }
