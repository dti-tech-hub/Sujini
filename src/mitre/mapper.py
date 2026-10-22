"""MITRE ATT&CK mapping from observed behaviors and evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.utils.config import get_mitre_config
from src.utils.helpers import clamp, utcnow


@dataclass
class TechniqueMapping:
    technique_id: str
    technique_name: str
    tactic: str
    tactics: list[str]
    subtechnique: str | None
    confidence: float
    mapping_status: str
    rationale: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    url: str | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactics": self.tactics,
            "subtechnique": self.subtechnique,
            "confidence": round(self.confidence, 3),
            "mapping_status": self.mapping_status,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.to_record()
        payload["url"] = self.url
        return payload


@dataclass
class MappingResult:
    techniques: list[TechniqueMapping]
    behaviors: list[str]
    unmapped_behaviors: list[str]
    note: str


class MitreMapper:
    def __init__(self) -> None:
        self.config = get_mitre_config()
        self.techniques = self.config.get("techniques", [])
        self.confirmed_threshold = float(self.config.get("confirmed_threshold", 0.75))

    def derive_behaviors(
        self,
        *,
        classification: str,
        alert_types: list[str],
        confidence: float,
        event_count: int,
    ) -> list[str]:
        behaviors = set(alert_types)
        if classification and classification not in {"benign_or_unknown", "suspicious_activity"}:
            behaviors.add(classification)
        if classification == "account_compromise":
            behaviors.add("successful_login_after_failures")
        if "brute_force" in behaviors:
            behaviors.add("repeated_failed_login")
        if "recon_scanning" in behaviors or "suspicious_user_agent" in behaviors:
            behaviors.add("recon_scanning")
        # Only retain behaviors that have a configured mapping or are useful
        # for explaining that no defensible mapping exists.
        return sorted(behaviors)

    def map(
        self,
        *,
        classification: str,
        alert_types: list[str],
        confidence: float,
        alerts: list[Any] | None = None,
        event_count: int = 0,
    ) -> MappingResult:
        alerts = alerts or []
        behaviors = self.derive_behaviors(
            classification=classification,
            alert_types=alert_types,
            confidence=confidence,
            event_count=event_count,
        )
        mapped: dict[str, TechniqueMapping] = {}
        unmapped: list[str] = []
        for behavior in behaviors:
            matches = [tech for tech in self.techniques if behavior in tech.get("behaviors", [])]
            if not matches:
                if behavior not in {"successful_login_after_failures"}:
                    unmapped.append(behavior)
                continue
            for tech in matches:
                evidence = self._evidence_for(behavior, alerts, classification, event_count)
                base = float(tech.get("base_confidence", 0.5))
                corroboration = min(max(len(evidence), 1), 4)
                adjusted = base + 0.02 * (corroboration - 1)
                if confidence < 0.60:
                    adjusted = min(adjusted, 0.70)
                adjusted = clamp(adjusted, 0.0, 0.98)
                status = "confirmed" if adjusted >= self.confirmed_threshold else "candidate"
                technique_id = str(tech["technique_id"])
                if technique_id in mapped:
                    existing = mapped[technique_id]
                    existing.confidence = max(existing.confidence, adjusted)
                    existing.evidence.extend(evidence)
                    existing.evidence = self._dedupe_evidence(existing.evidence)
                    existing.mapping_status = "confirmed" if existing.confidence >= self.confirmed_threshold else "candidate"
                else:
                    mapped[technique_id] = TechniqueMapping(
                        technique_id=technique_id,
                        technique_name=str(tech["technique_name"]),
                        tactic=str((tech.get("tactics") or ["Unknown"])[0]),
                        tactics=list(tech.get("tactics") or []),
                        subtechnique=tech.get("subtechnique"),
                        confidence=adjusted,
                        mapping_status=status,
                        rationale=str(tech.get("rationale", "")),
                        evidence=self._dedupe_evidence(evidence),
                        url=tech.get("url"),
                    )

        ordered = sorted(mapped.values(), key=lambda item: (-item.confidence, item.technique_id))
        if ordered:
            note = (
                f"{sum(1 for item in ordered if item.mapping_status == 'confirmed')} confirmed and "
                f"{sum(1 for item in ordered if item.mapping_status == 'candidate')} candidate mappings. "
                "Confidence is heuristic and not a statistical probability."
            )
        else:
            note = (
                "No defensible ATT&CK technique mapping was produced from the available evidence. "
                "Reputation alone is not mapped to a technique."
            )
        return MappingResult(techniques=ordered, behaviors=behaviors, unmapped_behaviors=sorted(set(unmapped)), note=note)

    @staticmethod
    def _evidence_for(
        behavior: str, alerts: list[Any], classification: str, event_count: int
    ) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        for alert in alerts:
            alert_type = getattr(alert, "alert_type", None) or (alert.get("alert_type") if isinstance(alert, dict) else None)
            if alert_type == behavior or (behavior == "account_compromise" and alert_type == "account_compromise"):
                payload = {
                    "type": "alert",
                    "alert_id": getattr(alert, "id", None),
                    "rule_id": getattr(alert, "rule_id", None),
                    "description": getattr(alert, "description", ""),
                }
                if payload not in evidence:
                    evidence.append(payload)
        if behavior in {"account_compromise", "successful_login_after_failures"}:
            evidence.append({"type": "classification", "classification": classification})
        if not evidence:
            evidence.append({"type": "aggregate", "event_count": event_count, "classification": classification})
        return evidence

    @staticmethod
    def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for item in items:
            key = repr(sorted(item.items()))
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result[:20]


def mapping_status() -> dict[str, Any]:
    config = get_mitre_config()
    return {
        "catalog": "local_config",
        "technique_count": len(config.get("techniques", [])),
        "confirmed_threshold": config.get("confirmed_threshold", 0.75),
        "source": "config/mitre_mapping.yaml",
        "last_checked": utcnow().isoformat(),
    }
