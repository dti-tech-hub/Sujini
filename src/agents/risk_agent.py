"""Risk assessment agent."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Incident
from src.risk.scorer import RiskScorer


class RiskAgent:
    def __init__(self, session: Session) -> None:
        self.session = session

    def run(
        self,
        incident: Incident,
        *,
        severity: str,
        confidence: float,
        category: str,
        events: list[Any],
        threat_intel: dict[str, Any],
    ) -> dict[str, Any]:
        scorer = RiskScorer(self.session)
        result = scorer.score(
            incident_id=incident.id,
            severity=severity,
            confidence=confidence,
            category=category,
            event_count=len(events),
            source_ip=incident.source_ip,
            username=incident.username,
            endpoints=[event.endpoint for event in events if event.endpoint],
            threat_intel=threat_intel,
        )
        repository.add_risk_assessment(
            self.session,
            incident.id,
            score=result.score,
            level=result.level,
            factors=result.factors,
            weights=result.weights,
            explanation=result.explanation,
        )
        incident.risk_score = result.score
        incident.severity = result.level
        self.session.flush()
        return result.to_dict()
