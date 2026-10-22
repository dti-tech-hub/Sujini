"""MITRE ATT&CK mapping agent."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Alert, Incident
from src.mitre.mapper import MitreMapper


class MitreAgent:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.mapper = MitreMapper()

    def run(
        self,
        incident: Incident,
        *,
        classification: str,
        confidence: float,
        alerts: list[Alert],
    ) -> dict[str, Any]:
        repository.delete_mitre_for_incident(self.session, incident.id)
        result = self.mapper.map(
            classification=classification,
            alert_types=[alert.alert_type for alert in alerts],
            confidence=confidence,
            alerts=alerts,
            event_count=incident.event_count,
        )
        records = []
        for technique in result.techniques:
            record = repository.add_mitre_mapping(
                self.session,
                incident.id,
                **technique.to_record(),
            )
            records.append({**record.to_dict(), "url": technique.url})
        return {
            "techniques": records,
            "behaviors": result.behaviors,
            "unmapped_behaviors": result.unmapped_behaviors,
            "note": result.note,
        }
