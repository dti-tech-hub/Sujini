"""Threat-intelligence agent: indicator extraction and enrichment."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database.models import Incident, SecurityEvent
from src.threat_intel.service import ThreatIntelService


class ThreatIntelAgent:
    def __init__(self, session: Session) -> None:
        self.session = session

    def run(self, incident: Incident, events: list[SecurityEvent]) -> dict[str, Any]:
        indicators: list[str] = []
        for value in [incident.source_ip, *(event.source_ip for event in events)]:
            if value and value not in indicators:
                indicators.append(value)
        service = ThreatIntelService(self.session)
        summary = service.enrich_ips(indicators, incident_id=incident.id)
        summary["providers"] = [
            {
                "indicator": item["indicator"],
                "verdict": item["verdict"],
                "mode": item["mode"],
                "is_mock": item["is_mock"],
            }
            for item in summary.get("indicators", [])
        ]
        return summary
