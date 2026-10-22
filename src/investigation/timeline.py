"""Incident timeline construction."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Incident
from src.utils.helpers import ensure_utc, iso

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_timeline(session: Session, incident: Incident) -> list[dict[str, Any]]:
    events = repository.events_for_incident(session, incident.id)
    alerts = repository.alerts_for_incident(session, incident.id)
    alerts_by_event: dict[str, list[Any]] = {}
    for alert in alerts:
        if alert.event_id:
            alerts_by_event.setdefault(alert.event_id, []).append(alert)

    entries: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda item: ensure_utc(item.timestamp)):
        related = alerts_by_event.get(event.id, [])
        label = event.event_type.replace("_", " ")
        if event.event_type == "failed_login":
            label = "failed login"
        elif event.event_type == "successful_login":
            label = "successful login"
        entries.append(
            {
                "timestamp": iso(event.timestamp),
                "kind": "event",
                "event_id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "label": label,
                "description": event.message or f"{event.method or '-'} {event.endpoint or '-'}",
                "source_ip": event.source_ip,
                "username": event.username,
                "method": event.method,
                "endpoint": event.endpoint,
                "status_code": event.status_code,
                "alert_types": [alert.alert_type for alert in related],
                "alert_ids": [alert.id for alert in related],
            }
        )

    for run in repository.agent_runs_for_incident(session, incident.id):
        entries.append(
            {
                "timestamp": iso(run.started_at),
                "kind": "agent_stage",
                "stage": run.stage,
                "status": run.status,
                "label": f"agent: {run.stage}",
                "description": f"Stage {run.status.lower()} in {run.duration_ms:.1f} ms.",
                "duration_ms": round(float(run.duration_ms or 0), 2),
            }
        )

    entries.sort(key=lambda item: item.get("timestamp") or "")
    return entries
