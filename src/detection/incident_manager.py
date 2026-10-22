"""Correlation of alerts and events into incidents."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Alert, Incident, SecurityEvent
from src.utils.config import get_config
from src.utils.helpers import ensure_utc

CATEGORY_PRIORITY = {
    "command_injection": 100,
    "account_compromise": 95,
    "sql_injection": 90,
    "path_traversal": 85,
    "brute_force": 80,
    "malicious_ip": 70,
    "abnormal_traffic": 60,
    "recon_scanning": 55,
    "suspicious_user_agent": 50,
    "prompt_injection_attempt": 45,
    "xss": 58,
    "ml_anomaly": 40,
    "suspicious_activity": 30,
    "unknown": 10,
}
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _window_start(event: SecurityEvent) -> Any:
    minutes = int(get_config().get("detection", {}).get("correlation_window_minutes", 10))
    return ensure_utc(event.timestamp) - timedelta(minutes=minutes)


def _title_for(alert: Alert, incident: Incident | None = None) -> str:
    actor = alert.source_ip or alert.username or "unknown source"
    return f"{alert.title} - {actor}"


class IncidentManager:
    def __init__(self, session: Session) -> None:
        self.session = session

    def assign_alert(self, alert: Alert, event: SecurityEvent) -> tuple[Incident, bool]:
        window_start = _window_start(event)
        incident = repository.find_correlated_incident(
            self.session,
            source_ip=alert.source_ip or event.source_ip,
            username=alert.username or event.username,
            since=window_start,
        )
        created = False
        if incident is None:
            incident = repository.create_incident(
                self.session,
                title=_title_for(alert),
                description=alert.description or alert.title,
                status="NEW",
                severity=alert.severity,
                risk_score=0.0,
                confidence=0.0,
                attack_category=alert.alert_type,
                source_ip=alert.source_ip or event.source_ip,
                username=alert.username or event.username,
                event_count=0,
                detection_source="rule_engine",
                approval_status="NOT_REQUIRED",
            )
            created = True

        if alert.incident_id != incident.id:
            alert.incident_id = incident.id
        repository.attach_event_to_incident(self.session, event, incident.id)

        # Pull in nearby events sharing the correlation key so the incident
        # timeline is not limited to alert-generating events.
        key_ip = incident.source_ip
        key_user = incident.username
        if key_ip:
            nearby = repository.events_for_ip_since(self.session, key_ip, window_start, limit=500)
        elif key_user:
            nearby = repository.events_for_user_since(self.session, key_user, window_start, limit=500)
        else:
            nearby = [event]
        upper = ensure_utc(event.timestamp)
        for candidate in nearby:
            candidate_ts = ensure_utc(candidate.timestamp)
            if window_start <= candidate_ts <= upper and candidate.incident_id in (None, incident.id):
                repository.attach_event_to_incident(self.session, candidate, incident.id)

        # Update aggregate severity/category/title using explicit precedence.
        if SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = alert.severity
        current_priority = CATEGORY_PRIORITY.get(incident.attack_category, 0)
        new_priority = CATEGORY_PRIORITY.get(alert.alert_type, 0)
        if new_priority > current_priority:
            incident.attack_category = alert.alert_type
            incident.title = _title_for(alert, incident)
            incident.description = alert.description or incident.description
        repository.refresh_event_count(self.session, incident)
        self.session.flush()
        return incident, created

    def attach_if_correlated(self, event: SecurityEvent) -> Incident | None:
        """Attach a non-alerting event to an open incident in the same window."""
        incident = repository.find_correlated_incident(
            self.session,
            source_ip=event.source_ip,
            username=event.username,
            since=_window_start(event),
        )
        if incident:
            repository.attach_event_to_incident(self.session, event, incident.id)
            repository.refresh_event_count(self.session, incident)
        return incident

    def add_alerts_to_incident(self, incident: Incident, alerts: list[Alert]) -> None:
        for alert in alerts:
            if alert.incident_id != incident.id:
                alert.incident_id = incident.id
        self.session.flush()
