"""Evidence collection for an incident."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Alert, Evidence, Incident, SecurityEvent
from src.detection.rules import evaluate_rules
from src.investigation.correlation import CorrelationResult, correlate
from src.utils.helpers import ensure_utc, iso
from src.utils.logging import get_logger

logger = get_logger(__name__)

SEVERITY_WEIGHT = {"INFO": 0.2, "LOW": 0.4, "MEDIUM": 0.7, "HIGH": 1.0, "CRITICAL": 1.3}


class EvidenceAgent:
    """Collects and persists evidence without altering the source events."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def _existing_keys(self, incident_id: str) -> set[str]:
        rows = self.session.scalars(select(Evidence).where(Evidence.incident_id == incident_id))
        return {f"{item.evidence_type}:{item.event_id}:{item.description[:80]}" for item in rows}

    def collect(self, incident: Incident) -> dict[str, Any]:
        events = repository.events_for_incident(self.session, incident.id)
        alerts = repository.alerts_for_incident(self.session, incident.id)
        correlation = correlate(events, alerts)
        existing = self._existing_keys(incident.id)
        added: list[Evidence] = []

        def add(evidence_type: str, description: str, weight: float, event_id: str | None = None,
                details: dict[str, Any] | None = None) -> None:
            key = f"{evidence_type}:{event_id}:{description[:80]}"
            if key in existing:
                return
            record = repository.add_evidence(
                self.session,
                incident.id,
                event_id=event_id,
                evidence_type=evidence_type,
                description=description[:2000],
                weight=round(weight, 3),
                details=details or {},
            )
            existing.add(key)
            added.append(record)

        for alert in alerts:
            add(
                evidence_type=alert.alert_type,
                description=f"[{alert.rule_id}] {alert.description}",
                weight=SEVERITY_WEIGHT.get(alert.severity, 0.5),
                event_id=alert.event_id,
                details={"alert_id": alert.id, "rule_id": alert.rule_id, "severity": alert.severity, **alert.details},
            )

        failed = [event for event in events if event.event_type == "failed_login" or event.status_code == 401]
        for event in failed[-10:]:
            add(
                evidence_type="failed_login",
                description=(
                    f"Failed authentication at {iso(event.timestamp)} for '{event.username or 'unknown'}' "
                    f"from {event.source_ip or 'unknown source'} ({event.method or '-'} {event.endpoint or '-'} -> {event.status_code})."
                ),
                weight=0.45,
                event_id=event.id,
                details={"status_code": event.status_code, "endpoint": event.endpoint},
            )

        suspicious_events = []
        for event in events:
            hits = evaluate_rules(event.to_dict())
            if hits:
                suspicious_events.append(event)
                for hit in hits:
                    add(
                        evidence_type="suspicious_request",
                        description=(
                            f"{hit.name}: {event.method or '-'} {event.endpoint or '-'} from "
                            f"{event.source_ip or 'unknown source'} matched {hit.rule_id}."
                        ),
                        weight=SEVERITY_WEIGHT.get(hit.severity, 0.7),
                        event_id=event.id,
                        details={
                            "rule_id": hit.rule_id,
                            "category": hit.category,
                            "matched_fields": hit.matched_fields,
                            "evidence": hit.evidence,
                        },
                    )

        successful = [
            event for event in events
            if event.event_type == "successful_login" or (
                event.status_code in {200, 302} and "/login" in (event.endpoint or "").lower()
            )
        ]
        for event in successful:
            add(
                evidence_type="successful_login",
                description=(
                    f"Successful authentication at {iso(event.timestamp)} for '{event.username or 'unknown'}' "
                    f"from {event.source_ip or 'unknown source'} after {len(failed)} failure(s)."
                ),
                weight=1.0,
                event_id=event.id,
                details={"prior_failures": len(failed), "status_code": event.status_code},
            )

        if correlation.success_after_failures:
            add(
                evidence_type="correlated_sequence",
                description=(
                    "Authentication timeline shows repeated failures followed by a successful login: "
                    "consistent with credential guessing followed by valid-account use."
                ),
                weight=1.2,
                details={"failed_logins": correlation.failed_login_count, "window_seconds": correlation.duration_seconds},
            )

        if events:
            add(
                evidence_type="timeline_bounds",
                description=(
                    f"Observed window: {iso(correlation.first_seen)} to {iso(correlation.last_seen)} "
                    f"({correlation.duration_seconds:.1f}s)."
                ),
                weight=0.3,
                event_id=events[0].id,
                details={"first_event": events[0].id, "last_event": events[-1].id},
            )

        prompt_flags = 0
        for event in events:
            flags = (event.raw_event or {}).get("_normalization", {}).get("prompt_injection_flags", 0)
            if flags:
                prompt_flags += int(flags)
                add(
                    evidence_type="prompt_injection_text",
                    description=(
                        "Event text contains instruction-like patterns. It was retained as data and "
                        "excluded from any instruction position."
                    ),
                    weight=0.6,
                    event_id=event.id,
                    details={"flags": flags, "containment": "untrusted-data envelope + schema validation"},
                )

        self.session.flush()
        total = self.session.scalars(select(Evidence).where(Evidence.incident_id == incident.id)).all()
        return {
            "evidence": [record.to_dict() for record in total],
            "added": len(added),
            "total": len(total),
            "correlation": correlation.to_dict(),
            "prompt_injection_flags": prompt_flags,
        }
