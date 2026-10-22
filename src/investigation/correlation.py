"""Event correlation for incident timelines."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from src.database.models import Alert, SecurityEvent
from src.utils.helpers import ensure_utc, iso


@dataclass
class CorrelationResult:
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    duration_seconds: float
    source_ips: list[str]
    usernames: list[str]
    endpoints: list[str]
    event_types: dict[str, int]
    alert_types: dict[str, int]
    failed_login_count: int
    success_after_failures: bool
    suspicious_request_count: int
    correlation_keys: list[str]
    correlation_confidence: float
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "duration_seconds": round(self.duration_seconds, 3),
            "source_ips": self.source_ips,
            "usernames": self.usernames,
            "endpoints": self.endpoints,
            "event_types": self.event_types,
            "alert_types": self.alert_types,
            "failed_login_count": self.failed_login_count,
            "success_after_failures": self.success_after_failures,
            "suspicious_request_count": self.suspicious_request_count,
            "correlation_keys": self.correlation_keys,
            "correlation_confidence": round(self.correlation_confidence, 3),
            "summary": self.summary,
        }


def correlate(events: list[SecurityEvent], alerts: list[Alert]) -> CorrelationResult:
    ordered = sorted(events, key=lambda event: ensure_utc(event.timestamp))
    if not ordered:
        return CorrelationResult(0, None, None, 0.0, [], [], [], {}, {}, 0, False, 0, [], 0.0, "No events available.")

    isps = sorted({event.source_ip for event in ordered if event.source_ip})
    users = sorted({event.username for event in ordered if event.username})
    endpoints = sorted({event.endpoint for event in ordered if event.endpoint})
    event_types = dict(Counter(event.event_type for event in ordered))
    alert_types = dict(Counter(alert.alert_type for alert in alerts))
    first = ensure_utc(ordered[0].timestamp)
    last = ensure_utc(ordered[-1].timestamp)
    failed = sum(1 for event in ordered if event.event_type == "failed_login" or event.status_code == 401)
    successful = [
        event for event in ordered
        if event.event_type == "successful_login" or (
            event.status_code in {200, 302} and "/login" in (event.endpoint or "").lower()
        )
    ]
    success_after_failures = bool(successful) and failed >= 3
    suspicious_alerts = [
        alert for alert in alerts
        if alert.alert_type not in {"ml_anomaly", "abnormal_traffic"}
    ]
    suspicious_requests = len(suspicious_alerts)

    keys = []
    if len(isps) == 1:
        keys.append("source_ip")
    if len(users) == 1:
        keys.append("username")
    if (last - first).total_seconds() <= 3600:
        keys.append("time_window")

    confidence = 0.35
    if len(isps) == 1:
        confidence += 0.20
    if len(users) == 1:
        confidence += 0.15
    if failed >= 3:
        confidence += 0.10
    if success_after_failures:
        confidence += 0.10
    if suspicious_requests:
        confidence += 0.05
    confidence = min(confidence, 0.98)

    if success_after_failures:
        narrative = "Correlated authentication failure cluster followed by a successful login."
    elif suspicious_requests:
        narrative = "Multiple suspicious requests correlate to one source within the incident window."
    else:
        narrative = "Events share source/identity and fall inside the correlation window."
    summary = (
        f"{len(ordered)} events from {', '.join(isps) or 'unknown source'} over "
        f"{(last - first).total_seconds():.1f}s; {len(alerts)} alerts; {narrative}"
    )
    return CorrelationResult(
        event_count=len(ordered),
        first_seen=first,
        last_seen=last,
        duration_seconds=(last - first).total_seconds(),
        source_ips=isps,
        usernames=users,
        endpoints=endpoints[:30],
        event_types=event_types,
        alert_types=alert_types,
        failed_login_count=failed,
        success_after_failures=success_after_failures,
        suspicious_request_count=suspicious_requests,
        correlation_keys=keys,
        correlation_confidence=confidence,
        summary=summary,
    )
