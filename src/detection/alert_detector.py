"""Hybrid alert detection: signatures, behavioral thresholds, optional ML."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Alert, SecurityEvent
from src.detection.anomaly_detector import AnomalyDetector
from src.detection.rules import RuleHit, evaluate_rules
from src.utils.config import get_config
from src.utils.helpers import bucket_time, ensure_utc, stable_hash
from src.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionResult:
    alerts: list[Alert] = field(default_factory=list)
    new_alerts: list[Alert] = field(default_factory=list)
    rule_hits: list[RuleHit] = field(default_factory=list)
    ml: dict[str, Any] | None = None
    duplicate: bool = False


class AlertDetector:
    def __init__(self, session: Session, *, enable_ml: bool | None = None) -> None:
        self.session = session
        self.config = get_config()
        det = self.config.get("detection", {})
        self.enable_ml = bool(det.get("enable_ml_anomaly", True)) if enable_ml is None else enable_ml
        self.anomaly = AnomalyDetector() if self.enable_ml else None
        self.detection_config = det
        self.duplicate_minutes = int(det.get("duplicate_window_minutes", 60))

    # -- helpers ---------------------------------------------------------
    def _dedup(self, rule_id: str, event: SecurityEvent, extra: str = "") -> str:
        bucket = bucket_time(event.timestamp, max(1, self.duplicate_minutes // 6 or 10))
        key = stable_hash(rule_id, event.source_ip, event.username, extra, bucket, length=40)
        return f"{rule_id}:{key}"

    def _create(
        self,
        event: SecurityEvent,
        *,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        rule_id: str,
        details: dict[str, Any],
        dedup_extra: str = "",
        event_id: str | None = None,
    ) -> tuple[Alert, bool]:
        alert, created = repository.add_alert(
            self.session,
            {
                "event_id": event_id if event_id is not None else event.id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "description": description,
                "rule_id": rule_id,
                "source_ip": event.source_ip,
                "username": event.username,
                "status": "OPEN",
                "details": details,
                "dedup_key": self._dedup(rule_id, event, dedup_extra),
            },
        )
        return alert, created

    # -- detection stages ------------------------------------------------
    def detect(self, event: SecurityEvent) -> DetectionResult:
        result = DetectionResult()
        event_dict = event.to_dict()

        for hit in evaluate_rules(event_dict):
            result.rule_hits.append(hit)
            alert, created = self._create(
                event,
                alert_type=hit.category,
                severity=hit.severity,
                title=f"{hit.name} detected",
                description=hit.description,
                rule_id=hit.rule_id,
                details={
                    "matched_fields": hit.matched_fields,
                    "evidence": hit.evidence,
                    "mitre_hints": hit.mitre,
                    "detection_source": "signature",
                },
                dedup_extra=hit.category,
            )
            if all(existing.id != alert.id for existing in result.alerts):
                result.alerts.append(alert)
            if created:
                result.new_alerts.append(alert)

        self._failed_login_rule(event, result)
        self._account_compromise_rule(event, result)
        self._request_rate_rule(event, result)
        self._server_error_rule(event, result)
        self._known_malicious_ip_rule(event, result)

        if self.anomaly and self.anomaly.available:
            ml_result = self.anomaly.score(event_dict)
            result.ml = ml_result
            if ml_result and ml_result.get("is_anomaly"):
                event.is_anomaly = True
                event.anomaly_score = ml_result.get("anomaly_score")
                # Suppress redundant ML alerts when a deterministic signature
                # already explains the event.
                if not result.alerts:
                    alert, created = self._create(
                        event,
                        alert_type="ml_anomaly",
                        severity="MEDIUM",
                        title="Machine-learning anomaly detected",
                        description="Isolation Forest scored the request outside the learned normal range.",
                        rule_id="ML-001",
                        details=ml_result,
                        dedup_extra=str(ml_result.get("decision_score")),
                    )
                    result.alerts.append(alert)
                    if created:
                        result.new_alerts.append(alert)
        return result

    def _event_counts(self, event: SecurityEvent, minutes: int, predicate) -> list[SecurityEvent]:
        since = ensure_utc(event.timestamp) - timedelta(minutes=minutes)
        if event.source_ip:
            candidates = repository.events_for_ip_since(self.session, event.source_ip, since, limit=500)
        elif event.username:
            candidates = repository.events_for_user_since(self.session, event.username, since, limit=500)
        else:
            candidates = [event]
        upper = ensure_utc(event.timestamp)
        return [e for e in candidates if since <= ensure_utc(e.timestamp) <= upper and predicate(e)]

    def _failed_login_rule(self, event: SecurityEvent, result: DetectionResult) -> None:
        if event.event_type not in {"failed_login", "unauthorized_access"} and event.status_code != 401:
            return
        cfg = self.detection_config
        threshold = int(cfg.get("failed_login_threshold", 5))
        window = int(cfg.get("failed_login_window_minutes", 10))
        failures = self._event_counts(event, window, lambda e: e.event_type == "failed_login" or e.status_code == 401)
        if len(failures) < threshold:
            return
        alert, created = self._create(
            event,
            alert_type="brute_force",
            severity="HIGH",
            title="Repeated failed login attempts",
            description=(
                f"{len(failures)} failed authentication attempts from {event.source_ip or 'unknown source'} "
                f"within {window} minutes, meeting the configured threshold of {threshold}."
            ),
            rule_id="AUTH-001",
            details={
                "failure_count": len(failures),
                "threshold": threshold,
                "window_minutes": window,
                "event_ids": [e.id for e in failures][-30:],
                "detection_source": "behavioral",
            },
            dedup_extra=f"threshold-{threshold}",
            event_id=failures[-1].id,
        )
        result.alerts.append(alert)
        if created:
            result.new_alerts.append(alert)

    def _account_compromise_rule(self, event: SecurityEvent, result: DetectionResult) -> None:
        if event.event_type != "successful_login" and not (
            event.status_code in {200, 302} and "/login" in (event.endpoint or "").lower()
        ):
            return
        cfg = self.detection_config
        minimum = int(cfg.get("account_compromise_min_failures", 3))
        window = int(cfg.get("failed_login_window_minutes", 10))
        failures = self._event_counts(
            event, window, lambda e: e.event_type == "failed_login" or e.status_code == 401
        )
        if len(failures) < minimum:
            return
        alert, created = self._create(
            event,
            alert_type="account_compromise",
            severity="CRITICAL",
            title="Successful login after repeated failures",
            description=(
                f"Successful authentication for '{event.username or 'unknown'}' followed {len(failures)} "
                f"failed attempts within {window} minutes, indicating possible account compromise."
            ),
            rule_id="AUTH-002",
            details={
                "failure_count": len(failures),
                "threshold": minimum,
                "window_minutes": window,
                "event_ids": [e.id for e in failures][-30:] + [event.id],
                "detection_source": "behavioral_correlation",
            },
            dedup_extra="post-failure-success",
        )
        result.alerts.append(alert)
        if created:
            result.new_alerts.append(alert)

    def _request_rate_rule(self, event: SecurityEvent, result: DetectionResult) -> None:
        cfg = self.detection_config
        threshold = int(cfg.get("request_rate_threshold", 30))
        window = int(cfg.get("request_rate_window_minutes", 1))
        count = len(self._event_counts(event, window, lambda e: True))
        if count < threshold:
            return
        alert, created = self._create(
            event,
            alert_type="abnormal_traffic",
            severity="MEDIUM",
            title="Abnormal request rate",
            description=(
                f"{count} requests from {event.source_ip or 'unknown source'} in {window} minute(s), "
                f"above the configured threshold of {threshold}."
            ),
            rule_id="RATE-001",
            details={"request_count": count, "threshold": threshold, "window_minutes": window, "detection_source": "behavioral"},
            dedup_extra="rate",
        )
        result.alerts.append(alert)
        if created:
            result.new_alerts.append(alert)

    def _server_error_rule(self, event: SecurityEvent, result: DetectionResult) -> None:
        if not event.status_code or event.status_code < 500:
            return
        cfg = self.detection_config
        threshold = int(cfg.get("server_error_threshold", 10))
        window = int(cfg.get("server_error_window_minutes", 5))
        errors = self._event_counts(event, window, lambda e: (e.status_code or 0) >= 500)
        if len(errors) < threshold:
            return
        alert, created = self._create(
            event,
            alert_type="abnormal_traffic",
            severity="MEDIUM",
            title="Server error burst",
            description=f"{len(errors)} server errors within {window} minutes may indicate fault injection or exploitation.",
            rule_id="HTTP-001",
            details={"error_count": len(errors), "threshold": threshold, "window_minutes": window, "detection_source": "behavioral"},
            dedup_extra="5xx",
        )
        result.alerts.append(alert)
        if created:
            result.new_alerts.append(alert)

    def _known_malicious_ip_rule(self, event: SecurityEvent, result: DetectionResult) -> None:
        watchlist = set(self.detection_config.get("known_malicious_ips", []))
        if not event.source_ip or event.source_ip not in watchlist:
            return
        alert, created = self._create(
            event,
            alert_type="malicious_ip",
            severity="HIGH",
            title="Known malicious source IP observed",
            description=(
                f"Source {event.source_ip} matches the locally configured demonstration watchlist. "
                "The watchlist is synthetic_demo_data, not live threat intelligence."
            ),
            rule_id="IP-001",
            details={
                "watchlist": "local_demo_watchlist",
                "data_label": "synthetic_demo_data",
                "detection_source": "reputation_watchlist",
            },
            dedup_extra="watchlist",
        )
        result.alerts.append(alert)
        if created:
            result.new_alerts.append(alert)


def detection_status() -> dict[str, Any]:
    detector = AnomalyDetector()
    return {
        "rule_engine": "ready",
        "ml_anomaly_detector": "ready" if detector.available else "model_not_trained",
        "ml_model_dataset": detector.metadata.get("dataset") if detector.available else None,
    }
