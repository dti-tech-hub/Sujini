"""Application service facade shared by the API, scripts, and evaluation."""
from __future__ import annotations

import math
import statistics
import time
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from src.agents.orchestrator import Orchestrator
from src.database import repository
from src.database.models import (
    Alert, Approval, Incident, MitreMapping, ResponseAction, SecurityEvent,
    ThreatIntelligence, User,
)
from src.detection.alert_detector import AlertDetector, detection_status
from src.detection.incident_manager import IncidentManager
from src.detection.normalization import normalize_event
from src.investigation.timeline import build_timeline
from src.llm.factory import llm_status
from src.response.approval import ApprovalService
from src.security.audit import AuditService
from src.threat_intel.service import threat_intel_status
from src.utils.config import get_config, runtime_summary
from src.utils.exceptions import AppError, ConflictError, NotFoundError, ValidationError
from src.utils.helpers import ensure_utc, iso, normalize_ip, utcnow
from src.utils.logging import get_logger

logger = get_logger(__name__)

INVESTIGATION_STAGES = {
    "evidence_collection", "alert_triage", "threat_intelligence", "mitre_mapping",
    "risk_assessment", "response_planning", "approval_gate",
}


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(quantile * len(ordered)) - 1))
    return round(ordered[index], 2)


class SocService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def _ingest_one(
        self,
        session: Session,
        payload: dict[str, Any],
        *,
        source: str,
        actor: str,
        actor_role: str,
        request_id: str | None,
        audit: AuditService,
        enable_ml: bool | None,
    ) -> dict[str, Any]:
        normalized = normalize_event(payload, source=source)
        event, created = repository.add_event(session, normalized)
        if not created:
            incident_manager = IncidentManager(session)
            incident = incident_manager.attach_if_correlated(event)
            audit.record(
                actor=actor, actor_role=actor_role, action="EVENT_DUPLICATE",
                entity_type="event", entity_id=event.id, incident_id=event.incident_id or (incident.id if incident else None),
                outcome="SKIPPED", details={"dedup_hash": event.dedup_hash}, request_id=request_id,
            )
            return {
                "event": event.to_dict(),
                "duplicate": True,
                "alerts": [],
                "incident_id": event.incident_id,
                "incident_created": False,
                "ml": None,
            }

        audit.record(
            actor=actor, actor_role=actor_role, action="EVENT_INGESTED",
            entity_type="event", entity_id=event.id, incident_id=None,
            outcome="SUCCESS",
            details={
                "event_type": event.event_type,
                "source": event.source,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "normalization_warnings": (event.raw_event or {}).get("_normalization", {}).get("warnings", []),
                "data_label": event.dataset_label,
            },
            request_id=request_id,
        )

        detector = AlertDetector(session, enable_ml=enable_ml)
        detection = detector.detect(event)
        incident_manager = IncidentManager(session)
        incidents: dict[str, Incident] = {}
        incidents_created = 0
        for alert in detection.new_alerts:
            incident, incident_created = incident_manager.assign_alert(alert, event)
            incidents[incident.id] = incident
            if incident_created:
                incidents_created += 1
                audit.record(
                    actor="detection_engine", actor_role="system", action="INCIDENT_CREATED",
                    entity_type="incident", entity_id=incident.id, incident_id=incident.id,
                    outcome="SUCCESS",
                    details={
                        "trigger_alert": alert.alert_type,
                        "rule_id": alert.rule_id,
                        "severity": alert.severity,
                        "source_ip": incident.source_ip,
                        "username": incident.username,
                    },
                    request_id=request_id,
                )
            audit.record(
                actor="detection_engine", actor_role="system", action="ALERT_CREATED",
                entity_type="alert", entity_id=alert.id, incident_id=incident.id,
                outcome="SUCCESS",
                details={"alert_type": alert.alert_type, "rule_id": alert.rule_id, "severity": alert.severity},
                request_id=request_id,
            )
            session.refresh(alert)
        if not detection.new_alerts:
            incident_manager.attach_if_correlated(event)

        for alert in detection.alerts:
            session.refresh(alert)
        session.flush()
        return {
            "event": event.to_dict(),
            "duplicate": False,
            "alerts": [alert.to_dict() for alert in detection.alerts],
            "alerts_created": len(detection.new_alerts),
            "incident_id": event.incident_id or (next(iter(incidents)) if incidents else None),
            "incident_created": incidents_created > 0,
            "ml": detection.ml,
            "normalization_warnings": (event.raw_event or {}).get("_normalization", {}).get("warnings", []),
        }

    def ingest_event(
        self,
        payload: dict[str, Any],
        *,
        actor: str = "system",
        actor_role: str = "system",
        request_id: str | None = None,
        source: str = "api",
        auto_investigate: bool | None = None,
    ) -> dict[str, Any]:
        session = self.session_factory()
        try:
            audit = AuditService(session)
            result = self._ingest_one(
                session, payload, source=source, actor=actor, actor_role=actor_role,
                request_id=request_id, audit=audit, enable_ml=None,
            )
            session.commit()
            incident_id = result.get("incident_id")
            should_auto = (
                get_config().get("detection", {}).get("auto_investigate", False)
                if auto_investigate is None else auto_investigate
            )
            if should_auto and incident_id and result.get("incident_created"):
                try:
                    result["investigation"] = self.investigate(
                        incident_id, actor="auto_responder", actor_role="system", request_id=request_id
                    )
                except Exception as exc:
                    logger.exception("Automatic investigation failed")
                    result["investigation_error"] = str(exc)[:300]
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def ingest_alert(
        self,
        payload: dict[str, Any],
        *,
        actor: str,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self.ingest_event(
            payload, actor=actor, actor_role=actor_role, request_id=request_id, source="security_alert"
        )

    def ingest_batch(
        self,
        payloads: list[dict[str, Any]],
        *,
        actor: str = "system",
        actor_role: str = "system",
        request_id: str | None = None,
        source: str = "api_batch",
        enable_ml: bool | None = None,
        auto_investigate: bool = False,
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        session = self.session_factory()
        try:
            audit = AuditService(session)
            for payload in payloads:
                results.append(
                    self._ingest_one(
                        session, payload, source=source, actor=actor, actor_role=actor_role,
                        request_id=request_id, audit=audit, enable_ml=enable_ml,
                    )
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        incident_ids = sorted({item["incident_id"] for item in results if item.get("incident_id")})
        investigations = []
        if auto_investigate:
            for incident_id in incident_ids:
                try:
                    investigations.append(
                        self.investigate(incident_id, actor=actor, actor_role=actor_role, request_id=request_id)
                    )
                except Exception as exc:
                    logger.exception("Batch auto-investigation failed for %s", incident_id)
                    investigations.append({"incident_id": incident_id, "error": str(exc)[:300]})
        return {
            "submitted": len(payloads),
            "ingested": sum(1 for item in results if not item["duplicate"]),
            "duplicates": sum(1 for item in results if item["duplicate"]),
            "alerts_created": sum(item.get("alerts_created", 0) for item in results),
            "incidents": incident_ids,
            "events": results,
            "investigations": investigations,
        }

    def create_incident(self, payload: dict[str, Any], *, actor: str, actor_role: str,
                        request_id: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            title = str(payload.get("title", "")).strip()
            if not title:
                raise ValidationError("title is required")
            severity = str(payload.get("severity", "MEDIUM")).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValidationError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")
            source_ip = payload.get("source_ip")
            if source_ip:
                source_ip, valid = normalize_ip(source_ip)
                if not valid:
                    raise ValidationError("source_ip is not a valid IP address")
            category = str(payload.get("attack_category", "suspicious_activity")).strip().lower()
            incident = repository.create_incident(
                session,
                title=title[:255],
                description=str(payload.get("description", ""))[:4000],
                severity=severity,
                attack_category=category[:64],
                source_ip=source_ip,
                username=(str(payload.get("username")).strip()[:128] if payload.get("username") else None),
                status="NEW",
                detection_source="manual",
                event_count=0,
            )
            AuditService(session).record(
                actor=actor, actor_role=actor_role, action="INCIDENT_CREATED_MANUAL",
                entity_type="incident", entity_id=incident.id, incident_id=incident.id,
                outcome="SUCCESS", details={"title": title, "severity": severity}, request_id=request_id,
            )
            session.commit()
            return incident.to_dict()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Read models
    # ------------------------------------------------------------------
    def list_events(self, **filters: Any) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            return [event.to_dict() for event in repository.list_events(session, **filters)]
        finally:
            session.close()

    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            return [alert.to_dict() for alert in repository.list_alerts(session, **filters)]
        finally:
            session.close()

    def list_incidents(self, **filters: Any) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            return [incident.to_dict() for incident in repository.list_incidents(session, **filters)]
        finally:
            session.close()

    def get_incident_detail(self, incident_id: str) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            risk = sorted(incident.risk_assessments, key=lambda item: item.created_at)[-1] if incident.risk_assessments else None
            actions = sorted(incident.response_actions, key=lambda item: item.created_at)
            approvals = sorted(incident.approvals, key=lambda item: item.created_at)
            agent_runs = repository.agent_runs_for_incident(session, incident.id)
            audit_entries = repository.list_audit(session, incident_id=incident.id, limit=500)
            return {
                "incident": incident.to_dict(include_events=False),
                "events": [event.to_dict() for event in sorted(incident.events, key=lambda item: item.timestamp)],
                "alerts": [alert.to_dict() for alert in sorted(incident.alerts, key=lambda item: item.created_at)],
                "evidence": [item.to_dict() for item in sorted(incident.evidence, key=lambda item: item.created_at)],
                "threat_intelligence": [item.to_dict() for item in sorted(incident.threat_intelligence, key=lambda item: item.fetched_at)],
                "mitre": [item.to_dict() for item in sorted(incident.mitre_mappings, key=lambda item: -item.confidence)],
                "risk": risk.to_dict() if risk else None,
                "risk_history": [item.to_dict() for item in sorted(incident.risk_assessments, key=lambda item: item.created_at)],
                "response": {
                    "actions": [action.to_dict() for action in actions],
                    "approval_required": incident.approval_required,
                    "approval_status": incident.approval_status,
                    "status": incident.status,
                },
                "approvals": [approval.to_dict() for approval in approvals],
                "timeline": build_timeline(session, incident),
                "agent_runs": [run.to_dict() for run in agent_runs],
                "audit": [entry.to_dict() for entry in audit_entries],
                "system": {
                    "llm_mode": incident.llm_mode,
                    "threat_intel_mode": (
                        incident.threat_intelligence[-1].mode if incident.threat_intelligence else "NOT_QUERIED"
                    ),
                    "simulation_only": True,
                },
            }
        finally:
            session.close()

    def timeline(self, incident_id: str) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            return build_timeline(session, incident)
        finally:
            session.close()

    def evidence(self, incident_id: str) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            return [item.to_dict() for item in sorted(incident.evidence, key=lambda item: item.created_at)]
        finally:
            session.close()

    def threat_intel(self, incident_id: str) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            return [item.to_dict() for item in sorted(incident.threat_intelligence, key=lambda item: item.fetched_at)]
        finally:
            session.close()

    def mitre(self, incident_id: str) -> list[dict[str, Any]]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            return [item.to_dict() for item in sorted(incident.mitre_mappings, key=lambda item: -item.confidence)]
        finally:
            session.close()

    def risk(self, incident_id: str) -> dict[str, Any] | None:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            if not incident.risk_assessments:
                return None
            return sorted(incident.risk_assessments, key=lambda item: item.created_at)[-1].to_dict()
        finally:
            session.close()

    def response(self, incident_id: str) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id, full=True)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            return {
                "incident_id": incident.id,
                "actions": [item.to_dict() for item in sorted(incident.response_actions, key=lambda item: item.created_at)],
                "approval_required": incident.approval_required,
                "approval_status": incident.approval_status,
                "status": incident.status,
                "approvals": [item.to_dict() for item in sorted(incident.approvals, key=lambda item: item.created_at)],
            }
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Investigation / response
    # ------------------------------------------------------------------
    def investigate(self, incident_id: str, *, actor: str = "system", actor_role: str = "system",
                    request_id: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            if incident.status not in {"NEW", "TRIAGED", "INVESTIGATING", "FAILED"}:
                raise ConflictError(f"Incident {incident_id} cannot be investigated in status {incident.status}")
            incident.status = "INVESTIGATING"
            incident.updated_at = utcnow()
            AuditService(session).record(
                actor=actor, actor_role=actor_role, action="INVESTIGATION_STARTED",
                entity_type="incident", entity_id=incident_id, incident_id=incident_id,
                outcome="STARTED", details={"event_count": incident.event_count}, request_id=request_id,
            )
            session.commit()

            orchestrator = Orchestrator(session)
            state = orchestrator.investigate(incident_id, actor=actor, request_id=request_id)
            session.commit()

            auto_executed = False
            if not state.get("approval_required"):
                response_state = orchestrator.execute_approved(
                    incident_id, actor="policy_engine", actor_role="system", request_id=request_id
                )
                state["execution"] = response_state.get("execution")
                state["verification"] = response_state.get("verification")
                auto_executed = True
                session.commit()

            session.refresh(incident)
            result = {
                "incident_id": incident_id,
                "status": incident.status,
                "approval_required": incident.approval_required,
                "approval_status": incident.approval_status,
                "risk_score": round(float(incident.risk_score or 0), 2),
                "severity": incident.severity,
                "classification": state.get("classification", incident.attack_category),
                "confidence": round(float(state.get("confidence", incident.confidence or 0)), 4),
                "llm_mode": state.get("llm_mode", incident.llm_mode),
                "threat_intel_mode": (state.get("threat_intel") or {}).get("mode", "NOT_QUERIED"),
                "mitre_techniques": [item["technique_id"] for item in state.get("mitre_techniques", [])],
                "evidence_count": len(state.get("evidence", [])),
                "auto_executed": auto_executed,
                "verification": state.get("verification"),
            }
            result["incident"] = self.get_incident_detail(incident_id)
            return result
        except Exception as exc:
            session.rollback()
            self._mark_failed(incident_id, str(exc))
            raise
        finally:
            session.close()

    def _mark_failed(self, incident_id: str, error: str) -> None:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if incident:
                incident.status = "FAILED"
                incident.resolution = f"Pipeline failure: {error[:400]}"
                incident.updated_at = utcnow()
                AuditService(session).record(
                    actor="system", actor_role="system", action="INVESTIGATION_FAILED",
                    entity_type="incident", entity_id=incident_id, incident_id=incident_id,
                    outcome="FAILED", details={"error": error[:400]},
                )
                session.commit()
        except Exception:
            session.rollback()
            logger.exception("Failed to mark incident %s as FAILED", incident_id)
        finally:
            session.close()

    def approve(self, incident_id: str, user: User, reason: str, *, action_ids: list[str] | None = None,
                request_id: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            result = ApprovalService(session).decide(
                incident, user, "APPROVED", reason, request_id=request_id, action_ids=action_ids
            )
            session.commit()
            result["incident"] = self.get_incident_detail(incident_id)["incident"]
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def reject(self, incident_id: str, user: User, reason: str, *, action_ids: list[str] | None = None,
               request_id: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            result = ApprovalService(session).decide(
                incident, user, "REJECTED", reason, request_id=request_id, action_ids=action_ids
            )
            session.commit()
            result["incident"] = self.get_incident_detail(incident_id)["incident"]
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def execute(self, incident_id: str, user: User, request_id: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incident = repository.get_incident(session, incident_id)
            if not incident:
                raise NotFoundError(f"Incident {incident_id} not found")
            orchestrator = Orchestrator(session)
            state = orchestrator.execute_approved(
                incident_id, actor=user.username, actor_role=user.role, request_id=request_id
            )
            session.commit()
            return {
                "incident_id": incident_id,
                "execution": state.get("execution"),
                "verification": state.get("verification"),
                "incident": self.get_incident_detail(incident_id),
            }
        except (ConflictError, ValidationError, NotFoundError) as exc:
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            self._mark_failed(incident_id, str(exc))
            raise AppError(f"Response execution failed: {str(exc)[:300]}") from exc
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Metrics and audit
    # ------------------------------------------------------------------
    def metrics(self) -> dict[str, Any]:
        session = self.session_factory()
        try:
            incidents = list(session.scalars(select(Incident)))
            total_events = int(session.scalar(select(func.count(SecurityEvent.id))) or 0)
            total_alerts = int(session.scalar(select(func.count(Alert.id))) or 0)
            severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            status_counts: Counter[str] = Counter()
            categories: Counter[str] = Counter()
            ip_counts: Counter[str] = Counter()
            llm_modes: Counter[str] = Counter()
            for incident in incidents:
                severity_counts[incident.severity] = severity_counts.get(incident.severity, 0) + 1
                status_counts[incident.status] += 1
                categories[incident.attack_category] += 1
                if incident.source_ip:
                    ip_counts[incident.source_ip] += 1
                llm_modes[incident.llm_mode] += 1

            now = utcnow()
            days = [(now.date() - timedelta(days=offset)).isoformat() for offset in reversed(range(14))]
            timeseries = {day: {"incidents": 0, "events": 0} for day in days}
            for incident in incidents:
                key = ensure_utc(incident.created_at).date().isoformat()
                if key in timeseries:
                    timeseries[key]["incidents"] += 1
            event_rows = session.execute(
                select(SecurityEvent.timestamp).where(SecurityEvent.timestamp >= now - timedelta(days=14))
            ).scalars()
            for timestamp in event_rows:
                key = ensure_utc(timestamp).date().isoformat()
                if key in timeseries:
                    timeseries[key]["events"] += 1

            response_times = [
                (ensure_utc(incident.verified_at) - ensure_utc(incident.created_at)).total_seconds()
                for incident in incidents if incident.verified_at
            ]
            approvals = list(session.scalars(select(Approval).order_by(Approval.created_at.asc())))
            first_approval: dict[str, Any] = {}
            for approval in approvals:
                first_approval.setdefault(approval.incident_id, approval)
            approval_times = [
                (ensure_utc(approval.created_at) - ensure_utc(next(i for i in incidents if i.id == incident_id).created_at)).total_seconds()
                for incident_id, approval in first_approval.items()
                if any(i.id == incident_id for i in incidents)
            ]
            runs = session.execute(
                select(MitreMapping.technique_id, func.count(MitreMapping.id))
                .group_by(MitreMapping.technique_id)
                .order_by(func.count(MitreMapping.id).desc())
                .limit(10)
            ).all()
            from src.database.models import AgentRun
            from src.database.models import AgentRun
            runs_by_incident: dict[str, float] = {}
            for run in session.scalars(select(AgentRun)):
                if run.stage in INVESTIGATION_STAGES:
                    runs_by_incident[run.incident_id] = runs_by_incident.get(run.incident_id, 0.0) + float(run.duration_ms or 0)
            investigation_times = list(runs_by_incident.values())
            ti_modes: Counter[str] = Counter()
            for record in session.scalars(select(ThreatIntelligence)):
                ti_modes[record.mode] += 1
            executed_actions = int(session.scalar(select(func.count(ResponseAction.id)).where(ResponseAction.status == "EXECUTED")) or 0)
            pending_actions = int(
                session.scalar(select(func.count(ResponseAction.id)).where(ResponseAction.status == "PENDING_APPROVAL")) or 0
            )
            audit_valid, audit_entries, audit_error = repository.verify_audit_chain(session)
            return {
                "generated_at": iso(now),
                "totals": {
                    "incidents": len(incidents),
                    "events": total_events,
                    "alerts": total_alerts,
                    "unresolved_incidents": sum(
                        1 for incident in incidents if incident.status not in {"VERIFIED", "CLOSED", "REJECTED"}
                    ),
                    "pending_approvals": sum(1 for incident in incidents if incident.approval_status == "PENDING"),
                    "verified_incidents": sum(1 for incident in incidents if incident.status == "VERIFIED"),
                    "executed_response_actions": executed_actions,
                    "pending_response_actions": pending_actions,
                },
                "severity": severity_counts,
                "status": dict(status_counts),
                "attack_categories": dict(categories.most_common()),
                "top_source_ips": [{"source_ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
                "mitre_techniques": [{"technique_id": technique, "count": count} for technique, count in runs],
                "timeseries": [{"date": day, **values} for day, values in timeseries.items()],
                "response_time": {
                    "average_seconds": round(statistics.mean(response_times), 2) if response_times else None,
                    "median_seconds": round(statistics.median(response_times), 2) if response_times else None,
                    "p95_seconds": _percentile(response_times, 0.95),
                    "samples": len(response_times),
                },
                "approval_time": {
                    "average_seconds": round(statistics.mean(approval_times), 2) if approval_times else None,
                    "median_seconds": round(statistics.median(approval_times), 2) if approval_times else None,
                    "samples": len(approval_times),
                },
                "investigation_time": {
                    "average_ms": round(statistics.mean(investigation_times), 2) if investigation_times else None,
                    "median_ms": round(statistics.median(investigation_times), 2) if investigation_times else None,
                    "p95_ms": _percentile(investigation_times, 0.95),
                    "samples": len(investigation_times),
                },
                "average_risk_score": round(statistics.mean([float(i.risk_score or 0) for i in incidents]), 2) if incidents else None,
                "llm_modes": dict(llm_modes),
                "threat_intel_modes": dict(ti_modes),
                "audit": {"chain_valid": audit_valid, "entries": audit_entries, "error": audit_error},
                "system": {
                    **runtime_summary(),
                    "llm": llm_status(),
                    "threat_intel": threat_intel_status(),
                    "detection": detection_status(),
                    "database": "ok",
                },
            }
        finally:
            session.close()

    def audit_log(self, *, limit: int = 100, offset: int = 0, incident_id: str | None = None,
                  action: str | None = None) -> dict[str, Any]:
        session = self.session_factory()
        try:
            entries = repository.list_audit(
                session, limit=limit, offset=offset, incident_id=incident_id, action=action, descending=True
            )
            valid, count, error = repository.verify_audit_chain(session)
            return {
                "entries": [entry.to_dict() for entry in entries],
                "chain": {"valid": valid, "entries": count, "error": error},
            }
        finally:
            session.close()

    def health(self) -> dict[str, Any]:
        started = time.perf_counter()
        session = self.session_factory()
        try:
            session.execute(select(1))
            db_status = "ok"
        except Exception as exc:
            db_status = f"error: {type(exc).__name__}"
        finally:
            session.close()
        latency_ms = (time.perf_counter() - started) * 1000
        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "database_latency_ms": round(latency_ms, 2),
            "version": runtime_summary()["app_version"],
            "llm": llm_status()["mode"],
            "threat_intel": threat_intel_status()["mode"],
            "detection": detection_status(),
            "simulation_mode": bool(get_config().get("response", {}).get("simulation_mode", True)),
            "timestamp": iso(utcnow()),
        }
