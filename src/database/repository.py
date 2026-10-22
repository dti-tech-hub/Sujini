"""Persistence helpers.

All database access is parameterized through SQLAlchemy; raw SQL string
concatenation is not used anywhere in the application.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from src.database.models import (
    AgentRun, Alert, Approval, AuditLog, Evidence, Incident, MitreMapping,
    ResponseAction, RiskAssessment, SecurityEvent, ThreatIntelligence, User,
)
from src.utils.helpers import dumps, hash_chain, iso, natural_sort_key, utcnow

TERMINAL_INCIDENT_STATUSES = {"VERIFIED", "CLOSED", "REJECTED", "FAILED"}


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def create_user(session: Session, username: str, password_hash: str, role: str = "viewer") -> User:
    user = User(username=username, password_hash=password_hash, role=role)
    session.add(user)
    session.flush()
    return user


def get_user_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username))


def count_users(session: Session) -> int:
    return int(session.scalar(select(func.count(User.id))) or 0)


def touch_last_login(session: Session, user: User) -> None:
    user.last_login_at = utcnow()
    session.flush()


# ---------------------------------------------------------------------------
# Events and alerts
# ---------------------------------------------------------------------------
def add_event(session: Session, payload: dict[str, Any]) -> tuple[SecurityEvent, bool]:
    existing = session.scalar(select(SecurityEvent).where(SecurityEvent.dedup_hash == payload["dedup_hash"]))
    if existing:
        return existing, False
    event = SecurityEvent(**payload)
    session.add(event)
    session.flush()
    return event, True


def list_events(
    session: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
    severity: str | None = None,
    source_ip: str | None = None,
    incident_id: str | None = None,
) -> list[SecurityEvent]:
    query = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).offset(offset)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if source_ip:
        query = query.where(SecurityEvent.source_ip == source_ip)
    if incident_id:
        query = query.where(SecurityEvent.incident_id == incident_id)
    return list(session.scalars(query))


def get_event(session: Session, event_id: str) -> SecurityEvent | None:
    return session.get(SecurityEvent, event_id)


def events_since(session: Session, since: datetime, limit: int = 1000) -> list[SecurityEvent]:
    query = select(SecurityEvent).where(SecurityEvent.timestamp >= since).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    return list(session.scalars(query))


def events_for_ip_since(session: Session, source_ip: str, since: datetime, limit: int = 500) -> list[SecurityEvent]:
    query = (
        select(SecurityEvent)
        .where(SecurityEvent.source_ip == source_ip, SecurityEvent.timestamp >= since)
        .order_by(SecurityEvent.timestamp.asc())
        .limit(limit)
    )
    return list(session.scalars(query))


def events_for_user_since(session: Session, username: str, since: datetime, limit: int = 500) -> list[SecurityEvent]:
    query = (
        select(SecurityEvent)
        .where(SecurityEvent.username == username, SecurityEvent.timestamp >= since)
        .order_by(SecurityEvent.timestamp.asc())
        .limit(limit)
    )
    return list(session.scalars(query))


def events_for_incident(session: Session, incident_id: str) -> list[SecurityEvent]:
    query = (
        select(SecurityEvent)
        .where(SecurityEvent.incident_id == incident_id)
        .order_by(SecurityEvent.timestamp.asc())
    )
    return list(session.scalars(query))


def attach_event_to_incident(session: Session, event: SecurityEvent, incident_id: str) -> None:
    if event.incident_id != incident_id:
        event.incident_id = incident_id
        session.flush()


def add_alert(session: Session, payload: dict[str, Any]) -> tuple[Alert, bool]:
    existing = session.scalar(select(Alert).where(Alert.dedup_key == payload["dedup_key"]))
    if existing:
        return existing, False
    alert = Alert(**payload)
    session.add(alert)
    session.flush()
    return alert, True


def list_alerts(
    session: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    severity: str | None = None,
    incident_id: str | None = None,
) -> list[Alert]:
    query = select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    if severity:
        query = query.where(Alert.severity == severity)
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)
    return list(session.scalars(query))


def alerts_for_incident(session: Session, incident_id: str) -> list[Alert]:
    return list(
        session.scalars(
            select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.created_at.asc())
        )
    )


def count_alerts_since(session: Session, since: datetime) -> int:
    return int(session.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since)) or 0)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
def next_incident_id(session: Session) -> str:
    ids = list(session.scalars(select(Incident.id)))
    numbers = []
    for value in ids:
        try:
            numbers.append(int(value.split("-")[-1]))
        except (ValueError, IndexError):
            continue
    return f"INC-{(max(numbers) if numbers else 0) + 1:04d}"


def create_incident(session: Session, **fields: Any) -> Incident:
    if "id" not in fields or not fields["id"]:
        fields["id"] = next_incident_id(session)
    incident = Incident(**fields)
    session.add(incident)
    session.flush()
    return incident


def get_incident(session: Session, incident_id: str, *, full: bool = False) -> Incident | None:
    if not full:
        return session.get(Incident, incident_id)
    query = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.events),
            selectinload(Incident.alerts),
            selectinload(Incident.evidence),
            selectinload(Incident.threat_intelligence),
            selectinload(Incident.mitre_mappings),
            selectinload(Incident.risk_assessments),
            selectinload(Incident.response_actions),
            selectinload(Incident.approvals),
        )
    )
    return session.scalar(query)


def list_incidents(
    session: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source_ip: str | None = None,
    approval_status: str | None = None,
) -> list[Incident]:
    query = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if category:
        query = query.where(Incident.attack_category == category)
    if source_ip:
        query = query.where(Incident.source_ip == source_ip)
    if approval_status:
        query = query.where(Incident.approval_status == approval_status)
    return list(session.scalars(query))


def count_incidents(session: Session) -> int:
    return int(session.scalar(select(func.count(Incident.id))) or 0)


def find_correlated_incident(
    session: Session,
    *,
    source_ip: str | None,
    username: str | None,
    since: datetime,
) -> Incident | None:
    """Find a recent non-terminal incident sharing the strongest key."""
    key_field = Incident.source_ip if source_ip else Incident.username
    key_value = source_ip or username
    if not key_value:
        return None
    query = (
        select(Incident)
        .where(
            key_field == key_value,
            Incident.created_at >= since,
            Incident.status.notin_(list(TERMINAL_INCIDENT_STATUSES)),
        )
        .order_by(Incident.created_at.desc())
    )
    return session.scalar(query)


def update_incident(session: Session, incident: Incident, **fields: Any) -> Incident:
    for key, value in fields.items():
        if hasattr(incident, key):
            setattr(incident, key, value)
    incident.updated_at = utcnow()
    session.flush()
    return incident


def refresh_event_count(session: Session, incident: Incident) -> int:
    count = int(
        session.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.incident_id == incident.id)) or 0
    )
    incident.event_count = count
    session.flush()
    return count


# ---------------------------------------------------------------------------
# Investigation artifacts
# ---------------------------------------------------------------------------
def add_evidence(session: Session, incident_id: str, **fields: Any) -> Evidence:
    record = Evidence(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def delete_evidence_for_incident(session: Session, incident_id: str) -> None:
    for record in session.scalars(select(Evidence).where(Evidence.incident_id == incident_id)):
        session.delete(record)
    session.flush()


def add_threat_intelligence(session: Session, incident_id: str, **fields: Any) -> ThreatIntelligence:
    record = ThreatIntelligence(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def latest_threat_intel(session: Session, indicator: str, provider: str, since: datetime) -> ThreatIntelligence | None:
    query = (
        select(ThreatIntelligence)
        .where(
            ThreatIntelligence.indicator == indicator,
            ThreatIntelligence.provider == provider,
            ThreatIntelligence.fetched_at >= since,
        )
        .order_by(ThreatIntelligence.fetched_at.desc())
    )
    return session.scalar(query)


def add_mitre_mapping(session: Session, incident_id: str, **fields: Any) -> MitreMapping:
    record = MitreMapping(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def delete_mitre_for_incident(session: Session, incident_id: str) -> None:
    for record in session.scalars(select(MitreMapping).where(MitreMapping.incident_id == incident_id)):
        session.delete(record)
    session.flush()


def add_risk_assessment(session: Session, incident_id: str, **fields: Any) -> RiskAssessment:
    record = RiskAssessment(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def latest_risk(session: Session, incident_id: str) -> RiskAssessment | None:
    return session.scalar(
        select(RiskAssessment)
        .where(RiskAssessment.incident_id == incident_id)
        .order_by(RiskAssessment.created_at.desc())
    )


def add_response_action(session: Session, incident_id: str, **fields: Any) -> ResponseAction:
    record = ResponseAction(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def get_response_action(session: Session, action_id: str) -> ResponseAction | None:
    return session.get(ResponseAction, action_id)


def response_actions_for_incident(session: Session, incident_id: str) -> list[ResponseAction]:
    return list(
        session.scalars(
            select(ResponseAction)
            .where(ResponseAction.incident_id == incident_id)
            .order_by(ResponseAction.created_at.asc())
        )
    )


def delete_actions_for_incident(session: Session, incident_id: str) -> None:
    for record in session.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id)):
        session.delete(record)
    session.flush()


def add_approval(session: Session, incident_id: str, **fields: Any) -> Approval:
    record = Approval(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def approvals_for_incident(session: Session, incident_id: str) -> list[Approval]:
    return list(
        session.scalars(
            select(Approval).where(Approval.incident_id == incident_id).order_by(Approval.created_at.asc())
        )
    )


def add_agent_run(session: Session, incident_id: str, **fields: Any) -> AgentRun:
    record = AgentRun(incident_id=incident_id, **fields)
    session.add(record)
    session.flush()
    return record


def agent_runs_for_incident(session: Session, incident_id: str) -> list[AgentRun]:
    return list(
        session.scalars(
            select(AgentRun).where(AgentRun.incident_id == incident_id).order_by(AgentRun.started_at.asc())
        )
    )


# ---------------------------------------------------------------------------
# Audit trail (append-only, hash chained)
# ---------------------------------------------------------------------------
def append_audit(
    session: Session,
    *,
    actor: str,
    actor_role: str,
    action: str,
    entity_type: str = "incident",
    entity_id: str | None = None,
    incident_id: str | None = None,
    outcome: str = "SUCCESS",
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
    timestamp: datetime | None = None,
) -> AuditLog:
    previous = session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    previous_hash = previous.entry_hash if previous else "GENESIS"
    ts = timestamp or utcnow()
    payload = {
        "timestamp": iso(ts),
        "actor": actor,
        "actor_role": actor_role,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "incident_id": incident_id,
        "outcome": outcome,
        "details": details or {},
        "request_id": request_id,
    }
    entry_hash = hash_chain(previous_hash, dumps(payload))
    entry = AuditLog(
        timestamp=ts,
        actor=actor,
        actor_role=actor_role,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        incident_id=incident_id,
        outcome=outcome,
        details=details or {},
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        request_id=request_id,
    )
    session.add(entry)
    session.flush()
    return entry


def list_audit(
    session: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    incident_id: str | None = None,
    action: str | None = None,
    descending: bool = False,
) -> list[AuditLog]:
    order = AuditLog.id.desc() if descending else AuditLog.id.asc()
    query = select(AuditLog).order_by(order).limit(limit).offset(offset)
    if incident_id:
        query = query.where(AuditLog.incident_id == incident_id)
    if action:
        query = query.where(AuditLog.action == action)
    return list(session.scalars(query))


def all_audit_entries(session: Session) -> list[AuditLog]:
    return list(session.scalars(select(AuditLog).order_by(AuditLog.id.asc())))


def verify_audit_chain(session: Session) -> tuple[bool, int, str | None]:
    entries = all_audit_entries(session)
    previous_hash = "GENESIS"
    for entry in entries:
        payload = {
            "timestamp": iso(entry.timestamp),
            "actor": entry.actor,
            "actor_role": entry.actor_role,
            "action": entry.action,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "incident_id": entry.incident_id,
            "outcome": entry.outcome,
            "details": entry.details or {},
            "request_id": entry.request_id,
        }
        expected = hash_chain(previous_hash, dumps(payload))
        if entry.previous_hash != previous_hash or entry.entry_hash != expected:
            return False, len(entries), f"Chain break at audit entry {entry.id}"
        previous_hash = entry.entry_hash
    return True, len(entries), None
