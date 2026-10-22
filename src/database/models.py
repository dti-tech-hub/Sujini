"""SQLAlchemy ORM models for the incident-response platform."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from src.utils.helpers import iso, utcnow


def _id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": iso(self.created_at),
            "last_login_at": iso(self.last_login_at),
        }


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="NEW", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    attack_category: Mapped[str] = mapped_column(String(64), default="suspicious_activity", index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    investigation_summary: Mapped[str] = mapped_column(Text, default="")
    reasoning: Mapped[list[Any]] = mapped_column(JSON, default=list)
    llm_mode: Mapped[str] = mapped_column(String(40), default="demo_template")
    detection_source: Mapped[str] = mapped_column(String(64), default="rule_engine")
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_status: Mapped[str] = mapped_column(String(24), default="NOT_REQUIRED")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)

    events: Mapped[list["SecurityEvent"]] = relationship(back_populates="incident")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    threat_intelligence: Mapped[list["ThreatIntelligence"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    mitre_mappings: Mapped[list["MitreMapping"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    response_actions: Mapped[list["ResponseAction"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    approvals: Mapped[list["Approval"]] = relationship(back_populates="incident", cascade="all, delete-orphan")

    def to_dict(self, include_events: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "risk_score": round(float(self.risk_score or 0), 2),
            "confidence": round(float(self.confidence or 0), 4),
            "attack_category": self.attack_category,
            "source_ip": self.source_ip,
            "username": self.username,
            "event_count": self.event_count,
            "assigned_to": self.assigned_to,
            "investigation_summary": self.investigation_summary,
            "reasoning": self.reasoning or [],
            "llm_mode": self.llm_mode,
            "detection_source": self.detection_source,
            "approval_required": self.approval_required,
            "approval_status": self.approval_status,
            "verified_at": iso(self.verified_at),
            "closed_at": iso(self.closed_at),
            "resolution": self.resolution,
        }
        if include_events:
            payload["events"] = [event.to_dict() for event in sorted(self.events, key=lambda e: e.timestamp)]
        return payload


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(64), default="api")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(12), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    dataset_label: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    incident: Mapped[Incident | None] = relationship(back_populates="events")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": iso(self.timestamp),
            "received_at": iso(self.received_at),
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "method": self.method,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "incident_id": self.incident_id,
            "is_anomaly": self.is_anomaly,
            "anomaly_score": self.anomaly_score,
            "dataset_label": self.dataset_label,
            "raw_event": self.raw_event or {},
        }


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("security_events.id"), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)

    incident: Mapped[Incident | None] = relationship(back_populates="alerts")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": iso(self.created_at),
            "event_id": self.event_id,
            "incident_id": self.incident_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "username": self.username,
            "status": self.status,
            "details": self.details or {},
        }


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("security_events.id"), nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "event_id": self.event_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "weight": round(float(self.weight or 0), 3),
            "details": self.details or {},
            "created_at": iso(self.created_at),
        }


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), default="ip")
    provider: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(24), default="unknown")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=True)
    mode: Mapped[str] = mapped_column(String(24), default="MOCK")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="threat_intelligence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "provider": self.provider,
            "verdict": self.verdict,
            "score": round(float(self.score or 0), 2),
            "malicious": self.malicious,
            "details": self.details or {},
            "is_mock": self.is_mock,
            "mode": self.mode,
            "fetched_at": iso(self.fetched_at),
            "error": self.error,
        }


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(24), index=True)
    technique_name: Mapped[str] = mapped_column(String(128))
    subtechnique: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tactic: Mapped[str] = mapped_column(String(64))
    tactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    mapping_status: Mapped[str] = mapped_column(String(16), default="candidate")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="mitre_mappings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "subtechnique": self.subtechnique,
            "tactic": self.tactic,
            "tactics": self.tactics or [],
            "confidence": round(float(self.confidence or 0), 3),
            "mapping_status": self.mapping_status,
            "rationale": self.rationale,
            "evidence": self.evidence or [],
            "created_at": iso(self.created_at),
        }


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(16))
    factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    weights: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="risk_assessments")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "score": round(float(self.score or 0), 2),
            "level": self.level,
            "factors": self.factors or {},
            "weights": self.weights or {},
            "explanation": self.explanation,
            "created_at": iso(self.created_at),
        }


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_mode: Mapped[str] = mapped_column(String(16), default="auto")
    status: Mapped[str] = mapped_column(String(24), default="RECOMMENDED", index=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    recommendation_source: Mapped[str] = mapped_column(String(64), default="policy_engine")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="response_actions")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "description": self.description,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
            "policy_mode": self.policy_mode,
            "status": self.status,
            "parameters": self.parameters or {},
            "is_simulated": self.is_simulated,
            "recommendation_source": self.recommendation_source,
            "created_at": iso(self.created_at),
            "approved_at": iso(self.approved_at),
            "approved_by": self.approved_by,
            "executed_at": iso(self.executed_at),
            "result": self.result or {},
            "error": self.error,
        }


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("response_actions.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(String(64), default="RESPONSE_PLAN")
    approver_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approver_username: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    incident: Mapped[Incident] = relationship(back_populates="approvals")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "approver_id": self.approver_id,
            "approver_username": self.approver_username,
            "decision": self.decision,
            "reason": self.reason,
            "created_at": iso(self.created_at),
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    actor_role: Mapped[str] = mapped_column(String(24), default="system")
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), default="incident")
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(24), default="SUCCESS")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": iso(self.timestamp),
            "actor": self.actor,
            "actor_role": self.actor_role,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "incident_id": self.incident_id,
            "outcome": self.outcome,
            "details": self.details or {},
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "request_id": self.request_id,
        }


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    stage: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(24), default="SUCCESS")
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    provider: Mapped[str] = mapped_column(String(64), default="deterministic")
    output_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "stage": self.stage,
            "status": self.status,
            "duration_ms": round(float(self.duration_ms or 0), 2),
            "provider": self.provider,
            "output_summary": self.output_summary or {},
            "error": self.error,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at),
        }
