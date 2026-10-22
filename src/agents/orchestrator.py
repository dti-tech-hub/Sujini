"""LangGraph orchestration for investigation and response workflows."""
from __future__ import annotations

import time
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph
from sqlalchemy.orm import Session

from src.agents.mitre_agent import MitreAgent
from src.agents.response_agent import ResponseAgent
from src.agents.risk_agent import RiskAgent
from src.agents.threat_intel_agent import ThreatIntelAgent
from src.database import repository
from src.database.models import Incident
from src.investigation.evidence import EvidenceAgent
from src.investigation.incident_analysis import InvestigationAgent
from src.response.executor import ResponseExecutor
from src.response.verification import VerificationService
from src.security.audit import AuditService
from src.utils.config import get_config
from src.utils.exceptions import NotFoundError
from src.utils.helpers import utcnow
from src.utils.logging import get_logger, log_stage

logger = get_logger(__name__)


class InvestigationState(TypedDict, total=False):
    incident_id: str
    actor: str
    request_id: str | None
    events: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    correlation: dict[str, Any]
    classification: str
    confidence: float
    severity: str
    investigation_summary: str
    reasoning: list[str]
    recommended_next_steps: list[str]
    llm_mode: str
    prompt_injection_flags: int
    threat_intel: dict[str, Any]
    mitre_techniques: list[dict[str, Any]]
    mitre_note: str
    risk_score: float
    risk_level: str
    risk_assessment: dict[str, Any]
    response_plan: dict[str, Any]
    approval_required: bool
    approval_status: str
    status: str
    audit_entries: list[int]
    error: str | None


class ResponseState(TypedDict, total=False):
    incident_id: str
    actor: str
    actor_role: str
    request_id: str | None
    execution: dict[str, Any]
    verification: dict[str, Any]
    audit_entries: list[int]
    error: str | None


class Orchestrator:
    """Two-phase agent workflow.

    Phase 1: evidence -> triage -> threat intel -> MITRE -> risk -> response
             plan -> approval gate.
    Phase 2 (after auto-policy or human approval): execute -> verify -> audit.

    The split makes the human approval gate durable in the database rather
    than holding a long-running graph in memory.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditService(session)
        self.config = get_config()
        self.investigation_graph = self._build_investigation_graph()
        self.response_graph = self._build_response_graph()

    def _incident(self, incident_id: str) -> Incident:
        incident = repository.get_incident(self.session, incident_id)
        if not incident:
            raise NotFoundError(f"Incident {incident_id} not found")
        return incident

    def _summary(self, stage: str, result: dict[str, Any]) -> dict[str, Any]:
        if stage == "evidence_collection":
            return {
                "evidence_total": result.get("total"),
                "evidence_added": result.get("added"),
                "correlation_confidence": (result.get("correlation") or {}).get("correlation_confidence"),
            }
        if stage == "alert_triage":
            return {
                "classification": result.get("classification"),
                "confidence": result.get("confidence"),
                "severity": result.get("severity"),
                "llm_mode": result.get("llm_mode"),
            }
        if stage == "threat_intelligence":
            return {
                "verdict": result.get("verdict"),
                "mode": result.get("mode"),
                "indicator_count": len(result.get("indicators", [])),
            }
        if stage == "mitre_mapping":
            return {
                "technique_count": len(result.get("techniques", [])),
                "confirmed": sum(1 for item in result.get("techniques", []) if item.get("mapping_status") == "confirmed"),
                "candidate": sum(1 for item in result.get("techniques", []) if item.get("mapping_status") == "candidate"),
            }
        if stage == "risk_assessment":
            return {"risk_score": result.get("score"), "risk_level": result.get("level")}
        if stage == "response_planning":
            return {
                "action_count": len(result.get("actions", [])),
                "approval_required": result.get("approval_required"),
            }
        if stage == "approval_gate":
            return {"approval_required": result.get("approval_required"), "approval_status": result.get("approval_status")}
        return {}

    def _run_stage(
        self,
        state: dict[str, Any],
        *,
        stage: str,
        audit_action: str,
        func: Callable[[dict[str, Any]], dict[str, Any]],
        provider: str = "deterministic_rules",
    ) -> dict[str, Any]:
        started = utcnow()
        started_perf = time.perf_counter()
        incident_id = state["incident_id"]
        try:
            result = func(state)
            duration_ms = (time.perf_counter() - started_perf) * 1000
            summary = self._summary(stage, result)
            repository.add_agent_run(
                self.session,
                incident_id,
                stage=stage,
                status="SUCCESS",
                duration_ms=duration_ms,
                provider=provider,
                output_summary=summary,
                started_at=started,
                finished_at=utcnow(),
            )
            entry = self.audit.record(
                actor="agent",
                actor_role="system",
                action=audit_action,
                entity_type="incident",
                entity_id=incident_id,
                incident_id=incident_id,
                outcome="SUCCESS",
                details={"stage": stage, "duration_ms": round(duration_ms, 2), **summary},
                request_id=state.get("request_id"),
            )
            log_stage(logger, stage, incident_id=incident_id, duration_ms=duration_ms, result="SUCCESS", **summary)
            result["audit_entries"] = list(state.get("audit_entries", [])) + [entry.id]
            return result
        except Exception as exc:
            duration_ms = (time.perf_counter() - started_perf) * 1000
            repository.add_agent_run(
                self.session,
                incident_id,
                stage=stage,
                status="FAILED",
                duration_ms=duration_ms,
                provider=provider,
                output_summary={},
                error=f"{type(exc).__name__}: {str(exc)[:400]}",
                started_at=started,
                finished_at=utcnow(),
            )
            self.audit.record(
                actor="agent",
                actor_role="system",
                action=f"{audit_action}_FAILED",
                entity_type="incident",
                entity_id=incident_id,
                incident_id=incident_id,
                outcome="FAILED",
                details={"stage": stage, "duration_ms": round(duration_ms, 2), "error": str(exc)[:400]},
                request_id=state.get("request_id"),
            )
            log_stage(logger, stage, incident_id=incident_id, duration_ms=duration_ms, result="FAILED", error=str(exc)[:300])
            raise

    # -- phase 1 nodes ---------------------------------------------------
    def _evidence_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            output = EvidenceAgent(self.session).collect(incident)
            return {
                "evidence": output["evidence"],
                "correlation": output["correlation"],
                "prompt_injection_flags": output["prompt_injection_flags"],
                "events": [event.to_dict() for event in repository.events_for_incident(self.session, incident.id)],
                "alerts": [alert.to_dict() for alert in repository.alerts_for_incident(self.session, incident.id)],
            }
        return self._run_stage(state, stage="evidence_collection", audit_action="EVIDENCE_COLLECTED", func=act, provider="evidence_rules")

    def _triage_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            events = repository.events_for_incident(self.session, incident.id)
            alerts = repository.alerts_for_incident(self.session, incident.id)
            result = InvestigationAgent(self.session).investigate(
                incident,
                events,
                alerts,
                correlation=EvidenceAgent(self.session).collect(incident)["correlation"] if not state.get("correlation") else _correlation_object(state["correlation"]),
                prompt_injection_flags=int(state.get("prompt_injection_flags", 0)),
            )
            incident.attack_category = result.classification
            incident.confidence = result.confidence
            incident.investigation_summary = result.summary
            incident.reasoning = result.reasoning + [f"Next steps: {step}" for step in result.next_steps]
            incident.llm_mode = result.llm_mode
            self.session.flush()
            return {
                "classification": result.classification,
                "confidence": result.confidence,
                "severity": result.severity,
                "investigation_summary": result.summary,
                "reasoning": result.reasoning,
                "recommended_next_steps": result.next_steps,
                "llm_mode": result.llm_mode,
            }
        return self._run_stage(state, stage="alert_triage", audit_action="INVESTIGATION_COMPLETED", func=act, provider="investigation_agent")

    def _threat_intel_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            events = repository.events_for_incident(self.session, incident.id)
            return {"threat_intel": ThreatIntelAgent(self.session).run(incident, events)}
        return self._run_stage(state, stage="threat_intelligence", audit_action="THREAT_INTEL_ENRICHED", func=act, provider="threat_intel")

    def _mitre_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            alerts = repository.alerts_for_incident(self.session, incident.id)
            output = MitreAgent(self.session).run(
                incident,
                classification=state.get("classification", incident.attack_category),
                confidence=float(state.get("confidence", incident.confidence)),
                alerts=alerts,
            )
            return {
                "mitre_techniques": output["techniques"],
                "mitre_note": output["note"],
            }
        return self._run_stage(state, stage="mitre_mapping", audit_action="MITRE_MAPPED", func=act, provider="mitre_mapper")

    def _risk_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            events = repository.events_for_incident(self.session, incident.id)
            output = RiskAgent(self.session).run(
                incident,
                severity=state.get("severity", incident.severity),
                confidence=float(state.get("confidence", incident.confidence)),
                category=state.get("classification", incident.attack_category),
                events=events,
                threat_intel=state.get("threat_intel", {}),
            )
            return {
                "risk_score": output["score"],
                "risk_level": output["level"],
                "risk_assessment": output,
            }
        return self._run_stage(state, stage="risk_assessment", audit_action="RISK_CALCULATED", func=act, provider="risk_model")

    def _response_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            plan = ResponseAgent(self.session).run(
                incident,
                risk_level=state.get("risk_level", incident.severity),
                category=state.get("classification", incident.attack_category),
            )
            return {
                "response_plan": plan,
                "approval_required": plan["approval_required"],
            }
        return self._run_stage(state, stage="response_planning", audit_action="RESPONSE_PLANNED", func=act, provider="policy_engine")

    def _approval_gate_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            required = bool(state.get("approval_required", incident.approval_required))
            if required:
                incident.status = "AWAITING_APPROVAL"
                incident.approval_status = "PENDING"
                incident.approval_required = True
            else:
                incident.status = "APPROVED"
                incident.approval_status = "NOT_REQUIRED"
                incident.approval_required = False
            self.session.flush()
            return {
                "approval_required": required,
                "approval_status": incident.approval_status,
                "status": incident.status,
            }
        return self._run_stage(
            state,
            stage="approval_gate",
            audit_action="APPROVAL_REQUESTED" if state.get("approval_required") else "AUTO_APPROVAL_GRANTED",
            func=act,
            provider="policy_engine",
        )

    def _build_investigation_graph(self):
        graph = StateGraph(InvestigationState)
        graph.add_node("evidence_collection", self._evidence_node)
        graph.add_node("alert_triage", self._triage_node)
        graph.add_node("threat_intelligence", self._threat_intel_node)
        graph.add_node("mitre_mapping", self._mitre_node)
        graph.add_node("risk_assessment", self._risk_node)
        graph.add_node("response_planning", self._response_node)
        graph.add_node("approval_gate", self._approval_gate_node)
        graph.add_edge(START, "evidence_collection")
        graph.add_edge("evidence_collection", "alert_triage")
        graph.add_edge("alert_triage", "threat_intelligence")
        graph.add_edge("threat_intelligence", "mitre_mapping")
        graph.add_edge("mitre_mapping", "risk_assessment")
        graph.add_edge("risk_assessment", "response_planning")
        graph.add_edge("response_planning", "approval_gate")
        graph.add_edge("approval_gate", END)
        return graph.compile()

    # -- phase 2 nodes ---------------------------------------------------
    def _execute_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            execution = ResponseExecutor(self.session).execute(
                incident,
                actor=state.get("actor", "system"),
                actor_role=state.get("actor_role", "system"),
                request_id=state.get("request_id"),
            )
            return {"execution": execution}
        return self._run_stage(state, stage="response_execution", audit_action="RESPONSE_EXECUTED", func=act, provider="simulated_executor")

    def _verify_node(self, state: dict[str, Any]) -> dict[str, Any]:
        def act(state: dict[str, Any]) -> dict[str, Any]:
            incident = self._incident(state["incident_id"])
            verification = VerificationService(self.session).verify(
                incident,
                actor=state.get("actor", "system"),
                actor_role=state.get("actor_role", "system"),
                request_id=state.get("request_id"),
            )
            return {"verification": verification}
        return self._run_stage(state, stage="response_verification", audit_action="RESPONSE_VERIFICATION_COMPLETED", func=act, provider="verification_rules")

    def _build_response_graph(self):
        graph = StateGraph(ResponseState)
        graph.add_node("execute", self._execute_node)
        graph.add_node("verify", self._verify_node)
        graph.add_edge(START, "execute")
        graph.add_edge("execute", "verify")
        graph.add_edge("verify", END)
        return graph.compile()

    # -- public API ------------------------------------------------------
    def investigate(self, incident_id: str, *, actor: str, request_id: str | None = None) -> dict[str, Any]:
        initial: InvestigationState = {
            "incident_id": incident_id,
            "actor": actor,
            "request_id": request_id,
            "audit_entries": [],
        }
        return dict(self.investigation_graph.invoke(initial, config={"recursion_limit": 50}))

    def execute_approved(self, incident_id: str, *, actor: str, actor_role: str,
                         request_id: str | None = None) -> dict[str, Any]:
        initial: ResponseState = {
            "incident_id": incident_id,
            "actor": actor,
            "actor_role": actor_role,
            "request_id": request_id,
            "audit_entries": [],
        }
        return dict(self.response_graph.invoke(initial, config={"recursion_limit": 30}))


def _correlation_object(payload: dict[str, Any]):
    """Rebuild a CorrelationResult from serialized state."""
    from src.investigation.correlation import CorrelationResult
    from src.utils.helpers import parse_timestamp

    first, _ = parse_timestamp(payload.get("first_seen"))
    last, _ = parse_timestamp(payload.get("last_seen"))
    return CorrelationResult(
        event_count=int(payload.get("event_count", 0)),
        first_seen=first,
        last_seen=last,
        duration_seconds=float(payload.get("duration_seconds", 0)),
        source_ips=list(payload.get("source_ips", [])),
        usernames=list(payload.get("usernames", [])),
        endpoints=list(payload.get("endpoints", [])),
        event_types=dict(payload.get("event_types", {})),
        alert_types=dict(payload.get("alert_types", {})),
        failed_login_count=int(payload.get("failed_login_count", 0)),
        success_after_failures=bool(payload.get("success_after_failures")),
        suspicious_request_count=int(payload.get("suspicious_request_count", 0)),
        correlation_keys=list(payload.get("correlation_keys", [])),
        correlation_confidence=float(payload.get("correlation_confidence", 0)),
        summary=str(payload.get("summary", "")),
    )
