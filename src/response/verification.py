"""Verification of executed simulated responses."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import AuditLog, Incident
from src.response.executor import ResponseExecutor
from src.security.audit import AuditService
from src.utils.exceptions import ConflictError
from src.utils.helpers import utcnow


class VerificationService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditService(session)

    def verify(self, incident: Incident, actor: str = "system", actor_role: str = "system",
               request_id: str | None = None) -> dict[str, Any]:
        if incident.status == "FAILED":
            raise ConflictError("Cannot verify an incident whose response execution failed")
        actions = repository.response_actions_for_incident(self.session, incident.id)
        executable = [
            action for action in actions
            if action.policy_mode in {"auto", "approval"}
        ]
        advisory = [action for action in actions if action.policy_mode == "advisory"]

        checks: list[dict[str, Any]] = []
        checks.append({
            "name": "actions_recorded",
            "passed": len(actions) > 0,
            "detail": f"{len(actions)} response action records found",
        })
        checks.append({
            "name": "approved_actions_executed",
            "passed": all(action.status == "EXECUTED" for action in executable) if executable else True,
            "detail": f"{sum(1 for action in executable if action.status == 'EXECUTED')}/{len(executable)} executable actions executed",
        })
        checks.append({
            "name": "simulation_effects_recorded",
            "passed": all(
                action.result.get("simulated") is True and action.result.get("effect") == "No real system was modified."
                for action in executable if action.status == "EXECUTED"
            ) if executable else True,
            "detail": "Every executed simulated action records its no-effect verification",
        })
        checks.append({
            "name": "advisory_not_executed",
            "passed": all(action.status != "EXECUTED" for action in advisory),
            "detail": f"{len(advisory)} advisory action(s) remain non-executed recommendations",
        })
        audit_entries = self.session.scalars(
            select(AuditLog).where(
                AuditLog.incident_id == incident.id,
                AuditLog.action.in_(["RESPONSE_ACTION_EXECUTED", "RESPONSE_APPROVED"]),
            )
        ).all()
        checks.append({
            "name": "audit_trail_present",
            "passed": len(audit_entries) > 0,
            "detail": f"{len(audit_entries)} execution/approval audit entries found",
        })
        unresolved = [action for action in executable if action.status not in {"EXECUTED", "REJECTED"}]
        checks.append({
            "name": "no_unresolved_actions",
            "passed": not unresolved,
            "detail": f"{len(unresolved)} unresolved executable action(s)",
        })

        verified = all(check["passed"] for check in checks)
        now = utcnow()
        if verified:
            incident.status = "VERIFIED"
            incident.verified_at = now
            incident.updated_at = now
            incident.resolution = "Simulated response executed and verified. No real system was modified."
        self.session.flush()
        self.audit.record(
            actor=actor,
            actor_role=actor_role,
            action="RESPONSE_VERIFIED" if verified else "RESPONSE_VERIFICATION_FAILED",
            entity_type="incident",
            entity_id=incident.id,
            incident_id=incident.id,
            outcome="SUCCESS" if verified else "FAILED",
            details={"checks": checks},
            request_id=request_id,
        )
        audit_result = self.audit.verify()
        return {
            "incident_id": incident.id,
            "verified": verified,
            "status": incident.status,
            "checks": checks,
            "audit_chain_valid": audit_result["valid"],
            "audit_entries": audit_result["entries"],
            "verified_at": incident.verified_at.isoformat() if incident.verified_at else None,
        }
