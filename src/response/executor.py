"""Controlled executor for simulated response actions.

This executor cannot modify a firewall, session store, credential store, or
host. It records plausible simulation results and audit entries. There is no
code path from LLM output to shell or network-mutating operations.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Incident, ResponseAction
from src.response.actions import action_definition, is_allowed_action, simulation_mode
from src.security.audit import AuditService
from src.utils.exceptions import ConflictError, PolicyError
from src.utils.helpers import utcnow
from src.utils.logging import get_logger

logger = get_logger(__name__)


class ResponseExecutor:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditService(session)

    def execute(self, incident: Incident, actor: str, actor_role: str, request_id: str | None = None) -> dict[str, Any]:
        if not simulation_mode():
            raise PolicyError(
                "Real response execution is disabled. This project only supports simulation_mode=true."
            )
        if incident.status not in {"APPROVED", "CONTAINMENT"}:
            raise ConflictError(f"Incident {incident.id} is not approved for execution (status={incident.status})")

        actions = repository.response_actions_for_incident(self.session, incident.id)
        executable = [
            action for action in actions
            if action.policy_mode in {"auto", "approval"} and action.status in {"APPROVED", "EXECUTED"}
        ]
        if not executable:
            raise ConflictError("No approved executable actions found")
        if any(action.requires_approval and action.status != "APPROVED" for action in executable if action.status != "EXECUTED"):
            raise ConflictError("An approval-gated action has not been approved")

        executed: list[ResponseAction] = []
        failed: list[ResponseAction] = []
        now = utcnow()
        for action in executable:
            if action.status == "EXECUTED":
                executed.append(action)
                continue
            self.audit.record(
                actor=actor,
                actor_role=actor_role,
                action="RESPONSE_ACTION_STARTED",
                entity_type="response_action",
                entity_id=action.id,
                incident_id=incident.id,
                outcome="STARTED",
                details={"action_type": action.action_type, "simulated": action.is_simulated},
                request_id=request_id,
            )
            try:
                if not is_allowed_action(action.action_type):
                    raise PolicyError(f"Action '{action.action_type}' is not in the response allowlist")
                definition = action_definition(action.action_type)
                if not definition:
                    raise PolicyError(f"Unknown response action '{action.action_type}'")
                if not action.is_simulated and action.action_type.startswith("SIMULATE_"):
                    raise PolicyError("Simulated action has inconsistent simulation metadata")
                action.status = "EXECUTED"
                action.executed_at = now
                action.result = {
                    "status": "EXECUTED",
                    "simulated": bool(action.is_simulated),
                    "mode": "SIMULATION" if action.is_simulated else "RECORD_ONLY",
                    "effect": "No real system was modified.",
                    "action_type": action.action_type,
                    "target": {
                        "source_ip": action.parameters.get("source_ip"),
                        "username": action.parameters.get("username"),
                    },
                    "executed_at": now.isoformat(),
                    "execution_id": action.id,
                }
                action.error = None
                executed.append(action)
                self.audit.record(
                    actor=actor,
                    actor_role=actor_role,
                    action="RESPONSE_ACTION_EXECUTED",
                    entity_type="response_action",
                    entity_id=action.id,
                    incident_id=incident.id,
                    outcome="SUCCESS",
                    details={
                        "action_type": action.action_type,
                        "simulated": action.is_simulated,
                        "result": action.result,
                    },
                    request_id=request_id,
                )
            except Exception as exc:  # noqa: BLE001 - every failure is contained and audited
                action.status = "FAILED"
                action.error = str(exc)[:500]
                action.result = {"status": "FAILED", "error": action.error}
                failed.append(action)
                self.audit.record(
                    actor=actor,
                    actor_role=actor_role,
                    action="RESPONSE_ACTION_FAILED",
                    entity_type="response_action",
                    entity_id=action.id,
                    incident_id=incident.id,
                    outcome="FAILED",
                    details={"action_type": action.action_type, "error": action.error},
                    request_id=request_id,
                )

        incident.status = "CONTAINMENT" if not failed else "FAILED"
        incident.updated_at = now
        self.session.flush()
        return {
            "incident_id": incident.id,
            "executed": [action.to_dict() for action in executed],
            "failed": [action.to_dict() for action in failed],
            "all_succeeded": not failed,
            "actor": actor,
        }
