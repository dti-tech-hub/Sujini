"""Human approval decisions for response plans."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import Incident, ResponseAction, User
from src.response.actions import simulation_mode
from src.security.audit import AuditService
from src.utils.config import get_response_rules
from src.utils.exceptions import ConflictError, PolicyError, ValidationError
from src.utils.helpers import utcnow
from src.utils.logging import get_logger

logger = get_logger(__name__)


class ApprovalService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.rules = get_response_rules().get("approval", {})
        self.audit = AuditService(session)

    def _check_role(self, approver: User) -> None:
        allowed = {role.lower() for role in self.rules.get("allowed_roles", ["analyst", "admin"])}
        if approver.role.lower() not in allowed:
            raise PolicyError(f"Role '{approver.role}' is not allowed to approve response actions")

    def decide(
        self,
        incident: Incident,
        approver: User,
        decision: str,
        reason: str,
        request_id: str | None = None,
        action_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self._check_role(approver)
        decision = decision.upper().strip()
        if decision not in {"APPROVED", "REJECTED"}:
            raise ValidationError("Decision must be APPROVED or REJECTED")
        if incident.status != "AWAITING_APPROVAL":
            raise ConflictError(f"Incident {incident.id} is not awaiting approval (status={incident.status})")
        if incident.approval_status != "PENDING":
            raise ConflictError(f"Incident {incident.id} has no pending approval (approval_status={incident.approval_status})")

        actions = repository.response_actions_for_incident(self.session, incident.id)
        pending = [action for action in actions if action.requires_approval and action.status == "PENDING_APPROVAL"]
        if not pending:
            raise ConflictError("No approval-gated actions are pending")

        if action_ids:
            requested = set(action_ids)
            pending_ids = {action.id for action in pending}
            if requested != pending_ids:
                raise ValidationError(
                    "action_ids must include every pending approval-gated action; partial approval is not supported"
                )

        if decision == "REJECTED":
            minimum = int(self.rules.get("min_reason_length", 3))
            if len(reason.strip()) < minimum:
                raise ValidationError(f"Rejection reason must be at least {minimum} characters")

        now = utcnow()
        for action in actions:
            if action.requires_approval and action.status == "PENDING_APPROVAL":
                action.status = decision
                action.approved_at = now
                action.approved_by = approver.username
                repository.add_approval(
                    self.session,
                    incident.id,
                    action_id=action.id,
                    action_type=action.action_type,
                    approver_id=approver.id,
                    approver_username=approver.username,
                    decision=decision,
                    reason=reason.strip(),
                )

        if decision == "APPROVED":
            incident.status = "APPROVED"
            incident.approval_status = "APPROVED"
            outcome = "APPROVED"
            audit_action = "RESPONSE_APPROVED"
        else:
            incident.status = "REJECTED"
            incident.approval_status = "REJECTED"
            incident.closed_at = now
            incident.resolution = f"Response plan rejected: {reason.strip()}"
            for action in actions:
                if not action.requires_approval and action.policy_mode in {"auto", "approval"} and action.status == "APPROVED":
                    action.status = "REJECTED"
            outcome = "REJECTED"
            audit_action = "RESPONSE_REJECTED"

        incident.updated_at = now
        self.session.flush()
        self.audit.record(
            actor=approver.username,
            actor_role=approver.role,
            action=audit_action,
            entity_type="incident",
            entity_id=incident.id,
            incident_id=incident.id,
            outcome=outcome,
            details={
                "decision": decision,
                "reason": reason.strip(),
                "action_ids": [action.id for action in pending],
                "action_types": [action.action_type for action in pending],
                "simulation_mode": simulation_mode(),
            },
            request_id=request_id,
        )
        return {
            "incident": incident.to_dict(),
            "decision": decision,
            "approver": approver.username,
            "reason": reason.strip(),
            "actions": [action.to_dict() for action in actions],
        }
