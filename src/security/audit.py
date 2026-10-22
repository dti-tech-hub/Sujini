"""Application audit trail service."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import AuditLog
from src.utils.logging import get_logger

logger = get_logger(__name__)


class AuditService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record(
        self,
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
    ) -> AuditLog:
        entry = repository.append_audit(
            self.session,
            actor=actor,
            actor_role=actor_role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            incident_id=incident_id,
            outcome=outcome,
            details=details or {},
            request_id=request_id,
        )
        logger.info(
            "audit",
            extra={
                "audit_id": entry.id,
                "incident_id": incident_id,
                "action": action,
                "actor": actor,
                "result": outcome,
            },
        )
        return entry

    def verify(self) -> dict[str, Any]:
        valid, count, error = repository.verify_audit_chain(self.session)
        return {"valid": valid, "entries": count, "error": error}
