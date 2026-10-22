"""Metrics, system status, and audit routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_service
from src.database.models import User
from src.security.authentication import get_current_user, require_roles
from src.services.soc_service import SocService

router = APIRouter(prefix="/api", tags=["metrics and audit"])
_reader = Depends(get_current_user)


@router.get("/metrics")
def metrics(
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    return service.metrics()


@router.get("/audit")
def audit(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    incident_id: str | None = None,
    action: str | None = None,
    service: SocService = Depends(get_service),
    user: User = Depends(require_roles("analyst", "admin")),
) -> dict:
    return service.audit_log(limit=limit, offset=offset, incident_id=incident_id, action=action)


@router.get("/system")
def system_status(
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    data = service.metrics()
    return {
        "system": data["system"],
        "audit": data["audit"],
        "totals": data["totals"],
        "generated_at": data["generated_at"],
    }
