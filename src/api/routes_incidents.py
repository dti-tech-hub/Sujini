"""Incident routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status

from src.api.deps import get_request_id, get_service
from src.api.schemas import IncidentCreate
from src.database.models import User
from src.security.authentication import get_current_user, require_roles
from src.services.soc_service import SocService

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
_reader = Depends(get_current_user)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = Depends(require_roles("analyst", "admin")),
) -> dict:
    return service.create_incident(
        payload.model_dump(exclude_none=True),
        actor=user.username,
        actor_role=user.role,
        request_id=get_request_id(request),
    )


@router.get("")
def list_incidents(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    category: str | None = None,
    source_ip: str | None = None,
    approval_status: str | None = None,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.list_incidents(
        limit=limit, offset=offset, status=status_filter, severity=severity,
        category=category, source_ip=source_ip, approval_status=approval_status,
    )
    return {"items": items, "count": len(items), "limit": limit, "offset": offset}


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    return service.get_incident_detail(incident_id)
