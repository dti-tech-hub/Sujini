"""Security event and alert routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_request_id, get_service
from src.api.schemas import EventBatch, EventIn
from src.database.models import User
from src.security.authentication import get_current_user, require_roles
from src.services.soc_service import SocService

router = APIRouter(prefix="/api", tags=["events and alerts"])

_reader = Depends(get_current_user)
_ingestor = Depends(require_roles("analyst", "admin"))


@router.post("/events", status_code=status.HTTP_201_CREATED)
def ingest_event(
    payload: EventIn,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _ingestor,
) -> dict:
    return service.ingest_event(
        payload.model_dump(exclude_none=True),
        actor=user.username,
        actor_role=user.role,
        request_id=get_request_id(request),
    )


@router.post("/events/batch", status_code=status.HTTP_201_CREATED)
def ingest_events_batch(
    payload: EventBatch,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _ingestor,
) -> dict:
    return service.ingest_batch(
        [item.model_dump(exclude_none=True) for item in payload.events],
        actor=user.username,
        actor_role=user.role,
        request_id=get_request_id(request),
    )


@router.get("/events")
def list_events(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: str | None = None,
    severity: str | None = None,
    source_ip: str | None = None,
    incident_id: str | None = None,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.list_events(
        limit=limit, offset=offset, event_type=event_type, severity=severity,
        source_ip=source_ip, incident_id=incident_id,
    )
    return {"items": items, "count": len(items), "limit": limit, "offset": offset}


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
def ingest_alert(
    payload: EventIn,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _ingestor,
) -> dict:
    return service.ingest_alert(
        payload.model_dump(exclude_none=True),
        actor=user.username,
        actor_role=user.role,
        request_id=get_request_id(request),
    )


@router.get("/alerts")
def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    incident_id: str | None = None,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.list_alerts(limit=limit, offset=offset, severity=severity, incident_id=incident_id)
    return {"items": items, "count": len(items), "limit": limit, "offset": offset}
