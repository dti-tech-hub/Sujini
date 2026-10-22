"""Investigation and evidence routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from src.api.deps import get_request_id, get_service
from src.database.models import User
from src.security.authentication import get_current_user, require_roles
from src.services.soc_service import SocService

router = APIRouter(prefix="/api/incidents", tags=["investigation"])
_reader = Depends(get_current_user)
_investigator = Depends(require_roles("analyst", "admin"))


@router.post("/{incident_id}/investigate")
def investigate(
    incident_id: str,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _investigator,
) -> dict:
    return service.investigate(
        incident_id, actor=user.username, actor_role=user.role, request_id=get_request_id(request)
    )


@router.get("/{incident_id}/timeline")
def timeline(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.timeline(incident_id)
    return {"incident_id": incident_id, "items": items, "count": len(items)}


@router.get("/{incident_id}/evidence")
def evidence(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.evidence(incident_id)
    return {"incident_id": incident_id, "items": items, "count": len(items)}


@router.get("/{incident_id}/threat-intel")
def threat_intel(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.threat_intel(incident_id)
    return {"incident_id": incident_id, "items": items, "count": len(items)}


@router.get("/{incident_id}/mitre")
def mitre(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    items = service.mitre(incident_id)
    return {"incident_id": incident_id, "items": items, "count": len(items)}


@router.get("/{incident_id}/risk")
def risk(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    item = service.risk(incident_id)
    return {"incident_id": incident_id, "risk": item}
