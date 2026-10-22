"""Response, approval, and execution routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from src.api.deps import get_request_id, get_service
from src.api.schemas import ApprovalRequest, RejectionRequest
from src.database.models import User
from src.security.authentication import get_current_user, require_roles
from src.services.soc_service import SocService

router = APIRouter(prefix="/api/incidents", tags=["response"])
_reader = Depends(get_current_user)
_approver = Depends(require_roles("analyst", "admin"))


@router.get("/{incident_id}/response")
def response_plan(
    incident_id: str,
    service: SocService = Depends(get_service),
    user: User = _reader,
) -> dict:
    return service.response(incident_id)


@router.post("/{incident_id}/approve")
def approve(
    incident_id: str,
    payload: ApprovalRequest,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _approver,
) -> dict:
    return service.approve(
        incident_id, user, payload.reason, action_ids=payload.action_ids,
        request_id=get_request_id(request),
    )


@router.post("/{incident_id}/reject")
def reject(
    incident_id: str,
    payload: RejectionRequest,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _approver,
) -> dict:
    return service.reject(
        incident_id, user, payload.reason, action_ids=payload.action_ids,
        request_id=get_request_id(request),
    )


@router.post("/{incident_id}/execute")
def execute(
    incident_id: str,
    request: Request,
    service: SocService = Depends(get_service),
    user: User = _approver,
) -> dict:
    return service.execute(incident_id, user, request_id=get_request_id(request))
