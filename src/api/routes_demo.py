"""Explicit, admin-only synthetic demonstration endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from src.api.deps import get_request_id, get_service
from src.database.models import User
from src.security.authentication import require_roles
from src.services.demo_scenarios import brute_force_compromise_scenario
from src.services.soc_service import SocService

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.post("/scenario")
def run_demo_scenario(
    request: Request,
    auto_investigate: bool = True,
    service: SocService = Depends(get_service),
    user: User = Depends(require_roles("admin")),
) -> dict:
    scenario = brute_force_compromise_scenario()
    batch = service.ingest_batch(
        scenario["events"],
        actor=user.username,
        actor_role=user.role,
        request_id=get_request_id(request),
        source="demo_scenario",
    )
    incident_ids = batch["incidents"]
    investigation = None
    if auto_investigate and incident_ids:
        investigation = service.investigate(
            incident_ids[0], actor=user.username, actor_role=user.role, request_id=get_request_id(request)
        )
    detail = service.get_incident_detail(incident_ids[0]) if incident_ids else None
    return {
        "scenario": scenario["name"],
        "data_label": scenario["data_label"],
        "ground_truth": scenario["ground_truth"],
        "batch": {key: batch[key] for key in ("submitted", "ingested", "duplicates", "alerts_created", "incidents")},
        "investigation": investigation,
        "incident": detail,
    }
