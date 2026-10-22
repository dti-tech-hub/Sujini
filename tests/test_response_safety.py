"""Response-policy safety tests: allowlist, approval, simulation and verification."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.database import repository
from src.response.actions import allowlist, is_allowed_action, simulation_mode
from src.response.executor import ResponseExecutor
from src.services.demo_scenarios import brute_force_compromise_scenario
from src.services.soc_service import SocService
from src.utils.exceptions import ConflictError, PolicyError

pytestmark = pytest.mark.security


def _user(session_factory, role: str):
    session = session_factory()
    try:
        return repository.get_user_by_username(session, f"test_{role}")
    finally:
        session.close()


def _investigate_demo(service: SocService):
    scenario = brute_force_compromise_scenario()
    batch = service.ingest_batch(scenario["events"], enable_ml=False)
    incident_id = batch["incidents"][0]
    result = service.investigate(incident_id, actor="test_admin", actor_role="admin")
    return incident_id, result


def test_allowlist_is_explicit_and_unknown_actions_are_rejected():
    configured = allowlist()
    assert configured == {
        "CREATE_INCIDENT",
        "NOTIFY_ANALYST",
        "SIMULATE_NOTIFY_ADMIN",
        "SIMULATE_BLOCK_IP",
        "SIMULATE_DISABLE_SESSION",
        "SIMULATE_RESET_CREDENTIAL",
        "SIMULATE_QUARANTINE",
    }
    assert is_allowed_action("SIMULATE_BLOCK_IP")
    assert not is_allowed_action("RUN_SHELL")
    assert not is_allowed_action("DELETE_FIREWALL_RULE")


def test_simulation_mode_is_enabled_by_default():
    assert simulation_mode() is True


def test_executor_refuses_when_simulation_mode_is_disabled(monkeypatch, session_factory):
    monkeypatch.setattr("src.response.executor.simulation_mode", lambda: False)
    session = session_factory()
    try:
        executor = ResponseExecutor(session)
        with pytest.raises(PolicyError, match="simulation_mode=true"):
            executor.execute(
                SimpleNamespace(id="INC-UNSAFE", status="APPROVED"),
                actor="test",
                actor_role="admin",
            )
    finally:
        session.close()


def test_high_risk_incident_is_gated_before_execution(service, session_factory, users):
    incident_id, investigation = _investigate_demo(service)
    assert investigation["approval_required"] is True
    assert investigation["status"] == "AWAITING_APPROVAL"
    assert investigation["approval_status"] == "PENDING"
    assert investigation["auto_executed"] is False

    analyst = _user(session_factory, "analyst")
    with pytest.raises(ConflictError):
        service.execute(incident_id, analyst)

    detail = service.get_incident_detail(incident_id)
    assert detail["incident"]["status"] == "AWAITING_APPROVAL"
    assert all(action["status"] != "EXECUTED" for action in detail["response"]["actions"])


def test_approved_plan_executes_only_simulated_allowlisted_actions(service, session_factory, users):
    incident_id, _ = _investigate_demo(service)
    analyst = _user(session_factory, "analyst")
    service.approve(incident_id, analyst, "Reviewed evidence; simulated containment approved.")
    result = service.execute(incident_id, analyst)

    incident = result["incident"]["incident"]
    assert incident["status"] == "VERIFIED"
    assert result["verification"]["verified"] is True
    assert result["execution"]["all_succeeded"] is True
    actions = result["incident"]["response"]["actions"]
    assert actions
    assert all(action["is_simulated"] for action in actions)
    assert all(is_allowed_action(action["action_type"]) for action in actions)
    assert all(
        action["status"] == "EXECUTED"
        for action in actions
        if action["policy_mode"] in {"auto", "approval"}
    )
    assert all(
        action["status"] != "EXECUTED"
        for action in actions
        if action["policy_mode"] == "advisory"
    )
    executed = [action for action in actions if action["status"] == "EXECUTED"]
    assert executed
    assert all(
        action["result"].get("effect") == "No real system was modified."
        for action in executed
    )


def test_partial_approval_is_rejected(service, session_factory, users):
    incident_id, _ = _investigate_demo(service)
    analyst = _user(session_factory, "analyst")
    detail = service.get_incident_detail(incident_id)
    pending = [
        action["id"] for action in detail["response"]["actions"]
        if action["requires_approval"] and action["status"] == "PENDING_APPROVAL"
    ]
    assert len(pending) > 1
    with pytest.raises(Exception, match="partial approval"):
        service.approve(incident_id, analyst, "partial", action_ids=pending[:1])


def test_rejection_closes_incident_without_execution(service, session_factory, users):
    incident_id, _ = _investigate_demo(service)
    analyst = _user(session_factory, "analyst")
    service.reject(incident_id, analyst, "Not enough evidence for containment.")
    detail = service.get_incident_detail(incident_id)
    assert detail["incident"]["status"] == "REJECTED"
    assert detail["incident"]["approval_status"] == "REJECTED"
    assert all(action["status"] != "EXECUTED" for action in detail["response"]["actions"])
    assert any(entry["action"] == "RESPONSE_REJECTED" for entry in detail["audit"])
