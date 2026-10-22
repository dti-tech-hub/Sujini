"""End-to-end API workflow: ingest -> investigate -> approve -> execute -> verify -> audit."""
from __future__ import annotations

import pytest

from tests.conftest import auth_headers, login

pytestmark = pytest.mark.e2e


def test_full_demo_workflow(api_client, users):
    client, _ = api_client
    admin = auth_headers(login(client, users["admin"]))
    response = client.post("/api/demo/scenario?auto_investigate=true", headers=admin)
    assert response.status_code == 200, response.text
    demo = response.json()
    incident_id = demo["batch"]["incidents"][0]

    detail = client.get(f"/api/incidents/{incident_id}", headers=admin)
    assert detail.status_code == 200
    body = detail.json()
    incident = body["incident"]
    assert incident["id"] == incident_id
    assert incident["attack_category"] == "account_compromise"
    assert incident["approval_required"] is True
    assert incident["approval_status"] == "PENDING"
    assert incident["status"] == "AWAITING_APPROVAL"
    assert body["risk"]["level"] == "CRITICAL"
    assert body["system"]["llm_mode"] in {"DEMO_TEMPLATE", "DISABLED"}
    assert body["system"]["threat_intel_mode"] == "DEMO_MOCK"
    assert body["evidence"]
    assert body["timeline"]
    assert body["agent_runs"]
    assert {item["technique_id"] for item in body["mitre"]} == {"T1110", "T1078", "T1190"}
    assert all(event["dataset_label"] == "synthetic_demo_data" for event in body["events"])
    assert all(item["mode"] == "DEMO_MOCK" and item["is_mock"] for item in body["threat_intelligence"])

    for suffix in ("timeline", "evidence", "threat-intel", "mitre", "risk", "response"):
        endpoint = client.get(f"/api/incidents/{incident_id}/{suffix}", headers=admin)
        assert endpoint.status_code == 200, f"{suffix}: {endpoint.text}"

    execute_before_approval = client.post(f"/api/incidents/{incident_id}/execute", headers=admin)
    assert execute_before_approval.status_code == 409

    approve = client.post(
        f"/api/incidents/{incident_id}/approve",
        headers=admin,
        json={"reason": "End-to-end test approval after reviewing evidence."},
    )
    assert approve.status_code == 200, approve.text
    assert approve.json()["decision"] == "APPROVED"
    assert approve.json()["incident"]["status"] == "APPROVED"

    execute = client.post(f"/api/incidents/{incident_id}/execute", headers=admin)
    assert execute.status_code == 200, execute.text
    result = execute.json()
    assert result["verification"]["verified"] is True
    assert result["execution"]["all_succeeded"] is True
    final = result["incident"]["incident"]
    assert final["status"] == "VERIFIED"
    assert final["verified_at"]
    actions = result["incident"]["response"]["actions"]
    assert all(action["is_simulated"] for action in actions)
    assert all(action["result"].get("effect") == "No real system was modified." for action in actions if action["status"] == "EXECUTED")

    metrics = client.get("/api/metrics", headers=admin).json()
    assert metrics["audit"]["chain_valid"] is True
    assert metrics["totals"]["verified_incidents"] >= 1
    assert metrics["threat_intel_modes"].get("DEMO_MOCK", 0) >= 1
    assert metrics["llm_modes"]
    assert metrics["response_time"]["samples"] >= 1

    audit = client.get(f"/api/audit?incident_id={incident_id}&limit=500", headers=admin).json()
    actions_seen = {entry["action"] for entry in audit["entries"]}
    assert {
        "INVESTIGATION_STARTED",
        "EVIDENCE_COLLECTED",
        "THREAT_INTEL_ENRICHED",
        "MITRE_MAPPED",
        "RISK_CALCULATED",
        "RESPONSE_PLANNED",
        "APPROVAL_REQUESTED",
        "RESPONSE_APPROVED",
        "RESPONSE_EXECUTED",
        "RESPONSE_VERIFIED",
    }.issubset(actions_seen)
    assert audit["chain"]["valid"] is True


def test_rejected_plan_cannot_execute(api_client, users):
    client, _ = api_client
    admin = auth_headers(login(client, users["admin"]))
    demo = client.post("/api/demo/scenario?auto_investigate=true", headers=admin).json()
    incident_id = demo["batch"]["incidents"][0]

    reject = client.post(
        f"/api/incidents/{incident_id}/reject",
        headers=admin,
        json={"reason": "Insufficient evidence for simulated containment."},
    )
    assert reject.status_code == 200, reject.text
    assert reject.json()["decision"] == "REJECTED"
    execute = client.post(f"/api/incidents/{incident_id}/execute", headers=admin)
    assert execute.status_code == 409
    final = client.get(f"/api/incidents/{incident_id}", headers=admin).json()
    assert final["incident"]["status"] == "REJECTED"
    assert all(action["status"] != "EXECUTED" for action in final["response"]["actions"])
