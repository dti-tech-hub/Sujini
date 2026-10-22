"""API authentication, role enforcement, and security-header tests."""
from __future__ import annotations

import pytest

from tests.conftest import auth_headers, login

pytestmark = pytest.mark.integration


def test_health_and_root_are_public(api_client):
    client, _ = api_client
    health = client.get("/health")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["simulation_mode"] is True
    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["simulation_only"] is True


def test_api_requires_authentication(api_client):
    client, _ = api_client
    response = client.get("/api/incidents")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_login_success_and_me(api_client, users):
    client, _ = api_client
    token = login(client, users["analyst"])
    response = client.get("/auth/me", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["username"] == "test_analyst"
    assert response.json()["role"] == "analyst"


def test_login_failure_is_audited_no_secret_leak(api_client, users):
    client, app = api_client
    response = client.post(
        "/auth/login",
        json={"username": users["analyst"]["username"], "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert "access_token" not in response.text
    audit = app.state.soc_service.audit_log(limit=50, action="LOGIN_FAILED")
    assert audit["entries"]
    assert audit["entries"][0]["actor"] == "test_analyst"


def test_invalid_token_is_rejected(api_client):
    client, _ = api_client
    response = client.get("/api/metrics", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_viewer_cannot_ingest_or_approve(api_client, users):
    client, _ = api_client
    token = login(client, users["viewer"])
    headers = auth_headers(token)
    event = client.post(
        "/api/events",
        headers=headers,
        json={"source_ip": "10.40.0.1", "event_type": "http_request", "message": "x"},
    )
    assert event.status_code == 403
    demo = client.post("/api/demo/scenario", headers=headers)
    assert demo.status_code == 403
    assert client.get("/api/incidents", headers=headers).status_code == 200
    assert client.get("/api/metrics", headers=headers).status_code == 200
    assert client.get("/api/audit", headers=headers).status_code == 403


def test_analyst_can_ingest_but_not_run_admin_demo(api_client, users):
    client, _ = api_client
    token = login(client, users["analyst"])
    headers = auth_headers(token)
    event = client.post(
        "/api/events",
        headers=headers,
        json={
            "source_ip": "10.40.0.2",
            "destination": "/products",
            "event_type": "http_request",
            "message": "request completed",
        },
    )
    assert event.status_code == 201
    assert client.post("/api/demo/scenario", headers=headers).status_code == 403
    assert client.get("/api/audit", headers=headers).status_code == 200


def test_admin_demo_and_security_headers(api_client, users):
    client, _ = api_client
    token = login(client, users["admin"])
    response = client.post(
        "/api/demo/scenario?auto_investigate=true",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data_label"] == "synthetic_demo_data"
    assert body["batch"]["incidents"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"]


def test_api_validation_error_shape(api_client, users):
    client, _ = api_client
    token = login(client, users["analyst"])
    response = client.post(
        "/api/incidents",
        headers=auth_headers(token),
        json={"title": "x", "severity": "SUPER_HIGH"},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["detail"] == "Request validation failed"
    assert body["errors"]
