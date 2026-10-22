"""Shared pytest fixtures: isolated SQLite databases, seed users, and API client."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import create_app
from src.database import repository
from src.database.connection import create_database
from src.security.passwords import hash_password
from src.services.soc_service import SocService


def sqlite_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine, factory = create_database(sqlite_url(tmp_path / "unit.db"))
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture()
def service(session_factory) -> SocService:
    return SocService(session_factory)


@pytest.fixture()
def users(session_factory) -> dict[str, dict[str, str]]:
    credentials = {
        "viewer": "viewer-password-123",
        "analyst": "analyst-password-123",
        "admin": "admin-password-123",
    }
    session = session_factory()
    try:
        for role, password in credentials.items():
            repository.create_user(session, f"test_{role}", hash_password(password), role)
        session.commit()
    finally:
        session.close()
    return {
        role: {"username": f"test_{role}", "password": password}
        for role, password in credentials.items()
    }


@pytest.fixture()
def api_client(tmp_path: Path, users):
    app = create_app(sqlite_url(tmp_path / "api.db"), rate_limit_enabled=False)
    # The API owns a separate database from the unit-test `session_factory`
    # fixture, so the same credentials must be seeded into it explicitly.
    session = app.state.session_factory()
    try:
        for role, credentials in users.items():
            repository.create_user(
                session,
                credentials["username"],
                hash_password(credentials["password"]),
                role,
            )
        session.commit()
    finally:
        session.close()
    with TestClient(app) as client:
        yield client, app
    app.state.engine.dispose()


def login(client: TestClient, credentials: dict[str, str]) -> str:
    response = client.post(
        "/auth/login",
        json={"username": credentials["username"], "password": credentials["password"]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
