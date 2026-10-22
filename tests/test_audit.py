"""Tamper-evident audit-chain tests."""
from __future__ import annotations

import pytest
from sqlalchemy import text

from src.database import repository

pytestmark = pytest.mark.security


def test_audit_chain_is_valid_after_operations(service, session_factory):
    service.ingest_batch(
        [{"source_ip": "10.30.0.1", "event_type": "http_request", "message": "request"}],
        enable_ml=False,
    )
    session = session_factory()
    try:
        valid, count, error = repository.verify_audit_chain(session)
        assert valid is True
        assert count > 0
        assert error is None
    finally:
        session.close()


def test_audit_chain_detects_tampering(service, session_factory):
    service.ingest_batch(
        [{"source_ip": "10.30.0.2", "event_type": "http_request", "message": "request"}],
        enable_ml=False,
    )
    session = session_factory()
    try:
        session.execute(text("UPDATE audit_logs SET actor='tampered_actor' WHERE id = 1"))
        session.commit()
        valid, _, error = repository.verify_audit_chain(session)
        assert valid is False
        assert error
    finally:
        session.close()


def test_audit_action_filter_and_descending_order(service):
    service.ingest_batch(
        [{"source_ip": "10.30.0.3", "event_type": "http_request", "message": "request"}],
        enable_ml=False,
    )
    payload = service.audit_log(limit=10)
    assert payload["chain"]["valid"] is True
    assert payload["entries"]
    timestamps = [entry["timestamp"] for entry in payload["entries"]]
    assert timestamps == sorted(timestamps, reverse=True)
    filtered = service.audit_log(limit=10, action="EVENT_INGESTED")
    assert filtered["entries"]
    assert all(entry["action"] == "EVENT_INGESTED" for entry in filtered["entries"])
