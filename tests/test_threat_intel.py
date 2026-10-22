"""Threat-intelligence mode-labelling and local-scope tests."""
from __future__ import annotations

import pytest

from src.threat_intel.mock_provider import MockProvider
from src.threat_intel.service import ThreatIntelService, threat_intel_status

pytestmark = pytest.mark.unit


def test_documentation_ip_uses_labelled_demo_mock():
    service = ThreatIntelService()
    result = service.lookup_ip("198.51.100.77")
    assert result["mode"] == "DEMO_MOCK"
    assert result["is_mock"] is True
    assert result["malicious"] is True
    assert result["details"]["mock_disclaimer"]


def test_private_ip_is_not_sent_to_external_providers():
    service = ThreatIntelService()
    result = service.lookup_ip("10.0.0.5")
    assert result["mode"] == "NO_EXTERNAL_LOOKUP"
    assert result["is_mock"] is False
    assert result["verdict"] == "private"
    assert result["details"]["indicators"] == ["10.0.0.5"]


def test_invalid_indicator_is_handled_without_network_call():
    service = ThreatIntelService()
    result = service.lookup_ip("not-an-ip")
    assert result["mode"] == "INVALID"
    assert result["verdict"] == "error"
    assert result["is_mock"] is False


def test_mock_values_are_deterministic_for_same_indicator():
    provider = MockProvider()
    first = provider.lookup_ip("203.0.113.25")
    second = provider.lookup_ip("203.0.113.25")
    assert first.score == second.score
    assert first.verdict == second.verdict
    assert first.details["deterministic_bucket"] == second.details["deterministic_bucket"]


def test_status_never_claims_live_without_credentials():
    status = threat_intel_status()
    assert status["mode"] in {"DEMO_MOCK", "LIVE"}
    if not status["live_configured"]:
        assert status["mode"] == "DEMO_MOCK"
        assert status["providers"]["mock"] == "available"
