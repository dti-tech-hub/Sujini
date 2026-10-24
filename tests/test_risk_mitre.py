"""Risk-scoring transparency and MITRE mapping tests."""
from __future__ import annotations

import pytest

from src.mitre.mapper import MitreMapper
from src.risk.scorer import RiskScorer, explain_formula

pytestmark = pytest.mark.unit


def test_risk_score_is_bounded_and_weights_are_preserved():
    scorer = RiskScorer()
    result = scorer.score(
        incident_id="INC-TEST",
        severity="CRITICAL",
        confidence=0.95,
        category="account_compromise",
        event_count=25,
        source_ip="198.51.100.20",
        username="admin",
        endpoints=["/admin/audit"],
        threat_intel={"verdict": "malicious", "mode": "DEMO_MOCK", "is_mock": True},
    )
    assert 0.0 <= result.score <= 100.0
    assert result.level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(result.weights) == {
        "severity", "confidence", "asset_criticality", "threat_intel",
        "event_volume", "attack_impact", "recurrence",
    }
    assert abs(sum(result.weights.values()) - 1.0) < 1e-6
    total = sum(item["contribution"] for item in result.factors.values())
    assert abs(total * 100 - result.score) < 0.02
    assert "DEMO/MOCK" in result.explanation


def test_higher_severity_produces_higher_score_when_other_factors_are_equal():
    scorer = RiskScorer()
    common = dict(
        incident_id="INC-TEST", confidence=0.8, category="sql_injection",
        event_count=4, source_ip="10.0.0.5", username="alice",
        endpoints=["/products"], threat_intel={"verdict": "unknown"},
    )
    low = scorer.score(severity="LOW", **common)
    critical = scorer.score(severity="CRITICAL", **common)
    assert critical.score > low.score


def test_risk_score_never_exceeds_one_hundred():
    scorer = RiskScorer()
    result = scorer.score(
        incident_id="INC-TEST", severity="CRITICAL", confidence=1.0,
        category="command_injection", event_count=10_000,
        source_ip="198.51.100.77", username="admin", endpoints=["/admin/users"],
        threat_intel={"verdict": "malicious", "mode": "DEMO_MOCK", "is_mock": True},
    )
    assert result.score <= 100.0


def test_explain_formula_is_explicit_and_not_claimed_as_standard():
    payload = explain_formula()
    assert "weight" in payload["formula"]
    assert "not universal" in payload["note"].lower()


def test_mitre_maps_multi_stage_account_compromise():
    mapper = MitreMapper()
    result = mapper.map(
        classification="account_compromise",
        alert_types=["brute_force", "account_compromise", "sql_injection"],
        confidence=0.95,
        alerts=[],
        event_count=8,
    )
    ids = {item.technique_id for item in result.techniques}
    assert {"T1110", "T1078", "T1190"}.issubset(ids)
    assert all(item.confidence <= 0.98 for item in result.techniques)


def test_command_injection_maps_execution_and_initial_access():
    mapper = MitreMapper()
    result = mapper.map(
        classification="command_injection",
        alert_types=["command_injection"],
        confidence=0.92,
        alerts=[],
        event_count=1,
    )
    ids = {item.technique_id for item in result.techniques}
    assert {"T1059", "T1190"} == ids
    assert all(item.mapping_status == "confirmed" for item in result.techniques)


def test_xss_maps_javascript_subtechnique_as_candidate():
    mapper = MitreMapper()
    result = mapper.map(
        classification="xss",
        alert_types=["xss"],
        confidence=0.86,
        alerts=[],
        event_count=1,
    )
    assert [item.technique_id for item in result.techniques] == ["T1059.007"]
    assert result.techniques[0].mapping_status == "candidate"
    assert result.techniques[0].confidence < 0.75


def test_authorization_failure_alone_has_no_defensible_mapping():
    mapper = MitreMapper()
    result = mapper.map(
        classification="unauthorized_access",
        alert_types=["unauthorized_access"],
        confidence=0.75,
        alerts=[],
        event_count=4,
    )
    assert result.techniques == []


def test_reputation_only_incident_has_no_defensible_mapping():
    mapper = MitreMapper()
    result = mapper.map(
        classification="malicious_ip",
        alert_types=["malicious_ip"],
        confidence=0.7,
        alerts=[],
        event_count=1,
    )
    assert result.techniques == []
    assert "No defensible ATT&CK technique mapping" in result.note


def test_low_confidence_mapping_stays_candidate():
    mapper = MitreMapper()
    result = mapper.map(
        classification="abnormal_traffic",
        alert_types=["abnormal_traffic"],
        confidence=0.4,
        alerts=[],
        event_count=100,
    )
    assert result.techniques
    assert result.techniques[0].technique_id == "T1498"
    assert result.techniques[0].mapping_status == "candidate"
    assert result.techniques[0].confidence < 0.75
