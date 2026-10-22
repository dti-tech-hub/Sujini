"""Evaluation helpers, label provenance, and scenario-construction tests."""
from __future__ import annotations

import pytest

from src.evaluation.datasets import ATTACK_CATEGORIES, BENIGN, generate_labeled_dataset, generate_scenarios
from src.evaluation.metrics import (
    binary_detection_metrics, classification_metrics, latency_summary,
    mcnemar_exact, mitre_metrics, proportion, wilson_interval,
)

pytestmark = pytest.mark.unit


def test_synthetic_dataset_labels_are_separate_from_provenance():
    records = generate_labeled_dataset(n_samples=80, seed=7)
    assert len(records) == 80
    assert all(record["dataset_label"] == "synthetic_demo_data" for record in records)
    assert all("class_label" in record for record in records)
    assert {record["class_label"] for record in records} <= {BENIGN, *ATTACK_CATEGORIES}
    assert "dataset_label" not in {BENIGN, *ATTACK_CATEGORIES}


def test_scenario_generation_has_expected_counts_and_mitre_ground_truth():
    scenarios = generate_scenarios(per_class=3, seed=11)
    assert len(scenarios) == 24
    attacks = [item for item in scenarios if item.is_attack]
    benign = [item for item in scenarios if not item.is_attack]
    assert len(attacks) == 21
    assert len(benign) == 3
    compromise = next(item for item in scenarios if item.category == "account_compromise")
    assert compromise.expected_mitre == ["T1110", "T1078", "T1190"]
    assert any("/admin/users" in (event.get("destination") or "") for event in compromise.events)


def test_binary_detection_metrics_hand_computed():
    rows = [
        {"is_attack": True, "predicted": True},
        {"is_attack": True, "predicted": False},
        {"is_attack": False, "predicted": True},
        {"is_attack": False, "predicted": False},
    ]
    result = binary_detection_metrics(rows, "predicted")
    assert result["true_positive"] == 1
    assert result["false_positive"] == 1
    assert result["true_negative"] == 1
    assert result["false_negative"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["accuracy"] == 0.5


def test_classification_metrics_macro_and_confusion():
    rows = [
        {"expected_category": "a", "predicted": "a"},
        {"expected_category": "a", "predicted": "b"},
        {"expected_category": "b", "predicted": "b"},
    ]
    result = classification_metrics(rows, "predicted", ["a", "b"])
    assert result["accuracy"] == round(2 / 3, 4)
    assert result["per_class"]["a"]["recall"] == 0.5
    assert result["per_class"]["b"]["precision"] == 0.5
    assert result["confusion_matrix"]["a"]["b"] == 1


def test_mcnemar_exact_hand_computed():
    result = mcnemar_exact([True, True, False, False], [True, False, True, True])
    assert result["baseline_only_correct"] == 1
    assert result["agentic_only_correct"] == 2
    assert result["discordant_pairs"] == 3
    assert result["exact_two_sided_p"] == 1.0


def test_wilson_interval_and_proportion():
    interval = wilson_interval(8, 10)
    assert 0.0 <= interval["low"] < 0.8 < interval["high"] <= 1.0
    payload = proportion(8, 10)
    assert payload["rate"] == 0.8
    assert payload["ci95"] == interval
    empty = wilson_interval(0, 0)
    assert empty == {"low": None, "high": None}


def test_mitre_metrics_counts_micro_and_exact():
    rows = [
        {"expected_mitre": ["T1", "T2"], "predicted_mitre": ["T1"]},
        {"expected_mitre": ["T3"], "predicted_mitre": ["T3", "T4"]},
        {"expected_mitre": [], "predicted_mitre": ["T5"]},
    ]
    result = mitre_metrics(rows)
    assert result["eligible_scenarios"] == 2
    assert result["excluded_scenarios"] == 1
    assert result["true_positive"] == 2
    assert result["false_negative"] == 1
    assert result["false_positive"] == 1
    assert result["exact_set_match_rate"] == 0.0


def test_latency_summary_percentiles():
    result = latency_summary([10.0, 20.0, 30.0, 40.0, 50.0])
    assert result["samples"] == 5
    assert result["mean"] == 30.0
    assert result["median"] == 30.0
    assert result["p95"] == 50.0
    assert latency_summary([])["samples"] == 0
