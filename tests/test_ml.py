"""Runtime ML artifact tests: feature schema, loading, and honest metadata."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.detection.anomaly_detector import AnomalyDetector
from src.evaluation.datasets import generate_labeled_dataset
from src.ml.predict import AnomalyPredictor
from src.ml.preprocessing import FEATURE_NAMES, features_from_event
from src.ml.train import load_artifact
from src.utils.config import MODELS_DIR, RESULTS_DIR

pytestmark = pytest.mark.unit

ARTIFACT = MODELS_DIR / "anomaly_iforest.joblib"
ML_METRICS = RESULTS_DIR / "metrics" / "ml_metrics.json"


def test_feature_vector_shape_and_determinism():
    record = {
        "source_ip": "203.0.113.5",
        "destination": "/products?q=1%20UNION%20SELECT%20password%20FROM%20users",
        "method": "GET",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 NormalBrowser/1.0",
        "event_type": "http_request",
        "message": "request completed",
        "username": "alice",
    }
    first = features_from_event(record)
    second = features_from_event(record)
    assert len(first) == len(FEATURE_NAMES)
    assert first == second


@pytest.mark.skipif(not ARTIFACT.exists(), reason="model artifact not trained")
def test_artifact_metadata_is_labelled_synthetic_and_not_production():
    artifact = load_artifact(ARTIFACT)
    assert artifact["dataset"] == "synthetic_demo_data"
    assert artifact["features"] == FEATURE_NAMES
    assert artifact["threshold_selection"] == "labelled_validation_f1"
    assert "Not a production model" in artifact["note"]


@pytest.mark.skipif(not ARTIFACT.exists(), reason="model artifact not trained")
def test_predictor_returns_measured_scores_for_known_events():
    predictor = AnomalyPredictor(ARTIFACT)
    records = generate_labeled_dataset(n_samples=20, seed=3)
    for record in records[:5]:
        result = predictor.score(record)
        assert set(result) >= {
            "is_anomaly", "decision_score", "anomaly_score", "threshold", "dataset"
        }
        assert result["dataset"] == "synthetic_demo_data"
        assert isinstance(result["is_anomaly"], bool)


@pytest.mark.skipif(not ARTIFACT.exists(), reason="model artifact not trained")
def test_detector_ignores_artifact_with_wrong_feature_schema(tmp_path):
    import joblib

    bad = tmp_path / "bad.joblib"
    joblib.dump({"model": object(), "features": ["wrong"]}, bad)
    detector = AnomalyDetector(bad)
    assert detector.available is False


@pytest.mark.skipif(not ML_METRICS.exists(), reason="ML metrics not generated")
def test_ml_metrics_document_synthetic_evaluation():
    payload = json.loads(ML_METRICS.read_text(encoding="utf-8"))
    assert payload["dataset"]["data_label"] == "synthetic_demo_data"
    assert payload["dataset"]["n_samples"] > 0
    assert "random_forest" in payload["models"]
    assert "isolation_forest" in payload["models"]
    rf = payload["models"]["random_forest"]
    assert 0.0 <= rf["macro_f1"] <= 1.0
    isolation = payload["models"]["isolation_forest"]
    assert "validation split" in isolation["threshold_selection"]
    assert 0.0 <= isolation["validation_f1"] <= 1.0
