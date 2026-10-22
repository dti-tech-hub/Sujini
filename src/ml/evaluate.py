"""Evaluate the saved runtime anomaly model on the reproducible test split."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from src.evaluation.datasets import BENIGN, generate_labeled_dataset
from src.evaluation.environment import environment_info
from src.ml.preprocessing import features_from_event
from src.ml.train import load_artifact
from src.utils.config import RESULTS_DIR


def evaluate_saved_model(
    *,
    n_samples: int = 4200,
    seed: int = 42,
    test_size: float = 0.30,
    results_dir: Path | None = None,
) -> dict[str, Any]:
    results_dir = results_dir or RESULTS_DIR
    records = generate_labeled_dataset(n_samples=n_samples, seed=seed)
    X = np.asarray([features_from_event(record) for record in records], dtype=float)
    y = np.asarray([record["class_label"] for record in records])
    indices = np.arange(len(records))
    _, test_idx = train_test_split(indices, test_size=test_size, random_state=seed, stratify=y)
    artifact = load_artifact()
    model = artifact["model"]
    threshold = float(artifact["threshold"])
    X_test = X[test_idx]
    y_test = y[test_idx]
    decisions = model.decision_function(X_test)
    predictions = model.predict(X_test)
    flags = (predictions == -1) & (decisions <= threshold)
    true_attack = y_test != BENIGN
    attack_scores = -decisions
    payload = {
        "model_artifact": "models/anomaly_iforest.joblib",
        "dataset": "synthetic_demo_data",
        "test_samples": int(len(test_idx)),
        "threshold": round(threshold, 6),
        "metrics": {
            "accuracy_attack_vs_benign": round(float(accuracy_score(true_attack, flags)), 4),
            "precision": round(float(precision_score(true_attack, flags, zero_division=0)), 4),
            "recall": round(float(recall_score(true_attack, flags, zero_division=0)), 4),
            "f1": round(float(f1_score(true_attack, flags, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(true_attack, attack_scores)), 4),
        },
        "environment": environment_info(),
    }
    metrics_dir = results_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    path = metrics_dir / "saved_model_evaluation.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["path"] = str(path)
    return payload
