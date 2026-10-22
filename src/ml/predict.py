"""Inference helpers for the trained Isolation Forest artifact."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from src.ml.preprocessing import features_from_event
from src.ml.train import load_artifact


class AnomalyPredictor:
    def __init__(self, model_path: Path | None = None) -> None:
        self.artifact = load_artifact(model_path)
        self.model = self.artifact["model"]
        self.threshold = float(self.artifact["threshold"])

    def score(self, event: Any) -> dict[str, Any]:
        features = np.asarray([features_from_event(event)], dtype=float)
        decision = float(self.model.decision_function(features)[0])
        prediction = int(self.model.predict(features)[0])
        is_anomaly = prediction == -1 and decision <= self.threshold
        return {
            "is_anomaly": is_anomaly,
            "decision_score": round(decision, 6),
            "anomaly_score": round(-decision, 6),
            "threshold": round(self.threshold, 6),
            "dataset": self.artifact.get("dataset"),
            "trained_at": self.artifact.get("trained_at"),
        }

    def score_many(self, events: list[Any]) -> list[dict[str, Any]]:
        return [self.score(event) for event in events]
