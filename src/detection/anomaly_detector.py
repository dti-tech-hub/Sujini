"""Optional machine-learning anomaly signal for the detection engine."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from src.ml.preprocessing import FEATURE_NAMES, features_from_event
from src.utils.config import MODELS_DIR, get_config
from src.utils.logging import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    """Loads a trained Isolation Forest if one exists.

    When no model artifact is present the detector reports `available=False`
    and produces no alert. It never invents anomaly scores.
    """

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or (MODELS_DIR / "anomaly_iforest.joblib")
        self.model = None
        self.metadata: dict[str, Any] = {}
        self.available = False
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            return
        try:
            artifact = joblib.load(self.model_path)
            if isinstance(artifact, dict) and "model" in artifact:
                if artifact.get("features") != FEATURE_NAMES:
                    logger.warning("ML model feature schema mismatch; model ignored")
                    return
                self.model = artifact["model"]
                self.metadata = {k: v for k, v in artifact.items() if k != "model"}
            else:
                self.model = artifact
                self.metadata = {"dataset": "unknown"}
            self.available = True
        except Exception as exc:  # corrupt model must never crash ingestion
            logger.warning("Failed to load ML model: %s", exc)
            self.model = None
            self.available = False

    @property
    def threshold(self) -> float:
        cfg = get_config().get("detection", {})
        return float(self.metadata.get("threshold", cfg.get("ml_anomaly_threshold", -0.05)))

    def score(self, event: Any) -> dict[str, Any] | None:
        if not self.available or self.model is None:
            return None
        try:
            features = np.asarray([features_from_event(event)], dtype=float)
            decision = float(self.model.decision_function(features)[0])
            prediction = int(self.model.predict(features)[0])
            is_anomaly = prediction == -1 and decision <= self.threshold
            return {
                "available": True,
                "is_anomaly": is_anomaly,
                "decision_score": round(decision, 4),
                "anomaly_score": round(float(-decision), 4),
                "threshold": self.threshold,
                "model_mode": self.metadata.get("dataset", "unknown"),
                "trained_at": self.metadata.get("trained_at"),
            }
        except Exception as exc:
            logger.warning("ML scoring failed: %s", exc)
            return {"available": False, "error": str(exc)}
