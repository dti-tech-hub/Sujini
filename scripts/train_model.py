"""Train the supervised baselines and the runtime Isolation Forest."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ml.train import train_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Train ML models on labelled synthetic events.")
    parser.add_argument("--samples", type=int, default=4200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.30)
    args = parser.parse_args()
    metrics = train_all(n_samples=args.samples, seed=args.seed, test_size=args.test_size)
    forest = metrics["models"]["random_forest"]
    isolation = metrics["models"]["isolation_forest"]
    print(json.dumps({
        "data_label": "synthetic_demo_data",
        "dataset_size": metrics["dataset"]["n_samples"],
        "random_forest_accuracy": forest["accuracy"],
        "random_forest_macro_f1": forest["macro_f1"],
        "random_forest_attack_f1": forest["binary_attack"]["f1"],
        "isolation_forest_attack_f1": isolation["binary_attack"]["f1"],
        "isolation_forest_threshold": isolation["threshold"],
        "metrics_path": metrics["metrics_path"],
        "artifact": metrics["artifact"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
