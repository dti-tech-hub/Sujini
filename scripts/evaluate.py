"""Run the complete measured evaluation: ML, scenarios, figures and report."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation.benchmark import run_scenario_benchmark  # noqa: E402
from src.evaluation.report import write_report  # noqa: E402
from src.ml.evaluate import evaluate_saved_model  # noqa: E402
from src.ml.train import train_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible project evaluation.")
    parser.add_argument("--samples", type=int, default=4200, help="Synthetic ML events.")
    parser.add_argument("--per-class", type=int, default=10, help="Scenarios per category.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-ml", action="store_true")
    parser.add_argument("--skip-scenarios", action="store_true")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temporary scenario databases.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    ml_metrics = None
    saved_model = None
    scenario_metrics = None
    if not args.skip_ml:
        print("Training ML models on synthetic_demo_data ...", flush=True)
        ml_metrics = train_all(n_samples=args.samples, seed=args.seed)
        saved_model = evaluate_saved_model(n_samples=args.samples, seed=args.seed)
    if not args.skip_scenarios:
        print(f"Running {args.per_class} scenarios per category ...", flush=True)
        scenario_metrics = run_scenario_benchmark(
            per_class=args.per_class,
            seed=args.seed,
            keep_temp=args.keep_temp,
            verbose=not args.quiet,
        )
    report_path = write_report(ml=ml_metrics, scenario=scenario_metrics)

    headline: dict = {
        "report": str(report_path),
        "data_label": "synthetic_demo_data",
    }
    if ml_metrics:
        headline["ml"] = {
            "random_forest_accuracy": ml_metrics["models"]["random_forest"]["accuracy"],
            "random_forest_macro_f1": ml_metrics["models"]["random_forest"]["macro_f1"],
            "isolation_forest_attack_f1": ml_metrics["models"]["isolation_forest"]["binary_attack"]["f1"],
            "saved_model": (saved_model or {}).get("metrics"),
        }
    if scenario_metrics:
        headline["scenario"] = {
            "detection": scenario_metrics["detection"]["agentic"],
            "classification": {
                "baseline_accuracy": scenario_metrics["classification"]["baseline"]["accuracy"],
                "agentic_accuracy": scenario_metrics["classification"]["agentic"]["accuracy"],
                "mcnemar_p": scenario_metrics["classification"]["paired_comparison"]["exact_two_sided_p"],
            },
            "mitre_micro_f1": scenario_metrics["mitre"]["micro_f1"],
            "approval_gate_accuracy": scenario_metrics["response"]["approval_gate_accuracy"],
            "verification_rate": scenario_metrics["response"]["verification_rate"],
            "audit_chain_valid_rate": scenario_metrics["response"]["audit_chain_valid_rate"],
            "latency_ms": scenario_metrics["latency"],
        }
    print(json.dumps(headline, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
