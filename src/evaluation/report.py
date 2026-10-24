"""Generate the measured evaluation report and headline summary JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.evaluation.environment import environment_info
from src.utils.config import RESULTS_DIR


def _pct(value: Any) -> str:
    if value is None:
        return "NOT MEASURED"
    return f"{float(value) * 100:.2f}%"


def _num(value: Any, digits: int = 2) -> str:
    if value is None:
        return "NOT MEASURED"
    return f"{float(value):.{digits}f}"


def _int(value: Any) -> str:
    if value is None:
        return "NOT MEASURED"
    return str(int(value))


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def build_summary(ml: dict[str, Any] | None, scenario: dict[str, Any] | None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "environment": environment_info(),
        "data_provenance": "synthetic_demo_data",
        "ml": None,
        "scenario": None,
    }
    if ml:
        forest = ml["models"]["random_forest"]
        isolation = ml["models"]["isolation_forest"]
        summary["ml"] = {
            "dataset": ml["dataset"],
            "random_forest": {
                "accuracy": forest["accuracy"],
                "macro_f1": forest["macro_f1"],
                "weighted_f1": forest["weighted_f1"],
                "binary_attack": forest["binary_attack"],
            },
            "logistic_regression": {
                "accuracy": ml["models"]["logistic_regression"]["accuracy"],
                "macro_f1": ml["models"]["logistic_regression"]["macro_f1"],
                "binary_attack": ml["models"]["logistic_regression"]["binary_attack"],
            },
            "isolation_forest": {
                "binary_attack": isolation["binary_attack"],
                "threshold": isolation["threshold"],
                "validation_false_positive_rate": isolation["validation_false_positive_rate"],
                "threshold_selection": isolation["threshold_selection"],
            },
        }
    if scenario:
        summary["scenario"] = {
            "method": scenario["method"],
            "detection": scenario["detection"],
            "classification": {
                "baseline": {
                    "accuracy": scenario["classification"]["baseline"]["accuracy"],
                    "macro_f1": scenario["classification"]["baseline"]["macro_f1"],
                    "correct": scenario["classification"]["baseline"]["correct"],
                    "total": scenario["classification"]["baseline"]["total"],
                },
                "agentic": {
                    "accuracy": scenario["classification"]["agentic"]["accuracy"],
                    "macro_f1": scenario["classification"]["agentic"]["macro_f1"],
                    "correct": scenario["classification"]["agentic"]["correct"],
                    "total": scenario["classification"]["agentic"]["total"],
                },
                "paired_comparison": scenario["classification"]["paired_comparison"],
            },
            "incident_correlation": scenario["incident_correlation"],
            "mitre": scenario["mitre"],
            "risk": scenario["risk"],
            "response": scenario["response"],
            "latency": scenario["latency"],
            "modes": scenario["modes"],
            "totals": scenario["totals"],
        }
    return summary


def write_report(
    *,
    ml: dict[str, Any] | None = None,
    scenario: dict[str, Any] | None = None,
    results_dir: Path | None = None,
) -> Path:
    results_dir = results_dir or RESULTS_DIR
    report_dir = results_dir / "reports"
    metrics_dir = results_dir / "metrics"
    figure_dir = results_dir / "figures"
    report_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)

    summary = build_summary(ml, scenario)
    (metrics_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append("# Evaluation report: AI-agent incident response system")
    lines.append("")
    lines.append(
        f"Generated: **{summary['generated_at']}**  \n"
        f"Data provenance: **`synthetic_demo_data`**  \n"
        f"Environment: Python {summary['environment']['python']} on "
        f"{summary['environment']['platform']}  \n"
        f"Git commit: `{summary['environment'].get('git_commit') or 'not available'}`"
    )
    lines.append("")
    lines.append("> All values in this report were produced by the commands in the "
                 "Reproduction section. Synthetic data and mock threat intelligence are "
                 "labelled as such. No production or real-network performance is claimed.")
    lines.append("")

    lines.append("## 1. Headline results")
    lines.append("")
    if ml:
        forest = ml["models"]["random_forest"]
        isolation = ml["models"]["isolation_forest"]
        ml_rows = [
            ["Random Forest (supervised, 8 classes)", _pct(forest["accuracy"]), _pct(forest["macro_f1"]),
             _pct(forest["binary_attack"]["f1"]), _pct(forest["binary_attack"]["roc_auc"])],
            ["Logistic Regression (supervised, 8 classes)",
             _pct(ml["models"]["logistic_regression"]["accuracy"]),
             _pct(ml["models"]["logistic_regression"]["macro_f1"]),
             _pct(ml["models"]["logistic_regression"]["binary_attack"]["f1"]),
             _pct(ml["models"]["logistic_regression"]["binary_attack"]["roc_auc"])],
            ["Isolation Forest (unsupervised anomaly signal)",
             "n/a (binary)", "n/a (binary)", _pct(isolation["binary_attack"]["f1"]),
             _pct(isolation["binary_attack"]["roc_auc"])],
        ]
        lines.append("### 1.1 Machine learning on held-out synthetic events")
        lines.append("")
        lines.append(_table(
            ["Model", "Accuracy", "Macro F1", "Attack F1", "Attack ROC-AUC"], ml_rows
        ))
        lines.append("")
        lines.append(
            f"Dataset: {ml['dataset']['n_samples']} synthetic HTTP events "
            f"({ml['dataset']['train_size']} train / {ml['dataset']['test_size']} test), "
            f"{ml['dataset']['n_features']} features, seed {ml['dataset']['seed']}. "
            f"Isolation Forest was fitted only on benign training traffic; its operating "
            f"threshold ({isolation['threshold']:.6f}) was selected on a labelled validation "
            f"split (validation FPR {_pct(isolation['validation_false_positive_rate'])}). "
            "The test split was not used for threshold selection."
        )
        lines.append("")
    else:
        lines.append("ML evaluation: **NOT MEASURED** (run `python scripts/train_model.py`).")
        lines.append("")

    if scenario:
        detection = scenario["detection"]["agentic"]
        classification = scenario["classification"]
        response = scenario["response"]
        lines.append("### 1.2 Agentic pipeline on independent synthetic scenarios")
        lines.append("")
        lines.append(_table(
            ["Measure", "Baseline", "Agentic pipeline"],
            [
                ["Scenario detection precision", _pct(scenario["detection"]["baseline"]["precision"]),
                 _pct(detection["precision"])],
                ["Scenario detection recall", _pct(scenario["detection"]["baseline"]["recall"]),
                 _pct(detection["recall"])],
                ["Incident classification accuracy", _pct(classification["baseline"]["accuracy"]),
                 _pct(classification["agentic"]["accuracy"])],
                ["Incident classification macro F1", _pct(classification["baseline"]["macro_f1"]),
                 _pct(classification["agentic"]["macro_f1"])],
            ],
        ))
        lines.append("")
        lines.append(
            f"Scenario set: {scenario['method']['scenario_count']} scenarios "
            f"({scenario['method']['attack_count']} attacks, {scenario['method']['benign_count']} benign), "
            f"{scenario['method']['per_class']} per category, seed {scenario['method']['seed']}. "
            f"Paired McNemar exact two-sided p = "
            f"**{classification['paired_comparison']['exact_two_sided_p']:.6f}** "
            f"(discordant pairs: {classification['paired_comparison']['discordant_pairs']})."
        )
        lines.append("")
        lines.append(_table(
            ["Policy / safety measure", "Result"],
            [
                ["Incident correlation accuracy", _pct(scenario["incident_correlation"]["rate"])],
                ["MITRE micro F1 (eligible categories)", _pct(scenario["mitre"]["micro_f1"])],
                ["Approval-gate accuracy", _pct(response["approval_gate_accuracy"])],
                ["Expected key-action coverage", _pct(response["key_action_coverage"])],
                ["Response allowlist compliance", _pct(response["allowlist_compliance"])],
                ["Simulation-only compliance", _pct(response["simulation_compliance"])],
                ["Execution verification rate", _pct(response["verification_rate"])],
                ["Audit-chain validity across scenarios", _pct(response["audit_chain_valid_rate"])],
                ["Unauthorized executions", _int(response["unauthorized_executions"])],
            ],
        ))
        lines.append("")

    # -- ML details -------------------------------------------------------
    if ml:
        forest = ml["models"]["random_forest"]
        lines.append("## 2. Machine-learning evaluation detail")
        lines.append("")
        lines.append(f"Random Forest confusion matrix (rows = actual, columns = predicted), "
                     f"test n = {ml['dataset']['test_size']}:")
        lines.append("")
        labels = ml["dataset"]["labels"]
        matrix = forest["confusion_matrix"]
        lines.append(_table(
            ["actual \\ predicted", *labels],
            [[label, *[str(value) for value in row]] for label, row in zip(labels, matrix)],
        ))
        lines.append("")
        lines.append("Per-class Random Forest metrics:")
        lines.append("")
        lines.append(_table(
            ["Class", "Precision", "Recall", "F1", "Support"],
            [[label,
              _pct(forest["per_class"][label]["precision"]),
              _pct(forest["per_class"][label]["recall"]),
              _pct(forest["per_class"][label]["f1"]),
              _int(forest["per_class"][label]["support"])]
             for label in labels],
        ))
        lines.append("")
        lines.append("Top Random Forest feature importances (measured, impurity-based):")
        import csv
        importance_path = metrics_dir / "ml_feature_importance.csv"
        if importance_path.exists():
            with importance_path.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))[:8]
            lines.append("")
            lines.append(_table(
                ["Feature", "Importance"],
                [[row["feature"], _num(row["importance"], 4)] for row in rows],
            ))
        lines.append("")
        lines.append(
            f"Isolation Forest operating point: threshold = {ml['models']['isolation_forest']['threshold']:.6f}; "
            f"test attack precision {_pct(ml['models']['isolation_forest']['binary_attack']['precision'])}, "
            f"recall {_pct(ml['models']['isolation_forest']['binary_attack']['recall'])}, "
            f"F1 {_pct(ml['models']['isolation_forest']['binary_attack']['f1'])}, "
            f"ROC-AUC {_pct(ml['models']['isolation_forest']['binary_attack']['roc_auc'])}. "
            "The anomaly model is an additive signal; deterministic rules remain authoritative."
        )
        lines.append("")

    # -- Scenario details -------------------------------------------------
    if scenario:
        lines.append("## 3. Scenario detection and classification detail")
        lines.append("")
        lines.append(_table(
            ["Scenario category", "Detected", "Rate", "Baseline category", "Agentic category"],
            [[category,
              f"{values['detected']}/{values['total']}",
              _pct(values["rate"]),
              _baseline_category_for(scenario, category),
              _agentic_category_for(scenario, category)]
             for category, values in scenario["detection"]["by_category"].items()],
        ))
        lines.append("")
        lines.append("Per-class classification F1:")
        lines.append("")
        lines.append(_table(
            ["Class", "Support", "Baseline F1", "Agentic F1"],
            [[label,
              _int(scenario["classification"]["baseline"]["per_class"][label]["support"]),
              _pct(scenario["classification"]["baseline"]["per_class"][label]["f1"]),
              _pct(scenario["classification"]["agentic"]["per_class"][label]["f1"])]
             for label in scenario["classification"]["labels"] if label != "benign_or_unknown"],
        ))
        lines.append("")
        lines.append(
            "The baseline is intentionally a rule-only view: it reports the category of the "
            "earliest alert. It therefore leaves an account-compromise scenario labelled as "
            "brute force when the failure threshold fires before the successful login. The "
            "agentic pipeline re-triages the same alerts after evidence correlation, threat "
            "intelligence, MITRE mapping and risk scoring."
        )
        lines.append("")

        lines.append("## 4. Risk scoring (project-defined model)")
        lines.append("")
        risk = scenario["risk"]
        lines.append(
            f"Measured risk scores: n = {risk['samples']}, mean = {_num(risk['mean'])}, "
            f"min = {_num(risk['min'])}, max = {_num(risk['max'])}. Level counts: "
            f"{', '.join(f'{key}={value}' for key, value in sorted(risk['levels'].items())) or 'none'}."
        )
        lines.append("")
        lines.append(_table(
            ["Category", "n", "Mean", "Min", "Max", "Levels"],
            [[category, _int(values["n"]), _num(values["mean"]), _num(values["min"]),
              _num(values["max"]), ", ".join(f"{key}={value}" for key, value in sorted(values["levels"].items()))]
             for category, values in risk["by_category"].items()],
        ))
        lines.append("")
        lines.append(
            "The score is a transparent weighted sum of seven normalized factors. "
            "Weights and thresholds are project parameters, not universal standards. "
            "No ground-truth risk labels exist for these synthetic scenarios, so no "
            "risk-accuracy claim is made."
        )
        lines.append("")

        lines.append("## 5. Response, approval and audit")
        lines.append("")
        lines.append(_table(
            ["Measure", "Value"],
            [
                ["Attack scenarios investigated", _int(response["incidents_investigated"])],
                ["Approval-gated scenarios", _int(response["approval_required_count"])],
                ["Auto-executed (MEDIUM/LOW safe actions)", _int(response["auto_executed_count"])],
                ["Approval-gate correct", f"{response['approval_gate_correct']}/{response['approval_gate_total']}"],
                ["Expected key action present", f"{response['key_action_correct']}/{response['key_action_total']}"],
                ["Executed action records", _int(response["executed_actions"])],
                ["Simulated action records", _int(response["simulated_action_records"])],
                ["Non-simulated action records", _int(response["non_simulated_action_records"])],
                ["Unauthorized executions", _int(response["unauthorized_executions"])],
                ["Verified incidents", f"{response['verified_incidents']}/{response['incidents_investigated']}"],
                ["Audit-chain valid scenarios", f"{response['audit_chain_valid_scenarios']}/{scenario['method']['scenario_count']}"],
            ],
        ))
        lines.append("")
        lines.append(
            "All containment, remediation and notification actions are simulated. "
            "The executor refuses `simulation_mode=false`; LLM text cannot select or execute "
            "an action. HIGH and CRITICAL incidents require an analyst/admin approval before "
            "execution."
        )
        lines.append("")

        lines.append("## 6. Latency")
        lines.append("")
        lines.append(_table(
            ["Stage", "n", "Mean (ms)", "Median (ms)", "p95 (ms)", "Max (ms)"],
            [[name.replace("_ms", ""), _int(values["samples"]), _num(values["mean"]),
              _num(values["median"]), _num(values["p95"]), _num(values["max"])]
             for name, values in scenario["latency"].items() if isinstance(values, dict)],
        ))
        lines.append("")
        lines.append(
            "Wall-clock measurements from a local SQLite database on the evaluation host. "
            "They include Python orchestration, database I/O and audit hashing; they are not "
            "a production throughput or SLA claim."
        )
        lines.append("")

    # -- Reproduction -----------------------------------------------------
    lines.append("## 7. Reproduction")
    lines.append("")
    lines.append("```powershell")
    lines.append(".\\\\.venv\\\\Scripts\\\\python.exe -m pytest")
    lines.append(".\\\\.venv\\\\Scripts\\\\python.exe scripts\\\\train_model.py")
    lines.append(".\\\\.venv\\\\Scripts\\\\python.exe scripts\\\\evaluate.py")
    lines.append(".\\\\.venv\\\\Scripts\\\\python.exe scripts\\\\run_demo.py")
    lines.append("```")
    lines.append("")
    lines.append("Artifacts:")
    lines.append("")
    lines.append("- `results/metrics/ml_metrics.json`")
    lines.append("- `results/metrics/scenario_metrics.json`")
    lines.append("- `results/metrics/scenario_results.csv`")
    lines.append("- `results/metrics/summary.json`")
    lines.append("- `results/figures/`")
    lines.append("- `models/anomaly_iforest.joblib`")
    lines.append("")
    lines.append("## 8. Limitations and non-claims")
    lines.append("")
    lines.append("- The scenario and ML datasets are generated, not captured from production traffic.")
    lines.append("- Threat intelligence is deterministic mock data unless live API keys are configured; "
                 "documentation-range IPs are never queried live.")
    lines.append("- The LLM runs in deterministic template mode unless explicitly configured; "
                 "the reported investigation behaviour is therefore reproducible, not an evaluation "
                 "of a hosted language model.")
    lines.append("- MITRE ATT&CK ground truth is project-defined from scenario construction. "
                 "Reputation-only, volume-only and authorization-only scenarios are excluded from "
                 "MITRE accuracy.")
    lines.append("- All response effects are simulated. No firewall, session store, credential, "
                 "workload or network device is changed.")
    lines.append("- Per-class results on a small synthetic scenario set should not be extrapolated "
                 "to real enterprise detection rates.")
    lines.append("")

    report_path = report_dir / "evaluation_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    summary["report_path"] = str(report_path)
    return report_path


def _baseline_category_for(scenario: dict[str, Any], category: str) -> str:
    rows = [row for row in scenario.get("scenarios", []) if row["category"] == category]
    if not rows:
        return "NOT MEASURED"
    values = sorted({row["baseline_category"] for row in rows})
    return ", ".join(values)


def _agentic_category_for(scenario: dict[str, Any], category: str) -> str:
    rows = [row for row in scenario.get("scenarios", []) if row["category"] == category]
    if not rows:
        return "NOT MEASURED"
    values = sorted({row["agentic_category"] for row in rows})
    return ", ".join(values)
