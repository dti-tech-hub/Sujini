"""Reproducible scenario benchmark with a rule-only baseline.

Each scenario is executed in a *fresh temporary SQLite database* for both the
baseline and the full pipeline. This prevents cross-scenario correlation and
keeps every reported outcome independent of scenario ordering.
"""
from __future__ import annotations

import csv
import json
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from src.database import repository
from src.database.connection import create_database
from src.database.models import Alert
from src.evaluation.baseline import baseline_result
from src.evaluation.datasets import Scenario, generate_scenarios
from src.evaluation.environment import environment_info
from src.evaluation.metrics import (
    binary_detection_metrics, classification_metrics, detection_by_category,
    latency_summary, mcnemar_exact, mitre_metrics, proportion, risk_summary,
)
from src.response.actions import is_allowed_action
from src.security.passwords import hash_password, generate_password
from src.services.soc_service import SocService
from src.utils.config import RESULTS_DIR, get_config, runtime_summary
from src.utils.logging import get_logger

logger = get_logger(__name__)

CATEGORY_LABELS = [
    "benign_or_unknown",
    "brute_force",
    "account_compromise",
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "unauthorized_access",
    "malicious_ip",
    "abnormal_traffic",
]


def _sqlite_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _seed_analyst(session_factory, password_hash: str):
    session = session_factory()
    try:
        user = repository.create_user(session, "benchmark_analyst", password_hash, "analyst")
        session.commit()
        return user
    finally:
        session.close()


def _alerts(session_factory) -> list[Alert]:
    session = session_factory()
    try:
        return list(
            session.scalars(select(Alert).order_by(Alert.created_at.asc(), Alert.id.asc()))
        )
    finally:
        session.close()


def _audit_chain_valid(session_factory) -> bool:
    session = session_factory()
    try:
        valid, _, _ = repository.verify_audit_chain(session)
        return bool(valid)
    finally:
        session.close()


def _choose_incident(service: SocService) -> dict[str, Any] | None:
    incidents = service.list_incidents(limit=500)
    if not incidents:
        return None
    return max(incidents, key=lambda item: (item.get("event_count", 0), item["created_at"]))


def _run_baseline(scenario: Scenario, database_path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    engine, session_factory = create_database(_sqlite_url(database_path))
    try:
        service = SocService(session_factory)
        batch = service.ingest_batch(
            scenario.events,
            actor="evaluation",
            actor_role="system",
            source="evaluation_baseline",
            enable_ml=False,
            auto_investigate=False,
        )
        duration_ms = (time.perf_counter() - started) * 1000
        alerts = _alerts(session_factory)
        result = baseline_result(alerts)
        result.update(
            {
                "ingestion_ms": round(duration_ms, 2),
                "events": len(scenario.events),
                "incidents_created": len(batch["incidents"]),
            }
        )
        return result
    finally:
        engine.dispose()


def _run_agentic(
    scenario: Scenario,
    database_path: Path,
    analyst,
    *,
    request_id: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    engine, session_factory = create_database(_sqlite_url(database_path))
    try:
        service = SocService(session_factory)
        ingest_started = time.perf_counter()
        batch = service.ingest_batch(
            scenario.events,
            actor="evaluation",
            actor_role="system",
            source="evaluation_agentic",
            enable_ml=False,
            auto_investigate=False,
        )
        ingestion_ms = (time.perf_counter() - ingest_started) * 1000
        incident = _choose_incident(service)
        record: dict[str, Any] = {
            "events": len(scenario.events),
            "ingestion_ms": round(ingestion_ms, 2),
            "incident_count": len(batch["incidents"]),
            "alerts_created": batch["alerts_created"],
            "detected": bool(batch["alerts_created"]) or bool(incident),
            "predicted_category": "benign_or_unknown",
            "risk_score": None,
            "risk_level": None,
            "severity": None,
            "confidence": None,
            "approval_required": False,
            "approval_status": "NOT_REQUIRED",
            "approval_expected": False,
            "approval_gate_correct": True,
            "pending_before_approval": True,
            "auto_executed": False,
            "execution_verified": False,
            "actions": [],
            "action_count": 0,
            "executed_actions": 0,
            "simulated_actions": 0,
            "non_simulated_actions": 0,
            "key_action_present": None,
            "allowlist_compliant": True,
            "simulation_compliant": True,
            "predicted_mitre": [],
            "evidence_count": 0,
            "agent_runs": 0,
            "prompt_injection_flags": 0,
            "llm_mode": None,
            "ti_mode": "NOT_QUERIED",
            "investigation_ms": 0.0,
            "response_ms": 0.0,
            "total_ms": 0.0,
            "audit_chain_valid": True,
            "status": "NO_INCIDENT" if scenario.is_attack is False else "NO_INCIDENT",
            "error": None,
        }
        if not incident:
            record["total_ms"] = round((time.perf_counter() - started) * 1000, 2)
            record["audit_chain_valid"] = _audit_chain_valid(session_factory)
            return record

        incident_id = incident["id"]
        investigation_started = time.perf_counter()
        investigation = service.investigate(
            incident_id,
            actor="benchmark_admin",
            actor_role="admin",
            request_id=request_id,
        )
        investigation_ms = (time.perf_counter() - investigation_started) * 1000
        detail = service.get_incident_detail(incident_id)
        risk = detail.get("risk") or {}
        risk_level = risk.get("level") or detail["incident"]["severity"]
        expected_gate = risk_level in {"HIGH", "CRITICAL"}
        approval_required = bool(detail["incident"]["approval_required"])
        approval_status_before = investigation.get("approval_status", detail["incident"]["approval_status"])
        record.update(
            {
                "incident_id": incident_id,
                "detected": bool(detail["alerts"]),
                "predicted_category": detail["incident"]["attack_category"],
                "risk_score": risk.get("score"),
                "risk_level": risk_level,
                "severity": detail["incident"]["severity"],
                "confidence": detail["incident"]["confidence"],
                "approval_required": approval_required,
                "approval_status": detail["incident"]["approval_status"],
                "approval_expected": expected_gate,
                "pending_before_approval": (
                    not expected_gate or approval_status_before == "PENDING"
                ),
                "auto_executed": bool(investigation.get("auto_executed")),
                "investigation_ms": round(investigation_ms, 2),
                "evidence_count": len(detail["evidence"]),
                "agent_runs": len(detail["agent_runs"]),
                "prompt_injection_flags": sum(
                    int(((event.get("raw_event") or {}).get("_normalization") or {}).get("prompt_injection_flags", 0))
                    for event in detail["events"]
                ),
                "llm_mode": detail["incident"]["llm_mode"],
                "ti_mode": detail["system"]["threat_intel_mode"],
            }
        )
        record["approval_gate_correct"] = (
            approval_required == expected_gate and bool(record["pending_before_approval"])
        )

        response_started = time.perf_counter()
        if approval_required and detail["incident"]["status"] == "AWAITING_APPROVAL":
            service.approve(
                incident_id,
                analyst,
                "Synthetic benchmark approval under simulation-only policy.",
                request_id=request_id,
            )
            service.execute(incident_id, analyst, request_id=request_id)
        response_ms = (time.perf_counter() - response_started) * 1000

        final = service.get_incident_detail(incident_id)
        actions = final["response"]["actions"]
        action_types = [action["action_type"] for action in actions]
        executed = [action for action in actions if action["status"] == "EXECUTED"]
        record.update(
            {
                "status": final["incident"]["status"],
                "approval_status": final["incident"]["approval_status"],
                "execution_verified": final["incident"]["status"] == "VERIFIED",
                "actions": action_types,
                "action_count": len(actions),
                "executed_actions": len(executed),
                "simulated_actions": sum(1 for action in actions if action["is_simulated"]),
                "non_simulated_actions": sum(1 for action in actions if not action["is_simulated"]),
                "key_action_present": (
                    scenario.expected_key_action in action_types
                    if scenario.expected_key_action else None
                ),
                "allowlist_compliant": all(is_allowed_action(item) for item in action_types),
                "simulation_compliant": all(action["is_simulated"] for action in actions),
                "predicted_mitre": sorted({item["technique_id"] for item in final["mitre"]}),
                "response_ms": round(response_ms, 2),
                "audit_chain_valid": _audit_chain_valid(session_factory),
            }
        )
        record["total_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return record
    finally:
        engine.dispose()


def _aggregate(rows: list[dict[str, Any]], scenarios: list[Scenario], per_class: int, seed: int) -> dict[str, Any]:
    attack_rows = [row for row in rows if row["is_attack"]]
    benign_rows = [row for row in rows if not row["is_attack"]]
    baseline_detection = binary_detection_metrics(rows, "baseline_detected")
    agentic_detection = binary_detection_metrics(rows, "agentic_detected")
    baseline_classification = classification_metrics(rows, "baseline_category", CATEGORY_LABELS)
    agentic_classification = classification_metrics(rows, "agentic_category", CATEGORY_LABELS)
    paired = mcnemar_exact(
        [row["baseline_category"] == row["expected_category"] for row in rows],
        [row["agentic_category"] == row["expected_category"] for row in rows],
    )
    gated_rows = [row for row in attack_rows if row.get("incident_id")]
    gate_correct = sum(1 for row in gated_rows if row["approval_gate_correct"])
    key_action_rows = [row for row in gated_rows if row.get("key_action_present") is not None]
    key_action_correct = sum(1 for row in key_action_rows if row["key_action_present"])
    allowlist_rows = [row for row in gated_rows if row["action_count"]]
    allowlist_correct = sum(1 for row in allowlist_rows if row["allowlist_compliant"])
    simulation_correct = sum(1 for row in gated_rows if row["simulation_compliant"] and row["non_simulated_actions"] == 0)
    verified = sum(1 for row in gated_rows if row["execution_verified"])
    audit_valid = sum(1 for row in rows if row["audit_chain_valid"])
    correlation_correct = sum(
        1 for row in rows
        if (row["is_attack"] and row["incident_count"] == 1)
        or ((not row["is_attack"]) and row["incident_count"] == 0)
    )
    unauthorized = sum(
        1 for row in gated_rows
        if row["approval_expected"] and row["auto_executed"] and not row["approval_required"]
    )
    executed_actions = sum(row["executed_actions"] for row in gated_rows)
    simulated_actions = sum(row["simulated_actions"] for row in gated_rows)
    non_simulated_actions = sum(row["non_simulated_actions"] for row in gated_rows)

    response = {
        "attack_scenarios": len(attack_rows),
        "incidents_investigated": len(gated_rows),
        "approval_gate_accuracy": round(gate_correct / len(gated_rows), 4) if gated_rows else 0.0,
        "approval_gate_correct": gate_correct,
        "approval_gate_total": len(gated_rows),
        "approval_required_count": sum(1 for row in gated_rows if row["approval_required"]),
        "auto_executed_count": sum(1 for row in gated_rows if row["auto_executed"]),
        "unauthorized_executions": unauthorized,
        "key_action_coverage": round(key_action_correct / len(key_action_rows), 4) if key_action_rows else 0.0,
        "key_action_correct": key_action_correct,
        "key_action_total": len(key_action_rows),
        "allowlist_compliance": round(allowlist_correct / len(allowlist_rows), 4) if allowlist_rows else 0.0,
        "allowlist_total": len(allowlist_rows),
        "simulation_compliance": round(simulation_correct / len(gated_rows), 4) if gated_rows else 0.0,
        "verification_rate": round(verified / len(gated_rows), 4) if gated_rows else 0.0,
        "verified_incidents": verified,
        "executed_actions": executed_actions,
        "simulated_action_records": simulated_actions,
        "non_simulated_action_records": non_simulated_actions,
        "audit_chain_valid_rate": round(audit_valid / len(rows), 4) if rows else 0.0,
        "audit_chain_valid_scenarios": audit_valid,
    }
    latency = {
        "ingestion_ms": latency_summary([row["ingestion_ms"] for row in rows]),
        "investigation_ms": latency_summary([row["investigation_ms"] for row in gated_rows]),
        "response_ms": latency_summary([row["response_ms"] for row in gated_rows]),
        "total_ms": latency_summary([row["total_ms"] for row in rows]),
        "note": "Wall-clock durations measured on the evaluation host; not a production SLA.",
    }
    llm_modes: dict[str, int] = {}
    ti_modes: dict[str, int] = {}
    for row in gated_rows:
        llm_modes[row.get("llm_mode") or "UNKNOWN"] = llm_modes.get(row.get("llm_mode") or "UNKNOWN", 0) + 1
        ti_modes[row.get("ti_mode") or "UNKNOWN"] = ti_modes.get(row.get("ti_mode") or "UNKNOWN", 0) + 1

    config = get_config()
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "environment": environment_info(),
        "method": {
            "description": (
                "Rule-only baseline and full agentic pipeline run on identical generated scenarios, "
                "each in a fresh temporary SQLite database. ML anomaly detection is disabled in this "
                "scenario comparison so that the measured difference isolates incident-level "
                "classification and response policy; the ML model is evaluated separately."
            ),
            "per_class": per_class,
            "seed": seed,
            "scenario_count": len(scenarios),
            "attack_count": len(attack_rows),
            "benign_count": len(benign_rows),
            "data_label": "synthetic_demo_data",
            "baseline_definition": "Earliest rule alert selects the category; no investigation re-triage.",
            "agentic_definition": "Deterministic evidence-driven triage after LangGraph evidence/TI/MITRE/risk stages.",
        },
        "configuration": {
            "runtime": runtime_summary(),
            "detection": {
                "failed_login_threshold": config["detection"]["failed_login_threshold"],
                "failed_login_window_minutes": config["detection"]["failed_login_window_minutes"],
                "request_rate_threshold": config["detection"]["request_rate_threshold"],
                "correlation_window_minutes": config["detection"]["correlation_window_minutes"],
                "enable_ml_anomaly_scenario_run": False,
            },
            "response": {
                "simulation_mode": config["response"]["simulation_mode"],
                "require_approval_for_high": config["response"]["require_approval_for_high"],
                "require_approval_for_critical": config["response"]["require_approval_for_critical"],
                "require_approval_for_medium": config["response"]["require_approval_for_medium"],
            },
        },
        "detection": {
            "baseline": baseline_detection,
            "agentic": agentic_detection,
            "shared_rule_stage": True,
            "by_category": detection_by_category(rows, "agentic_detected"),
            "baseline_by_category": detection_by_category(rows, "baseline_detected"),
        },
        "incident_correlation": {
            **proportion(correlation_correct, len(rows)),
            "note": "Attack scenario must yield exactly one incident; benign scenario must yield zero.",
        },
        "classification": {
            "labels": CATEGORY_LABELS,
            "baseline": baseline_classification,
            "agentic": agentic_classification,
            "paired_comparison": paired,
        },
        "mitre": mitre_metrics(rows),
        "risk": risk_summary(attack_rows),
        "response": response,
        "latency": latency,
        "modes": {
            "llm": llm_modes,
            "threat_intel": ti_modes,
            "llm_note": "Deterministic template mode unless a live LLM was explicitly configured.",
            "threat_intel_note": "Live providers were not configured; documentation-range IPs use labelled mock data and private IPs are not externally queried.",
        },
        "totals": {
            "events_processed": sum(row["events"] for row in rows),
            "alerts_created_agentic": sum(row["alerts_created"] for row in rows),
            "incidents_investigated": len(gated_rows),
            "audit_entries_checked": None,
        },
        "scenarios": rows,
    }


def run_scenario_benchmark(
    *,
    per_class: int = 10,
    seed: int = 42,
    results_dir: Path | None = None,
    keep_temp: bool = False,
    verbose: bool = True,
) -> dict[str, Any]:
    results_dir = results_dir or RESULTS_DIR
    metrics_dir = results_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    scenarios = generate_scenarios(per_class=per_class, seed=seed)
    temp_root = Path(tempfile.mkdtemp(prefix="soc_eval_"))
    benchmark_hash = hash_password(generate_password(24))
    rows: list[dict[str, Any]] = []
    logger.info("Running %d scenarios (per_class=%d seed=%d)", len(scenarios), per_class, seed)
    try:
        for index, scenario in enumerate(scenarios, start=1):
            scenario_dir = temp_root / f"{index:03d}_{scenario.name}"
            scenario_dir.mkdir(parents=True, exist_ok=True)
            baseline = _run_baseline(scenario, scenario_dir / "baseline.db")
            engine, session_factory = create_database(_sqlite_url(scenario_dir / "agentic.db"))
            try:
                analyst = _seed_analyst(session_factory, benchmark_hash)
            finally:
                engine.dispose()
            agentic = _run_agentic(
                scenario,
                scenario_dir / "agentic.db",
                analyst,
                request_id=f"eval-{index:03d}",
            )
            expected_category = scenario.category if scenario.is_attack else "benign_or_unknown"
            row = {
                "scenario": scenario.name,
                "category": scenario.category,
                "expected_category": expected_category,
                "is_attack": scenario.is_attack,
                "expected_mitre": list(scenario.expected_mitre),
                "expected_key_action": scenario.expected_key_action,
                "baseline_detected": bool(baseline["detected"]),
                "baseline_category": baseline["predicted_category"],
                "baseline_alert_count": baseline["alert_count"],
                "baseline_alert_types": "|".join(baseline["alert_types"]),
                "baseline_ingestion_ms": baseline["ingestion_ms"],
                "agentic_detected": bool(agentic["detected"]),
                "agentic_category": agentic["predicted_category"],
                "agentic_alert_count": agentic["alerts_created"],
                **{key: value for key, value in agentic.items() if key not in {"detected", "predicted_category"}},
            }
            rows.append(row)
            if verbose:
                marker = "OK" if row["agentic_category"] == row["expected_category"] else "MISMATCH"
                logger.info(
                    "[%d/%d] %-24s baseline=%-18s agentic=%-18s risk=%s %s",
                    index, len(scenarios), scenario.name, row["baseline_category"],
                    row["agentic_category"], row.get("risk_level"), marker,
                )
        payload = _aggregate(rows, scenarios, per_class, seed)
        payload["rows"] = rows
        # Persist a flat, analysis-friendly CSV.
        csv_path = metrics_dir / "scenario_results.csv"
        fieldnames = sorted({key for row in rows for key in row})
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    key: ("|".join(map(str, value)) if isinstance(value, list) else value)
                    for key, value in row.items()
                })
        payload["csv_path"] = str(csv_path)
        json_path = metrics_dir / "scenario_metrics.json"
        serializable = dict(payload)
        serializable["rows"] = rows
        json_path.write_text(json.dumps(serializable, indent=2, default=str), encoding="utf-8")
        payload["metrics_path"] = str(json_path)

        from src.evaluation.figures import (
            plot_audit_and_approval, plot_detection_rates, plot_latency,
            plot_pipeline_diagram, plot_risk_by_category, plot_scenario_classification,
        )
        figure_dir = results_dir / "figures"
        try:
            plot_scenario_classification(payload, figure_dir / "scenario_classification.png")
            plot_detection_rates(payload, figure_dir / "scenario_detection_rates.png")
            plot_risk_by_category(rows, figure_dir / "risk_by_category.png")
            plot_latency(rows, figure_dir / "pipeline_latency.png")
            plot_audit_and_approval(payload, figure_dir / "response_policy_outcomes.png")
            plot_pipeline_diagram(figure_dir / "pipeline_diagram.png")
        except Exception:
            logger.exception("Failed to render scenario figures")
        return payload
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)
        else:
            logger.info("Kept evaluation databases in %s", temp_root)
