"""One-command end-to-end demonstration through the real FastAPI application.

The script:
1. creates a fresh local demo database and user;
2. logs in through /auth/login;
3. ingests the labelled synthetic scenario through /api/demo/scenario;
4. runs the LangGraph investigation, approval gate, simulated execution and verification;
5. prints measured incident fields and writes results/reports/demo_run.json.

No incident ID, risk score, status or metric is hard-coded.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.database import repository  # noqa: E402
from src.security.audit import AuditService  # noqa: E402
from src.security.passwords import generate_password, hash_password  # noqa: E402
from src.utils.config import DATA_DIR, RESULTS_DIR  # noqa: E402


def _reset(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if candidate.exists():
            candidate.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full synthetic incident-response demo.")
    parser.add_argument("--database", default=str(DATA_DIR / "demo.db"))
    parser.add_argument("--keep-db", action="store_true", help="Do not delete the demo database first.")
    parser.add_argument("--password", default=None, help="Optional demo admin password (min 12 chars).")
    parser.add_argument(
        "--scenario",
        default="brute_force_account_compromise",
        choices=["brute_force_account_compromise", "xss_injection", "unauthorized_access_attempts"],
        help="Synthetic demo scenario to run.",
    )
    args = parser.parse_args()

    database_path = Path(args.database)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if not args.keep_db:
        _reset(database_path)
    password = args.password or generate_password(24)
    if len(password) < 12:
        raise SystemExit("Demo password must be at least 12 characters")
    database_url = f"sqlite:///{database_path.resolve().as_posix()}"

    app = create_app(database_url, rate_limit_enabled=False)
    session = app.state.session_factory()
    try:
        if not repository.get_user_by_username(session, "demo_admin"):
            repository.create_user(session, "demo_admin", hash_password(password), "admin")
        AuditService(session).record(
            actor="demo_bootstrap", actor_role="system", action="DEMO_USER_READY",
            entity_type="user", outcome="SUCCESS",
            details={"username": "demo_admin", "database": database_path.name},
        )
        session.commit()
    finally:
        session.close()

    credentials_path = DATA_DIR / "demo_credentials.json"
    credentials_path.write_text(
        json.dumps({
            "username": "demo_admin",
            "password": password,
            "role": "admin",
            "database": str(database_path),
            "note": "Local synthetic demonstration credential; delete after use.",
        }, indent=2),
        encoding="utf-8",
    )
    try:
        credentials_path.chmod(0o600)
    except OSError:
        pass

    with TestClient(app) as client:
        login = client.post("/auth/login", json={"username": "demo_admin", "password": password})
        if login.status_code != 200:
            raise SystemExit(f"Login failed ({login.status_code}): {login.text[:500]}")
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        response = client.post(
            f"/api/demo/scenario?auto_investigate=true&scenario_name={args.scenario}",
            headers=headers,
        )
        if response.status_code != 200:
            raise SystemExit(f"Demo scenario failed ({response.status_code}): {response.text[:1000]}")
        demo = response.json()
        incident_id = demo["batch"]["incidents"][0]
        before = client.get(f"/api/incidents/{incident_id}", headers=headers).json()
        incident = before["incident"]
        risk = before["risk"] or {}
        mitre = sorted(item["technique_id"] for item in before["mitre"])
        ti_modes = sorted({item["mode"] for item in before["threat_intelligence"]})

        approve = client.post(
            f"/api/incidents/{incident_id}/approve",
            headers=headers,
            json={"reason": "Demo analyst approval after reviewing evidence (simulation only)."},
        )
        if approve.status_code != 200:
            raise SystemExit(f"Approval failed ({approve.status_code}): {approve.text[:1000]}")
        execution_response = client.post(f"/api/incidents/{incident_id}/execute", headers=headers)
        if execution_response.status_code != 200:
            raise SystemExit(f"Execution failed ({execution_response.status_code}): {execution_response.text[:1000]}")
        execution = execution_response.json()
        final = client.get(f"/api/incidents/{incident_id}", headers=headers).json()
        metrics = client.get("/api/metrics", headers=headers).json()
        audit = client.get("/api/audit?limit=5", headers=headers).json()

        executed = execution.get("execution", {}).get("executed", [])
        verification = execution.get("verification", {})
        summary = {
            "data_label": demo["data_label"],
            "scenario": demo["scenario"],
            "ground_truth": demo["ground_truth"],
            "incident_id": incident_id,
            "severity": risk.get("level") or incident["severity"],
            "risk_score": risk.get("score"),
            "status_before_approval": incident["status"],
            "approval_required": incident["approval_required"],
            "approval_status_before": incident["approval_status"],
            "classification": incident["attack_category"],
            "confidence": incident["confidence"],
            "mitre_techniques": mitre,
            "evidence_count": len(before["evidence"]),
            "threat_intel_modes": ti_modes,
            "llm_mode": incident["llm_mode"],
            "response_action_records": len(approve.json().get("actions", [])),
            "executed_actions": len(executed),
            "simulated_executed_actions": sum(1 for action in executed if action.get("is_simulated")),
            "verification_passed": verification.get("verified"),
            "verification_checks": verification.get("checks", []),
            "final_status": final["incident"]["status"],
            "audit_chain_valid": metrics["audit"]["chain_valid"],
            "audit_entries": metrics["audit"]["entries"],
            "database": str(database_path),
            "credentials_file": str(credentials_path),
            "dashboard_command": (
                "$env:SOC_API_URL='http://127.0.0.1:8000'; "
                ".\\.venv\\Scripts\\python.exe -m streamlit run dashboard/app.py"
            ),
            "recent_audit_actions": [entry["action"] for entry in audit["entries"]],
        }

        report_path = RESULTS_DIR / "reports" / "demo_run.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        print("=" * 78)
        print("AI-AGENT INCIDENT RESPONSE DEMO  (data_label: synthetic_demo_data)")
        print("=" * 78)
        print(f"Scenario              : {summary['scenario']}")
        print(f"Incident              : {summary['incident_id']}")
        print(f"Classification        : {summary['classification']} (confidence {summary['confidence']:.2f})")
        print(f"Risk                  : {summary['risk_score']} / 100 -> {summary['severity']}")
        print(f"Status after agent    : {summary['status_before_approval']} "
              f"(approval_required={summary['approval_required']})")
        print(f"MITRE techniques      : {', '.join(mitre) or 'none'}")
        print(f"Evidence records      : {summary['evidence_count']}")
        print(f"Threat-intel mode     : {', '.join(ti_modes) or 'NOT_QUERIED'}")
        print(f"LLM mode              : {summary['llm_mode']}")
        print(f"Approval              : {summary['approval_status_before']} -> APPROVED by demo_admin")
        print(f"Executed actions      : {summary['executed_actions']} "
              f"({summary['simulated_executed_actions']} simulated)")
        print(f"Verification          : {'PASSED' if summary['verification_passed'] else 'FAILED'}")
        print(f"Final status          : {summary['final_status']}")
        print(f"Audit hash chain      : {'VALID' if summary['audit_chain_valid'] else 'INVALID'} "
              f"({summary['audit_entries']} entries)")
        print(f"Result file           : {report_path}")
        print("-" * 78)
        print(f"Dashboard login       : demo_admin / {password}")
        print(f"Credentials file      : {credentials_path}")
        print("Start API             : .\\.venv\\Scripts\\python.exe -m uvicorn src.api.main:app --port 8000")
        print("Start dashboard       : .\\.venv\\Scripts\\python.exe -m streamlit run dashboard/app.py")
        print("=" * 78)

        ok = (
            summary["verification_passed"] is True
            and summary["final_status"] == "VERIFIED"
            and summary["audit_chain_valid"] is True
            and summary["simulated_executed_actions"] == summary["executed_actions"]
        )
        if not ok:
            print("DEMO VALIDATION FAILED: one or more measured checks did not pass.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
