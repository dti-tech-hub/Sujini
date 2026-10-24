# AGENTS.md — working rules for this repository

This file tells future coding agents and human contributors how this project is expected to be changed, tested and documented.

## 1. Project purpose

This is an academic B.Tech project: **AI Agent-Based Automated Cybersecurity Incident Response System** for web-application security. It must remain a real, runnable system. Do not replace working components with mock screenshots, hard-coded metrics or fabricated API responses.

The required pipeline is:

```text
Security Events → Detection → Investigation → Evidence → Threat Intelligence
→ MITRE ATT&CK → Risk → Response → Approval/Automation → Audit
```

## 2. Non-negotiable safety invariants

1. **Simulation only.** All response effects are simulated. Never add code that modifies a real firewall, host, container, session store, credential store or network device.
2. **Refuse unsafe mode.** `simulation_mode=false` must continue to raise a policy error.
3. **Allowlist.** Every response action must come from `config/response_rules.yaml`. The executor must independently re-check the allowlist.
4. **LLM is advisory.** LLM output must never select or execute an action. Deterministic classification and policy remain authoritative.
5. **Human approval.** HIGH and CRITICAL incidents require an analyst/admin approval before execution. Do not weaken this gate.
6. **Audit.** Every ingestion, detection, investigation stage, approval, rejection, execution, failure and verification must be audit-logged. Preserve the hash chain.
7. **Prompt injection is data.** Log content, user agents, usernames and messages are untrusted. Never interpolate them into an instruction position or shell command.
8. **No arbitrary execution.** Do not add `subprocess`, `os.system`, `eval`, `exec`, shell invocation or network-mutating calls driven by event/LLM content.
9. **Data provenance.** Synthetic data must carry `dataset_label="synthetic_demo_data"`. Mock threat intelligence must carry `is_mock=true` and an explicit mode such as `DEMO_MOCK`.
10. **No fabricated results.** Unmeasured values must be written as `NOT MEASURED`, never estimated or invented.

## 3. Environment and commands

Use the project interpreter:

```powershell
.\.venv\Scripts\python.exe
```

Global `pip.exe` is blocked on the development machine; use `.\.venv\Scripts\python.exe -m pip ...`.

| Task | Command |
|---|---|
| Install | `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` |
| Tests | `.\.venv\Scripts\python.exe -m pytest` |
| Seed users | `.\.venv\Scripts\python.exe scripts\seed_database.py` |
| Train model | `.\.venv\Scripts\python.exe scripts\train_model.py` |
| Full evaluation | `.\.venv\Scripts\python.exe scripts\evaluate.py` |
| End-to-end demo | `.\.venv\Scripts\python.exe scripts\run_demo.py` |
| API | `.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000` |
| Dashboard | `$env:SOC_API_URL="http://127.0.0.1:8000"; .\.venv\Scripts\python.exe -m streamlit run dashboard/app.py` |

Current test baseline: **84 passed, 1 warning**. The warning is an upstream Starlette deprecation notice.

## 4. Architecture map

- `src/services/soc_service.py` — central facade used by API, scripts and benchmark. Keep API routes thin.
- `src/agents/orchestrator.py` — LangGraph investigation and response graphs. Phase 1 ends at the durable approval gate; phase 2 executes and verifies.
- `src/detection/` — normalization, signature rules (SQL injection, XSS, command injection, traversal, reconnaissance, scanner user agent, prompt injection), behavioral detection (failed-login burst, success-after-failure, request rate, server-error burst, unauthorized access, malicious IP), ML anomaly signal and incident correlation. Failed-login counters are scoped to authentication endpoints; unauthorized access covers denial bursts and privileged-endpoint denials.
- `src/investigation/` — evidence, correlation, deterministic triage and timeline.
- `src/threat_intel/` — provider adapters, local/mock fallback and mode labels.
- `src/mitre/` — ATT&CK mapping and confidence/status logic.
- `src/risk/` — transparent weighted scoring; every factor must remain explainable.
- `src/response/` — planner, approval, simulated executor, verification.
- `src/security/` — JWT auth, PBKDF2 passwords, sanitization, rate limiting, audit hash chain.
- `src/evaluation/` — synthetic datasets, scenario benchmark, baseline, metrics, figures and report.
- `src/ml/` — 14-feature engineering, training, model artifact loading and inference.
- `dashboard/app.py` — thin Streamlit client over the API; it must not read SQLite directly.

## 5. Data and evaluation rules

- ML dataset anchor timestamp is fixed (`DATASET_ANCHOR` in `src/evaluation/datasets.py`) to keep features reproducible.
- Isolation Forest uses `n_jobs=1` so threshold selection is bit-for-bit reproducible.
- Scenario benchmark runs each scenario in a **fresh temporary SQLite database** for both baseline and agentic arms.
- ML anomaly detection is deliberately disabled in the scenario comparison (`enable_ml=False`) so the measured difference isolates incident-level classification and policy. Do not silently re-enable it without re-running and re-documenting the benchmark.
- The scenario baseline is rule-only and uses the earliest alert category. Do not "improve" the baseline with investigation logic; that would invalidate the comparison.
- MITRE ground truth is project-defined. Only categories with defensible mappings are eligible. `malicious_ip` and `abnormal_traffic` are excluded. Do not count them as MITRE accuracy.
- The Isolation Forest threshold uses labels on a validation split; describe it as **threshold-calibrated**, not fully unsupervised.
- Random Forest's 100% score is an artifact of separable synthetic features. Never market it as real-world accuracy.

## 6. Code style and conventions

- Python 3.11+; type hints where practical; `from __future__ import annotations` in source modules.
- Pydantic v2 for API/LLM schemas.
- SQLAlchemy 2.x declarative models; repository functions for persistence.
- Use UTC-aware timestamps and `iso()` for serialization.
- Raise `AppError` subclasses (`ValidationError`, `NotFoundError`, `ConflictError`, `PolicyError`) for domain failures. FastAPI maps them to JSON.
- Keep response action types uppercase and prefixed with `SIMULATE_` when they have simulated effects.
- Configuration belongs in `config/*.yaml` or environment variables, not hard-coded in route handlers.
- Add tests for every behavior change. Prefer deterministic unit tests; use the `create_app(temp_db_url, rate_limit_enabled=False)` pattern for API tests.
- Do not commit `data/*.db`, credentials, `.secret_key`, model binaries, generated results or logs.

## 7. Requirements for documentation changes

- Any numeric claim must come from a committed run artifact or be reproducible by a documented command.
- If an experiment was not run, write **NOT MEASURED**.
- Keep the distinction between:
  - `synthetic_demo_data` (dataset provenance),
  - `DEMO_TEMPLATE` / `LIVE_LLM` (LLM mode),
  - `DEMO_MOCK` / `NO_EXTERNAL_LOOKUP` / `DEMO_MOCK_FALLBACK` / `LIVE` (threat-intel mode),
  - `SIMULATION` (response effect).
- When evaluation numbers change, update all of:
  - `results/reports/evaluation_report.md` (generated),
  - `docs/EVALUATION.md`,
  - `docs/CONFERENCE_PAPER.md`,
  - `docs/conference_paper.tex`,
  - the summary in `README.md`,
  - `docs/FINAL_VALIDATION.md` if the validation state changed.

## 8. Before handing off

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe scripts\evaluate.py
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Then verify:

- tests pass;
- the demo reaches `VERIFIED`;
- audit chain is valid;
- all response action records are simulated;
- `results/reports/evaluation_report.md` contains the final measured values;
- `git status` contains no database, credential, model or generated-log artifacts.

Do not push to a remote unless the user explicitly asks.
