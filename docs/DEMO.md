# Demo and demonstration guide

This guide describes the end-to-end demonstration that was actually executed in this repository. The scenario is synthetic, the LLM runs deterministic templates, threat intelligence is mock/no-lookup, and every response action is simulated.

Measured reference run: **23 October 2026**, Windows 11, Python 3.14.5, commit `b0ade44a34ea`.

## 1. One command

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

The script uses the real FastAPI application through `TestClient` and a disposable SQLite database. It does not require a running server, internet access or API keys.

Measured console summary:

```text
Scenario              : brute_force_account_compromise
Incident              : INC-0001
Classification        : account_compromise (confidence 0.97)
Risk                  : 90.21 / 100 -> CRITICAL
Status after agent    : AWAITING_APPROVAL (approval_required=True)
MITRE techniques      : T1078, T1110, T1190
Evidence records      : 16
Threat-intel mode     : DEMO_MOCK
LLM mode              : DEMO_TEMPLATE
Approval              : PENDING -> APPROVED by demo_admin
Executed actions      : 6 (6 simulated)
Verification          : PASSED
Final status          : VERIFIED
Audit hash chain      : VALID (41 entries)
```

The run also writes `results/reports/demo_run.json` and local demo credentials to `data/demo_credentials.json` (git-ignored).

Select another synthetic scenario with `--scenario`:

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py --scenario xss_injection
.\.venv\Scripts\python.exe scripts\run_demo.py --scenario unauthorized_access_attempts
```

The measured XSS run reached `xss` at confidence 0.89 and risk 62.07 (HIGH), with MITRE `T1059.007`, four simulated actions and `VERIFIED`. The measured unauthorized-access run reached `unauthorized_access` at confidence 0.75 and risk 58.55 (HIGH), with no MITRE mapping, four simulated actions and `VERIFIED`. Both are synthetic and simulation-only.

## 2. What the demo does

The script performs the following steps in order. Each step writes to the database and the audit chain.

1. **Environment and database check** — creates a disposable SQLite database and applies the schema.
2. **Seed users** — creates the demo admin/analyst/viewer accounts.
3. **Generate the scenario** — produces `synthetic_demo_data` events:
   - five failed logins for `admin` from `198.51.100.77`;
   - a successful login after the failures;
   - a SQL-injection-shaped admin user search;
   - an admin audit-page access;
   - a request containing prompt-injection text.
4. **Ingest events** — normalization, deduplication, rule and behavioral detection.
5. **Create/correlate incident** — one incident is produced from the correlated events.
6. **Investigate** — LangGraph phase 1:
   evidence -> triage -> threat intelligence -> MITRE -> risk -> response plan -> approval gate.
7. **Enrich threat intelligence** — the documentation-range source IP is resolved by the deterministic mock provider and labelled `DEMO_MOCK`.
8. **Map MITRE ATT&CK** — `T1110`, `T1078`, `T1190`, with confidence/status and evidence.
9. **Score risk** — transparent weighted score; the measured demo score is 90.21 (CRITICAL).
10. **Plan response** — allowlisted actions, split into auto, approval-gated and advisory.
11. **Require approval** — the incident is `AWAITING_APPROVAL`; no gated action executes yet.
12. **Approve and execute** — an authenticated admin approves; the LangGraph response phase executes six simulated actions.
13. **Verify** — six checks pass; the incident becomes `VERIFIED`.
14. **Verify audit chain** — the hash chain is recomputed and reported valid.
15. **Summarize** — print the measured result and write the JSON report.

The demo does **not** execute a real network or host action. See `docs/SECURITY.md` for the safety invariants.

## 3. Demonstrating the dashboard

The dashboard is a thin Streamlit client over the API and does not read SQLite directly.

Terminal 1 — API:

```powershell
.\.venv\Scripts\python.exe scripts\seed_database.py
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Terminal 2 — dashboard:

```powershell
$env:SOC_API_URL="http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Open `http://127.0.0.1:8501` and sign in with the credentials printed by `seed_database.py` or the demo. To populate an incident through the dashboard workflow, run `scripts/run_demo.py` or call `POST /api/demo/scenario` as an admin; the dashboard itself does not expose a demo-scenario button.

Useful screens for a review:

| Screen | What it proves |
|---|---|
| Overview metrics and charts | Aggregation, severity/status distributions, top source IPs, ATT&CK counts, pipeline timing |
| Live events | Recent normalized events read from `GET /api/events`, including endpoint, status, source and severity |
| Incidents list and filters | Search by severity, status and category |
| Incident detail — Summary | Classification, confidence, reasoning, and runtime modes |
| Timeline | Correlated events, alerts, agent runs, approvals and execution in order |
| Evidence | Weighted evidence records, including prompt-injection containment |
| Threat intel | Per-indicator verdict, provider, `is_mock` and mode label |
| MITRE | Techniques, tactics, confidence and confirmed/candidate status |
| Risk | Every factor's raw value, normalized value, weight, contribution and explanation |
| Response | Auto, approval-gated and advisory actions with status |
| Approval | Approve/reject controls, approver identity, reason and decision history |
| Agent runs | Per-stage duration and provider |
| Audit | Hash-chained entries and chain verification |

Viewer accounts can read but cannot approve, execute or ingest. Analysts and admins can approve/reject/execute; only admins can load the demo scenario.

## 4. Demonstrating the API

Swagger UI: `http://127.0.0.1:8000/docs`.

Minimal flow:

```powershell
# 1. Health
curl.exe http://127.0.0.1:8000/health

# 2. Login (replace with a seeded credential)
curl.exe -X POST http://127.0.0.1:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{\"username\":\"demo_admin\",\"password\":\"<from data/demo_credentials.json>\"}'

# 3. Metrics (replace <token>)
curl.exe http://127.0.0.1:8000/api/metrics -H "Authorization: Bearer <token>"

# 4. Incident detail
curl.exe http://127.0.0.1:8000/api/incidents/INC-0001 -H "Authorization: Bearer <token>"

# 5. List demo scenarios, then run the XSS scenario
curl.exe http://127.0.0.1:8000/api/demo/scenarios -H "Authorization: Bearer <token>"
curl.exe -X POST "http://127.0.0.1:8000/api/demo/scenario?scenario_name=xss_injection" `
  -H "Authorization: Bearer <token>"
```

### Importing real-format logs

`scripts/import_logs.py` parses combined access logs, JSONL or CSV and posts them through the authenticated API:

```powershell
.\.venv\Scripts\python.exe scripts\import_logs.py --file access.log --format clf `
  --username admin --dataset-label synthetic_demo_data
```

Use `--dry-run` to validate parsing without sending. Log text is treated as data and is never executed.

Required endpoints exposed by the implementation:

```text
GET  /health
POST /api/events                 GET /api/events
POST /api/events/batch
POST /api/alerts                 GET /api/alerts
POST /api/incidents              GET /api/incidents
GET  /api/incidents/{id}
POST /api/incidents/{id}/investigate
GET  /api/incidents/{id}/timeline
GET  /api/incidents/{id}/evidence
GET  /api/incidents/{id}/threat-intel
GET  /api/incidents/{id}/mitre
GET  /api/incidents/{id}/risk
GET  /api/incidents/{id}/response
POST /api/incidents/{id}/approve
POST /api/incidents/{id}/reject
POST /api/incidents/{id}/execute
GET  /api/metrics                GET /api/audit
POST /auth/login                 GET /auth/me
GET  /api/system
GET  /api/demo/scenarios
POST /api/demo/scenario
```

The full request/response contract is in [`API.md`](API.md).

## 5. Suggested 8-minute presentation

1. **Problem and scope (1 min).** Web-application incidents need correlation, enrichment, risk and controlled response; this project implements that pipeline end to end.
2. **Safety framing (30 s).** All effects are simulated, the LLM is advisory, and HIGH/CRITICAL requires human approval.
3. **Run the demo (2 min).** Show the console summary: classification, risk, MITRE, approval, six simulated actions, verification and valid audit chain.
4. **Open the incident in the dashboard (3 min).** Walk through Summary, Timeline, Evidence, Threat intel, MITRE, Risk and Response. Point out the visible weights and mode labels.
5. **Show the approval gate (1 min).** Explain that the incident was `AWAITING_APPROVAL` before the analyst decision, and that a rejected incident would be audited with no execution.
6. **Show evaluation (1 min).** State the measured ML and scenario results with their caveats, and name the limitations: synthetic data, deterministic LLM, mock TI, no real containment.

## 6. Re-running evaluation

```powershell
.\.venv\Scripts\python.exe scripts\train_model.py
.\.venv\Scripts\python.exe scripts\evaluate.py
```

Generated artifacts:

```text
results/reports/evaluation_report.md
results/metrics/ml_metrics.json
results/metrics/scenario_metrics.json
results/metrics/scenario_results.csv
results/metrics/summary.json
results/metrics/saved_model_evaluation.json
results/metrics/*.csv
results/figures/*.png
```

Latency values are host-dependent. Non-latency metrics reproduce under seed 42 and the fixed dataset anchor.

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError` | Run commands with `.\\.venv\\Scripts\\python.exe`, not a global interpreter. |
| API starts but dashboard cannot log in | Check `SOC_API_URL` points to the API and that `scripts/seed_database.py` was run against the same `DATABASE_URL`. |
| `models/anomaly_iforest.joblib` missing | Run `scripts/train_model.py`; the rule engine still works, but the ML signal is reported unavailable. |
| `data/.secret_key` regenerated | JWTs issued with the old key stop working; sign in again. |
| Port already in use | Change `--port` (API) and `--server.port` (Streamlit). |
| Demo reports a different risk score | The demo uses the current timestamp and computes recurrence against a fresh database; the score is a real formula output, not a fixed constant. |
| Evaluation latency differs from the documented run | Wall-clock timing varies with host load; the non-latency metrics are the reproducible part. |

## 8. Cleanup

The demo uses a disposable database and disposable credentials. To reset local state:

```powershell
Remove-Item data\demo.db, data\demo_credentials.json -ErrorAction SilentlyContinue
Remove-Item data\soc.db -ErrorAction SilentlyContinue
```

Do not add a database, credential file, model binary or generated result to version control; all are covered by `.gitignore`.
