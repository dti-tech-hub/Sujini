# Final validation report

Validation date: **23 October 2026** (local time, UTC+05:30)
Code under test: **`b0ade44a34ea`** (`fix: make synthetic evaluation data and anomaly threshold reproducible`) plus uncommitted XSS/access-control, demo and documentation changes
Host: Windows 11 (`Windows-11-10.0.26200-SP0`), Python 3.14.5, 12 logical CPUs, AMD64
Data provenance: **`synthetic_demo_data`**
Response mode: **SIMULATION ONLY**

This document records the final checks that were actually executed. Values that were not measured are not presented as measured.

## 1. Test suite

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Result:

```text
84 passed, 1 warning in 55.08s (0:00:55)
```

The only warning is an upstream Starlette deprecation notice:

```text
StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated.
Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead.
```

Test distribution:

| File | Tests |
|---|---:|
| `tests/test_normalization.py` | 10 |
| `tests/test_detection.py` | 18 |
| `tests/test_risk_mitre.py` | 10 |
| `tests/test_response_safety.py` | 7 |
| `tests/test_audit.py` | 3 |
| `tests/test_api_auth.py` | 9 |
| `tests/test_api_e2e.py` | 2 |
| `tests/test_llm_security.py` | 7 |
| `tests/test_threat_intel.py` | 5 |
| `tests/test_ml.py` | 5 |
| `tests/test_evaluation.py` | 8 |
| **Total** | **84** |

Coverage highlights:

- prompt injection is flagged and contained as data;
- destructive LLM output is rejected by schema validation;
- `simulation_mode=false` is refused;
- non-allowlisted actions are refused;
- HIGH/CRITICAL incidents cannot execute before approval;
- rejection requires a reason;
- audit-chain modification is detected;
- viewer cannot write or approve;
- expired/invalid tokens are rejected;
- API end-to-end flow reaches verification;
- TI invalid indicators return `INVALID`;
- ML artifact feature schema is validated;
- XSS and unauthorized-access indicators produce the expected categories;
- generic access denials do not inflate failed-login or account-compromise counters;
- authorization-only scenarios are excluded from MITRE accuracy;
- evaluation metric implementations match hand-computed examples.

## 2. Full evaluation

Command:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate.py
```

Generated report: `results/reports/evaluation_report.md`
Generated at: **2026-10-23T02:59:39.641323+00:00**
Environment recorded in report: Python 3.14.5, Windows 11, git commit `b0ade44a34ea`

### 2.1 Headline checks

| Check | Result |
|---|---|
| ML dataset | 4,200 synthetic events; 2,940 train / 1,260 test; 14 features; seed 42 |
| Random Forest test accuracy | 100.00% (synthetic upper bound) |
| Logistic Regression test accuracy | 97.78% |
| Isolation Forest test attack F1 | 60.24%; ROC-AUC 79.24%; threshold -0.045324 |
| Scenario count | 100 (90 attacks, 10 benign) |
| Scenario detection precision/recall | 100.00% / 100.00% |
| Baseline classification accuracy | 90.00% |
| Agentic classification accuracy | 100.00% |
| McNemar exact p | 0.001953 |
| MITRE micro F1 (60 eligible) | 100.00% |
| Incident correlation | 100/100 |
| Approval gate | 90/90 |
| Key action coverage | 90/90 |
| Allowlist compliance | 100.00% |
| Simulation compliance | 100.00% |
| Verification | 90/90 |
| Executed action records | 390 |
| Simulated action records | 390 |
| Non-simulated action records | 0 |
| Unauthorized executions | 0 |
| Audit chain valid | 100/100 |

### 2.2 Risk and latency

Risk (n = 90): mean 60.33, min 49.95, max 76.75; HIGH 80, CRITICAL 10.

| Stage | n | Mean (ms) | Median (ms) | p95 (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|
| Ingestion | 100 | 173.76 | 118.71 | 546.27 | 622.76 |
| Investigation | 90 | 279.15 | 273.39 | 361.68 | 1101.15 |
| Response | 90 | 216.27 | 227.14 | 290.65 | 319.11 |
| Total | 100 | 717.11 | 741.83 | 1240.09 | 1506.70 |

### 2.3 Reproducibility controls

- Synthetic ML and scenario data use a fixed anchor timestamp (`DATASET_ANCHOR`), so the `hour` feature and event times do not depend on the date of the run.
- Isolation Forest threshold selection uses `n_jobs=1`, making the threshold bit-for-bit reproducible across repeated runs.
- The scenario benchmark uses a fresh temporary SQLite database per scenario for both arms.
- LLM mode is deterministic (`DEMO_TEMPLATE`); TI mock data is deterministic for documentation-range IPs.
- Two consecutive `train_model.py` runs during development produced identical Isolation Forest threshold and F1 (`-0.045324`, `0.6024`).

Latency is intentionally not claimed as reproducible; wall-clock timing varies with host load.

### 2.4 Known interpretation constraints

- The Random Forest's 100% is an artifact of separable template-generated features. It is not real-world accuracy.
- The Isolation Forest model is fitted without labels, but its threshold is selected on a labelled validation split. Call it **threshold-calibrated**, not fully unsupervised.
- MITRE ground truth is project-defined, not independent expert annotation.
- ML was disabled in the scenario benchmark for both arms.
- No live LLM was configured.
- No live threat-intelligence keys were configured.

## 3. End-to-end demo

Command:

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Measured output:

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

Verification checks recorded in `results/reports/demo_run.json`:

| Check | Passed | Detail |
|---|---|---|
| `actions_recorded` | yes | 6 response action records found |
| `approved_actions_executed` | yes | 6/6 executable actions executed |
| `simulation_effects_recorded` | yes | every executed simulated action records no effect |
| `advisory_not_executed` | yes | 0 advisory actions remained non-executed |
| `audit_trail_present` | yes | 7 execution/approval audit entries |
| `no_unresolved_actions` | yes | 0 unresolved executable actions |

The demo used a disposable database and disposable credentials. The credentials file `data/demo_credentials.json` is local and git-ignored.

## 4. API and dashboard runtime checks

A real Uvicorn process was started against `data/demo.db` on port 8010. A real Streamlit process was started on port 8511 with `SOC_API_URL=http://127.0.0.1:8010`.

Measured:

```text
API health: {"status":"ok","database":"ok","version":"1.0.0",
"llm":"DEMO_TEMPLATE","threat_intel":"DEMO_MOCK","simulation_mode":true,
"database_latency_ms":1.07,
"detection":{"rule_engine":"ready","ml_anomaly_detector":"ready",
"ml_model_dataset":"synthetic_demo_data"}}

API login: user=demo_admin role=admin expires_in=7200
API metrics: {"incidents":1,"events":9,"alerts":5,
"unresolved_incidents":0,"pending_approvals":0,"verified_incidents":1,
"executed_response_actions":6,"pending_response_actions":0}
API docs HTTP: 200
Dashboard HTTP: 200; bytes=6463
```

This confirms:

- the API starts and connects to SQLite;
- the ML artifact loads;
- `/health` reports `ok`;
- a real login returns a JWT;
- protected metrics are readable with the token;
- Swagger UI is served;
- Streamlit serves its page and can be pointed at the API.

Dashboard login was also exercised through the API using the same credential. A full browser automation test (click-through of every tab) was **NOT MEASURED**; the dashboard was validated by server startup, HTTP 200 and login/API calls.

## 5. Repository and artifact checks

| Check | Result |
|---|---|
| `git status` contains no database, credential, model or generated result | yes (runtime artifacts are git-ignored) |
| No hard-coded demo password in source | yes |
| `.env` ignored | yes |
| `data/.secret_key` ignored | yes |
| `data/*.db` ignored | yes |
| `models/*.joblib` ignored | yes |
| `results/*.json`, `*.csv`, `*.md`, `*.log` ignored | yes |
| README documents simulation-only behavior | yes |
| AGENTS.md documents safety invariants | yes |
| Paper and docs use only measured values | yes |
| Unmeasured experiments marked `NOT MEASURED` | yes |

## 6. Final verdict

| Area | Status |
|---|---|
| Install and import | PASS |
| Database schema and seed | PASS |
| Detection and normalization | PASS |
| ML training, artifact load and evaluation | PASS |
| LangGraph investigation | PASS |
| Evidence, TI, MITRE and risk | PASS |
| Approval gate | PASS |
| Simulated execution and verification | PASS |
| Audit chain | PASS |
| API authentication and roles | PASS |
| Dashboard startup | PASS |
| Full test suite | PASS (84/84) |
| Full evaluation | PASS (artifacts generated) |
| End-to-end demo | PASS (VERIFIED) |
| Real production readiness | **NOT CLAIMED** |
| Real-world detection performance | **NOT MEASURED** |
| Live LLM performance | **NOT MEASURED** |
| Live threat-intelligence performance | **NOT MEASURED** |
| Risk-score calibration | **NOT MEASURED** |

The project is complete and runnable as an academic prototype. The measured results support claims about the implemented pipeline and its behavior on synthetic data only.
