# Setup and operation guide

## 1. Requirements

- Windows 10/11 with PowerShell (the measured environment was Windows 11, build 26200).
- Python 3.11 or newer (measured: 3.14.5).
- Approximately 500 MB free disk space for the virtual environment, model artifact and databases.
- No external database, cloud account, API key or GPU is required.

The project was run with these measured package versions:

| Package | Version |
|---|---|
| numpy | 2.4.4 |
| pandas | 3.0.1 |
| scikit-learn | 1.8.0 |
| joblib | 1.5.3 |

`requirements.txt` uses compatible lower bounds, so a fresh install may resolve newer versions. Record the versions if you re-run the evaluation.

## 2. Installation

```powershell
cd B:\sujini
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use the interpreter directly if script execution policy blocks `Activate.ps1`. Global `pip.exe` is restricted on the development machine; always prefer `.\.venv\Scripts\python.exe -m pip`.

## 3. Configuration

Defaults are in `config/config.yaml`; secrets and deployment overrides belong in `.env` (copy `.env.example`).

```powershell
Copy-Item .env.example .env
```

Important settings:

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///data/soc.db` | Any SQLAlchemy URL; SQLite is the zero-setup default |
| `SOC_SECRET_KEY` | generated | JWT signing secret; if empty, `data/.secret_key` is created locally |
| `SOC_ADMIN_PASSWORD` | generated | Admin password for seeding; minimum 12 characters |
| `SOC_ANALYST_PASSWORD` | generated | Analyst password for seeding |
| `SOC_VIEWER_PASSWORD` | generated | Viewer password for seeding |
| `VIRUSTOTAL_API_KEY` | empty | Optional live TI provider |
| `ABUSEIPDB_API_KEY` | empty | Optional live TI provider |
| `THREAT_INTEL_ALLOW_MOCK_FALLBACK` | `true` | Allow clearly labelled mock fallback |
| `LLM_ENABLED` | `false` | Enable optional OpenAI-compatible enrichment |
| `LLM_API_KEY` | empty | Key for the configured endpoint |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `API_BASE_URL` | `http://127.0.0.1:8000` | Convenience value for clients |
| `CORS_ORIGINS` | localhost:8501 | Comma-separated allowed dashboard origins |
| `SOC_API_URL` | `http://127.0.0.1:8000` | Dashboard-to-API base URL (dashboard process) |

Behavioral thresholds, risk weights, MITRE mapping and response policy are in the YAML files under `config/`. Every threshold is a project parameter, not a universal security standard.

### SQLite

The default database file is `data/soc.db`. SQLite is suitable for a single-process academic demonstration. Do not run multiple Uvicorn workers against the same SQLite file under load; use PostgreSQL (or another SQLAlchemy URL) for concurrency.

### Live threat intelligence (optional)

Set `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY`. Private and documentation-range indicators are never sent live. Without keys, records are labelled `DEMO_MOCK` (public indicators), `NO_EXTERNAL_LOOKUP` (private indicators) or `DEMO_MOCK_FALLBACK` (live failure).

### Live LLM (optional)

```dotenv
LLM_ENABLED=true
LLM_API_KEY=...
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_TIMEOUT_SECONDS=25
```

The provider must implement an OpenAI-compatible `/chat/completions` endpoint. Output is parsed with a strict Pydantic schema; invalid output falls back to deterministic templates. The LLM cannot execute actions or override the deterministic classification.

To run without keys, leave `LLM_ENABLED=false`. The mode is reported as `DEMO_TEMPLATE`.

## 4. Initialize the database and users

```powershell
.\.venv\Scripts\python.exe scripts\seed_database.py
```

The script:

- creates the SQLite schema;
- creates `admin`, `analyst` and `viewer` if they do not exist;
- uses passwords from `SOC_*_PASSWORD` if set, otherwise generates 24-character random passwords;
- prints credentials once and writes generated values to `data/credentials.json`;
- appends a `USERS_SEEDED` audit entry.

To reset a SQLite database:

```powershell
.\.venv\Scripts\python.exe scripts\seed_database.py --reset
```

`--reset` is restricted to SQLite paths and refuses unexpected filenames.

## 5. Train the anomaly model

```powershell
.\.venv\Scripts\python.exe scripts\train_model.py
```

This trains Random Forest, Logistic Regression and Isolation Forest on 4,200 synthetic events, writes the runtime artifact to `models/anomaly_iforest.joblib`, and writes metrics to `results/metrics/`. The artifact is intentionally git-ignored and must be regenerated after a fresh clone.

If the artifact is absent, the API still runs; `/health` reports the ML detector as unavailable and deterministic rules continue to work.

## 6. Run the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected shape:

```json
{
  "status": "ok",
  "database": "ok",
  "version": "1.0.0",
  "llm": "DEMO_TEMPLATE",
  "threat_intel": "DEMO_MOCK",
  "simulation_mode": true,
  "database_latency_ms": 1.07
}
```

Interactive API documentation is at <http://127.0.0.1:8000/docs>.

If port 8000 is occupied, use another port and set `SOC_API_URL` for the dashboard:

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8010
$env:SOC_API_URL = "http://127.0.0.1:8010"
```

## 7. Run the dashboard

In a second terminal:

```powershell
$env:SOC_API_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Streamlit prints the local URL (normally <http://127.0.0.1:8501>). Sign in with an account from `data/credentials.json` or the disposable `demo_admin` from `scripts/run_demo.py`.

Dashboard behavior by role:

| Role | Read | Investigate | Approve / reject / execute |
|---|---|---|---|
| `viewer` | yes | no | no |
| `analyst` | yes | yes | yes |
| `admin` | yes | yes | yes |

## 8. Run the end-to-end demo

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

The script uses FastAPI `TestClient`, so no server is needed. It resets `data/demo.db`, creates a `demo_admin` account, logs in through the real API, ingests the labelled synthetic scenario, investigates, stops at approval, approves, executes, verifies and checks the audit chain.

Expected final lines:

```text
Classification        : account_compromise (confidence 0.97)
Risk                  : 90.21 / 100 -> CRITICAL
Status after agent    : AWAITING_APPROVAL (approval_required=True)
MITRE techniques      : T1078, T1110, T1190
Evidence records      : 16
Executed actions      : 6 (6 simulated)
Verification          : PASSED
Final status          : VERIFIED
Audit hash chain      : VALID
```

The result is also written to `results/reports/demo_run.json`. Demo credentials are written to `data/demo_credentials.json`; delete them after use.

### WinError 32 while resetting the demo database

If a previous API or dashboard process still has `data/demo.db` open, stop it before running the demo. On Windows, SQLite locks the file while the process is alive. Identify the process:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'uvicorn|streamlit' }
```

Stop only the process you started, then rerun. Do not kill unrelated services.

## 9. Manual API walkthrough

```powershell
$login = Invoke-RestMethod -Uri http://127.0.0.1:8000/auth/login `
  -Method Post -ContentType 'application/json' `
  -Body (@{ username='admin'; password='REPLACE_ME' } | ConvertTo-Json)

$headers = @{ Authorization = "Bearer $($login.access_token)" }

$event = @{
  timestamp    = (Get-Date).ToUniversalTime().ToString('o')
  source_ip    = '198.51.100.77'
  destination  = "/login"
  method       = 'POST'
  status_code  = 401
  username     = 'admin'
  event_type   = 'failed_login'
  message      = 'Invalid password'
  dataset_label = 'synthetic_demo_data'
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:8000/api/events `
  -Method Post -Headers $headers -ContentType 'application/json' -Body $event

Invoke-RestMethod -Uri http://127.0.0.1:8000/api/incidents -Headers $headers
```

Then investigate, approve and execute using the incident ID:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/INC-0001/investigate" -Method Post -Headers $headers
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/INC-0001/approve" -Method Post -Headers $headers `
  -ContentType 'application/json' -Body (@{ reason='Reviewed evidence; simulation approved.' } | ConvertTo-Json)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/INC-0001/execute" -Method Post -Headers $headers
```

Use the admin-only demo endpoint for the complete synthetic scenario:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/demo/scenario?auto_investigate=true" -Method Post -Headers $headers
```

## 10. Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Optional coverage:

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=src --cov-report=term-missing
```

Tests use temporary SQLite databases and disable API rate limiting. They do not call external threat-intelligence or LLM services.

## 11. Full evaluation

```powershell
.\.venv\Scripts\python.exe scripts\evaluate.py
```

Optional arguments:

```text
--samples 4200        synthetic ML events
--per-class 10        scenarios per category
--seed 42
--skip-ml
--skip-scenarios
--keep-temp           keep per-scenario SQLite databases
--quiet
```

Outputs:

- `results/metrics/ml_metrics.json`
- `results/metrics/scenario_metrics.json`
- `results/metrics/scenario_results.csv`
- `results/metrics/summary.json`
- `results/figures/*.png`
- `results/reports/evaluation_report.md`
- `models/anomaly_iforest.joblib`

The final measured run took about two minutes on the development host. Use `results/evaluation_run.log` to inspect the full run.

## 12. Resetting and cleaning

```powershell
# recreate local users and schema (SQLite only)
.\.venv\Scripts\python.exe scripts\seed_database.py --reset

# reset the demo database
Remove-Item data\demo.db* -Force
.\.venv\Scripts\python.exe scripts\run_demo.py

# regenerate all measured artifacts
.\.venv\Scripts\python.exe scripts\evaluate.py
```

Never commit `data/*.db`, `data/.secret_key`, `data/*credentials*.json`, `models/*.joblib`, logs or generated results. They are already ignored by `.gitignore`.

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: src` | Running from another directory | Run from the repository root or use the provided scripts |
| `WinError 32` on demo DB | API/dashboard still holds SQLite file | Stop the process using `data/demo.db` |
| Port already in use | Another service on 8000/8501 | Use another port; update `SOC_API_URL` |
| `401 Authentication required` | Missing/expired token | Log in again; tokens expire after 120 minutes |
| `403 Requires one of roles` | Viewer attempted a write/approve | Use analyst/admin |
| `/health` reports ML unavailable | Artifact missing or incompatible | Run `scripts/train_model.py` |
| TI mode is `DEMO_MOCK` | No live keys configured | Expected; labelled mock data |
| LLM mode is `DEMO_TEMPLATE` | `LLM_ENABLED=false` or no key | Expected; deterministic templates |
| `PolicyError: Real response execution is disabled` | `simulation_mode=false` attempted | Keep simulation mode enabled |
| API returns 429 | Rate limit exceeded | Wait for the window or use a test app with rate limiting disabled |
| Streamlit cannot reach API | Wrong `SOC_API_URL` or API down | Check the URL and `/health` |
| Test warning about `HTTP_422_UNPROCESSABLE_ENTITY` | Starlette deprecation | Harmless; upstream issue |

## 14. Production hardening checklist (not implemented)

This is an academic prototype. Before any real deployment you would need:

- a production database and migration tool (for example PostgreSQL + Alembic);
- external secret management and key rotation;
- TLS termination and network isolation;
- a shared rate-limit store;
- SSO/MFA and stronger authorization review;
- signed or externally anchored audit logs;
- real, reviewed response integrations with change control;
- privacy/legal review for log retention;
- load, failure-injection and adversarial testing;
- a proper incident-response runbook and human oversight process.
