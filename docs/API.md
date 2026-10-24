# API reference

Base URL in local development: `http://127.0.0.1:8000`. Interactive OpenAPI documentation is served at `/docs`, ReDoc at `/redoc`, and the schema at `/openapi.json`.

All timestamps are ISO-8601 UTC strings. All responses are JSON. Request bodies are limited to 5 MB. Rate limiting defaults to 120 requests per 60 seconds per client, plus a separate 10-per-60-second login limit.

## 1. Authentication and roles

### Login

```http
POST /auth/login
Content-Type: application/json

{"username": "admin", "password": "..."}
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 7200,
  "user": {
    "id": "...",
    "username": "admin",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-10-22T01:00:00+00:00",
    "last_login_at": "2026-10-22T01:05:00+00:00"
  }
}
```

Use the token in every protected request:

```http
Authorization: Bearer <access_token>
```

| Role | Read | Ingest / investigate | Approve / reject / execute | Audit log | Demo scenario |
|---|---|---|---|---|---|
| `viewer` | yes | no | no | no | no |
| `analyst` | yes | yes | yes | yes | no |
| `admin` | yes | yes | yes | yes | yes |

A failed login is audited as `LOGIN_FAILED` with `outcome=DENIED`. A successful login is audited as `LOGIN_SUCCESS`.

### Current user

```http
GET /auth/me
```

Returns the same user object shown above.

## 2. System endpoints

### Health

```http
GET /health
```

```json
{
  "status": "ok",
  "database": "ok",
  "version": "1.0.0",
  "llm": "DEMO_TEMPLATE",
  "threat_intel": "DEMO_MOCK",
  "simulation_mode": true,
  "timestamp": "2026-10-22T01:28:58.757620+00:00",
  "database_latency_ms": 1.07,
  "detection": {
    "rule_engine": "ready",
    "ml_anomaly_detector": "ready",
    "ml_model_dataset": "synthetic_demo_data"
  }
}
```

`GET /` returns the application name, version, docs/health paths and `simulation_only: true`.

## 3. Event ingestion

### Ingest one event

```http
POST /api/events
Authorization: Bearer <analyst-or-admin-token>
Content-Type: application/json
```

Minimal example:

```json
{
  "timestamp": "2026-10-22T01:00:00Z",
  "source_ip": "198.51.100.77",
  "destination": "/login",
  "method": "POST",
  "status_code": 401,
  "username": "admin",
  "event_type": "failed_login",
  "message": "Invalid password supplied",
  "user_agent": "Mozilla/5.0 DemoBrowser/1.0",
  "dataset_label": "synthetic_demo_data"
}
```

Raw combined-log example:

```json
{
  "line": "198.51.100.77 - - [22/Oct/2026:01:00:00 +0000] \"GET /products?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.7\""
}
```

Response (abridged):

```json
{
  "event": {
    "id": "...",
    "timestamp": "2026-10-22T01:00:00+00:00",
    "source_ip": "198.51.100.77",
    "username": "admin",
    "method": "POST",
    "endpoint": "/login",
    "status_code": 401,
    "event_type": "failed_login",
    "severity": "LOW",
    "dataset_label": "synthetic_demo_data",
    "incident_id": "INC-0001"
  },
  "duplicate": false,
  "alerts": [],
  "alerts_created": 0,
  "incident_id": "INC-0001",
  "incident_created": true,
  "ml": null,
  "normalization_warnings": []
}
```

`dataset_label` is a provenance label, not a model target. Use `synthetic_demo_data` for demonstrations.

### Ingest a batch

```http
POST /api/events/batch
```

```json
{
  "events": [
    {"source_ip": "198.51.100.77", "destination": "/login", "status_code": 401, "event_type": "failed_login"},
    {"source_ip": "198.51.100.77", "destination": "/products", "status_code": 200}
  ]
}
```

Maximum 500 events per batch. Response contains `submitted`, `ingested`, `duplicates`, `alerts_created`, `incidents`, per-event results and optional investigations.

### Alert-shaped ingestion

```http
POST /api/alerts
```

Uses the same event envelope but sets `source="security_alert"`. Useful for SIEM-forwarded alerts.

### List events

```http
GET /api/events?limit=100&offset=0&event_type=failed_login&severity=LOW&source_ip=198.51.100.77&incident_id=INC-0001
```

Filters: `event_type`, `severity`, `source_ip`, `incident_id`. `limit` is 1–500.

### List alerts

```http
GET /api/alerts?limit=100&offset=0&severity=HIGH&incident_id=INC-0001
```

Response shape: `{"items": [...], "count": n, "limit": n, "offset": n}`.

### Bulk log import

`scripts/import_logs.py` reads Apache/Nginx combined logs, JSONL or CSV and submits them through the authenticated batch API. It never writes the database directly and never executes log content.

```powershell
.\.venv\Scripts\python.exe scripts\import_logs.py --file access.log --format clf `
  --username admin --dataset-label synthetic_demo_data
```

The password is prompted interactively unless `--password` is supplied. `--dry-run` parses and counts without sending; `--batch-size` defaults to 100. CSV headers must use the same field aliases accepted by `POST /api/events`.

## 4. Incidents

### Create an incident manually

```http
POST /api/incidents
Authorization: Bearer <analyst-or-admin-token>
```

```json
{
  "title": "Suspicious admin access",
  "description": "Manually opened for review",
  "severity": "HIGH",
  "attack_category": "suspicious_activity",
  "source_ip": "198.51.100.77",
  "username": "admin"
}
```

### List incidents

```http
GET /api/incidents?limit=100&offset=0&status=AWAITING_APPROVAL&severity=CRITICAL&category=account_compromise&source_ip=198.51.100.77&approval_status=PENDING
```

### Incident detail

```http
GET /api/incidents/{incident_id}
```

Returns:

```json
{
  "incident": {},
  "events": [],
  "alerts": [],
  "evidence": [],
  "threat_intelligence": [],
  "mitre": [],
  "risk": {},
  "risk_history": [],
  "response": {"actions": [], "approval_required": true, "approval_status": "PENDING", "status": "AWAITING_APPROVAL"},
  "approvals": [],
  "timeline": [],
  "agent_runs": [],
  "audit": [],
  "system": {"llm_mode": "DEMO_TEMPLATE", "threat_intel_mode": "DEMO_MOCK", "simulation_only": true}
}
```

### Investigate

```http
POST /api/incidents/{incident_id}/investigate
Authorization: Bearer <analyst-or-admin-token>
```

Allowed from statuses `NEW`, `TRIAGED`, `INVESTIGATING` or `FAILED`. Runs the LangGraph investigation. If policy does not require approval, the service immediately runs the response graph and verifies it. HIGH/CRITICAL incidents stop at `AWAITING_APPROVAL`.

Response (abridged):

```json
{
  "incident_id": "INC-0001",
  "status": "AWAITING_APPROVAL",
  "approval_required": true,
  "approval_status": "PENDING",
  "risk_score": 90.21,
  "severity": "CRITICAL",
  "classification": "account_compromise",
  "confidence": 0.97,
  "llm_mode": "DEMO_TEMPLATE",
  "threat_intel_mode": "DEMO_MOCK",
  "mitre_techniques": ["T1078", "T1110", "T1190"],
  "evidence_count": 16,
  "auto_executed": false,
  "verification": null,
  "incident": {}
}
```

### Timeline, evidence, TI, MITRE, risk

| Endpoint | Response |
|---|---|
| `GET /api/incidents/{id}/timeline` | `{"incident_id", "items", "count"}` |
| `GET /api/incidents/{id}/evidence` | `{"incident_id", "items", "count"}` |
| `GET /api/incidents/{id}/threat-intel` | `{"incident_id", "items", "count"}` |
| `GET /api/incidents/{id}/mitre` | `{"incident_id", "items", "count"}` |
| `GET /api/incidents/{id}/risk` | `{"incident_id", "risk"}` (`risk` may be `null`) |

## 5. Response, approval and execution

### Read the response plan

```http
GET /api/incidents/{incident_id}/response
```

```json
{
  "incident_id": "INC-0001",
  "actions": [
    {
      "action_type": "SIMULATE_BLOCK_IP",
      "description": "... Target: source 198.51.100.77.",
      "risk_level": "CRITICAL",
      "requires_approval": true,
      "policy_mode": "approval",
      "status": "PENDING_APPROVAL",
      "is_simulated": true,
      "parameters": {"source_ip": "198.51.100.77", "simulation": true}
    }
  ],
  "approval_required": true,
  "approval_status": "PENDING",
  "status": "AWAITING_APPROVAL",
  "approvals": []
}
```

### Approve

```http
POST /api/incidents/{incident_id}/approve
Authorization: Bearer <analyst-or-admin-token>
```

```json
{
  "reason": "Reviewed evidence; simulation-only containment approved.",
  "action_ids": null
}
```

`action_ids` may be omitted to approve all approvable actions or provided to approve a subset. Approval records the approver and reason in the audit chain and sets the incident to `APPROVED`.

### Reject

```http
POST /api/incidents/{incident_id}/reject
```

```json
{"reason": "Insufficient evidence; tune the rule first.", "action_ids": null}
```

Rejection requires a reason of at least 3 characters. The incident becomes `REJECTED`; no response executes.

### Execute approved actions

```http
POST /api/incidents/{incident_id}/execute
Authorization: Bearer <analyst-or-admin-token>
```

Only valid for `APPROVED`/`CONTAINMENT` incidents. The executor:

- refuses if `simulation_mode=false`;
- re-checks the action allowlist;
- checks that every approval-gated action is approved;
- records `RESPONSE_ACTION_STARTED`, `RESPONSE_ACTION_EXECUTED` or `RESPONSE_ACTION_FAILED`;
- marks every result with `simulated: true` and `effect: "No real system was modified."`;
- sets the incident to `CONTAINMENT` or `FAILED`;
- runs verification and sets `VERIFIED` when all checks pass.

Response (abridged):

```json
{
  "incident_id": "INC-0001",
  "execution": {
    "executed": [],
    "failed": [],
    "all_succeeded": true
  },
  "verification": {
    "verified": true,
    "status": "VERIFIED",
    "checks": [
      {"name": "actions_recorded", "passed": true, "detail": "6 response action records found"},
      {"name": "approved_actions_executed", "passed": true, "detail": "6/6 executable actions executed"},
      {"name": "simulation_effects_recorded", "passed": true, "detail": "Every executed simulated action records its no-effect verification"},
      {"name": "advisory_not_executed", "passed": true, "detail": "0 advisory action(s) remain non-executed recommendations"},
      {"name": "audit_trail_present", "passed": true, "detail": "7 execution/approval audit entries found"},
      {"name": "no_unresolved_actions", "passed": true, "detail": "0 unresolved executable action(s)"}
    ],
    "audit_chain_valid": true
  },
  "incident": {}
}
```

## 6. Metrics and audit

### Metrics

```http
GET /api/metrics
```

Returns counts and chart-ready structures including:

- totals: events, alerts, incidents, pending approvals, verified incidents, executed actions;
- severity, status, category and source-IP distributions;
- 14-day timeseries;
- system mode summary (LLM, TI, simulation, ML);
- audit chain status.

This endpoint is read-only and available to viewers.

### System status

```http
GET /api/system
```

Returns system modes, audit validity and totals.

### Audit trail

```http
GET /api/audit?limit=100&offset=0&incident_id=INC-0001&action=RESPONSE_APPROVED
Authorization: Bearer <analyst-or-admin-token>
```

Each entry includes actor, role, action, entity, outcome, details, `previous_hash`, `entry_hash` and timestamp. Any authenticated reader can view incident-level audit entries through the incident detail; the dedicated audit endpoint is analyst/admin only.

## 7. Demo endpoints

### List scenarios

```http
GET /api/demo/scenarios
Authorization: Bearer <admin-token>
```

Returns the registered synthetic scenarios and their descriptions: `brute_force_account_compromise`, `xss_injection`, `unauthorized_access_attempts` and `benign_browsing`.

### Run a scenario

```http
POST /api/demo/scenario?scenario_name=xss_injection&auto_investigate=true
Authorization: Bearer <admin-token>
```

`scenario_name` defaults to `brute_force_account_compromise`. The default scenario ingests:

1. five failed logins;
2. a successful login;
3. an SQL-injection-shaped admin request;
4. admin audit access;
5. a prompt-injection log message.

`xss_injection` generates script-tag and event-handler requests. `unauthorized_access_attempts` generates repeated denials plus a privileged-endpoint denial. `benign_browsing` generates normal traffic and should not create an attack incident.

Returns the scenario name, `data_label`, ground truth, ingestion summary, investigation summary and full incident detail.

## 8. Error format

Domain errors:

```json
{
  "detail": "Incident INC-9999 not found",
  "code": "not_found",
  "request_id": "req_..."
}
```

Validation errors:

```json
{
  "detail": "Request validation failed",
  "errors": [
    {"loc": ["body", "events"], "msg": "List should have at least 1 item", "type": "too_short"}
  ],
  "request_id": "req_..."
}
```

Common status codes:

| Status | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Domain validation error |
| 401 | Missing/expired/invalid token |
| 403 | Role not permitted |
| 404 | Entity not found |
| 409 | Invalid state transition (for example, execute before approval) |
| 413 | Request larger than 5 MB |
| 422 | Pydantic validation failure |
| 429 | Rate limit exceeded |
| 500 | Internal error; details are logged, not returned |

Every response includes `X-Request-ID` and `X-Process-Time-ms`; security headers include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

## 9. cURL equivalents

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"REPLACE_ME"}' | jq -r .access_token)

curl -s http://127.0.0.1:8000/api/incidents -H "Authorization: Bearer $TOKEN"

curl -s -X POST http://127.0.0.1:8000/api/demo/scenario?auto_investigate=true \
  -H "Authorization: Bearer $TOKEN"
```

On Windows PowerShell, use `Invoke-RestMethod` as shown in [`SETUP.md`](SETUP.md).
