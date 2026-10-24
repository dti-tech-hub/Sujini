# Viva and demonstration guide

This guide contains a demonstration script and answers that match the code in this repository. Quote only the measured values below; do not invent accuracy, response-time improvements or live-provider results.

## 1. Fact sheet

| Item | Value |
|---|---|
| Project | AI Agent-Based Automated Cybersecurity Incident Response System |
| Scope | Web-application security incidents |
| Pipeline | Events -> detection -> investigation -> evidence -> TI -> MITRE -> risk -> response -> approval -> audit |
| Orchestration | LangGraph, two graphs (investigation and response) |
| API | FastAPI + Pydantic v2 + JWT + role-based access |
| Database | SQLAlchemy 2.x, SQLite by default (any SQLAlchemy URL supported) |
| Dashboard | Streamlit client over the API |
| LLM in measured run | `DEMO_TEMPLATE` (deterministic, not a hosted model) |
| Threat intelligence in measured run | `DEMO_MOCK` / `NO_EXTERNAL_LOOKUP` |
| Response effects | `SIMULATION` only |
| Tests | 84 passed, 1 upstream Starlette warning |
| Demo result | `INC-0001`, `account_compromise` 0.97, risk 90.21 CRITICAL, 6/6 simulated actions, `VERIFIED`, audit chain valid (41 entries) |
| Evaluation | 4,200 synthetic events, 100 synthetic scenarios, seed 42 |

Measured caveat: the Random Forest's 100% test accuracy is an artifact of separable synthetic features, not real-world performance. The Isolation Forest threshold was calibrated on a labelled validation split, so it is not a fully unsupervised result.

## 2. Five-minute demonstration script

### Minute 1 — frame the problem

> "Web applications produce many low-level events. A SOC analyst has to decide which events form an incident, collect evidence, check reputation, map the behavior to ATT&CK, assess risk, and choose a safe response. This project automates that workflow while keeping the dangerous decisions deterministic and human-approved."

State the safety boundary immediately:

> "No real firewall, session, credential or host is changed. Every response is simulated. The LLM is advisory and cannot choose or execute an action."

### Minute 2 — run the demo

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Point at the output:

- five failed logins, a success, a SQL-injection-shaped admin request and prompt-injection text become one correlated incident;
- classification `account_compromise`, confidence 0.97;
- MITRE `T1078`, `T1110`, `T1190`;
- risk 90.21, CRITICAL;
- status is `AWAITING_APPROVAL` before the human decision;
- after approval, six simulated actions execute and verification passes;
- the audit hash chain is valid.

### Minute 3 — show the evidence in the dashboard

Start the API and dashboard (see `docs/DEMO.md`), sign in as analyst/admin, open `INC-0001`, and walk the tabs:

1. **Summary** — classification, confidence, deterministic reasoning, mode labels.
2. **Timeline** — failures, success, malicious request, agent stages, approval and execution in order.
3. **Evidence** — weighted records, including the prompt-injection containment note.
4. **Threat intel** — provider, verdict, `is_mock`, and `DEMO_MOCK` label.
5. **MITRE** — technique, tactic, confidence, `confirmed`/`candidate` status.
6. **Risk** — every factor with raw value, normalized value, weight and contribution.
7. **Response** — auto, approval-gated and advisory actions with status.
8. **Approval** — approver, decision, reason, timestamp.
9. **Audit** — hash chain and verification.

### Minute 4 — explain the safety design

> "Three independent controls prevent unsafe automation: deterministic classification and policy are authoritative; the executor independently re-checks the allowlist, simulation mode and approval state; and HIGH/CRITICAL incidents cannot execute before an analyst or admin approves. LLM output is schema-validated but never wired to an action."

### Minute 5 — evaluation and limitations

Quote the measured results, then immediately state their scope:

> "On 100 synthetic scenarios the rule-only baseline classified 90% correctly and the agentic pipeline 100%; McNemar exact p = 0.001953. MITRE matched project-defined ground truth on all 60 eligible scenarios, and all 390 action records were simulated. These are synthetic, project-defined results. There was no live LLM, no live threat-intelligence key and no real containment, so I do not claim real-world accuracy."

## 3. Likely questions and answers

### Q1. Why "AI agents" rather than a single script?

The workflow has genuinely different responsibilities: evidence collection, triage, enrichment, mapping, risk, response planning and verification. Each is a node in a LangGraph state graph with its own output, duration and audit record. This makes the reasoning inspectable and lets each stage fail or fall back independently. The agents are not decorative: deterministic triage, policy and the executor are separate authorities, and the LLM cannot act.

### Q2. Why LangGraph?

It gives an explicit, typed, serializable state and a visible graph rather than an opaque chain of calls. Node boundaries make per-stage audit and timing natural. It also supports the two-phase design: investigation ends at a durable approval gate, and execution is a separate graph invoked only after approval. A long-running human-in-the-loop process would be harder to audit and would not survive a restart.

### Q3. Why FastAPI?

Pydantic v2 models provide request/response validation and OpenAPI generation; dependency injection keeps routes thin over `SocService`; and `TestClient` lets the test suite exercise the real application against a temporary database. Swagger is available at `/docs`.

### Q4. Why include threat intelligence?

Reputation is useful context for prioritization, but it is not proof of an attack. The system accepts only IP indicators, never queries private or documentation ranges externally, labels mock results explicitly, surfaces conflicting providers, and keeps deterministic detection authoritative. Without keys it still runs and says `DEMO_MOCK` rather than pretending to have live data.

### Q5. Why MITRE ATT&CK?

It gives a shared vocabulary for behavior. The mapper uses a curated local catalog with base confidence, supporting evidence and a confirmed/candidate threshold. It deliberately avoids mappings the project cannot defend: `malicious_ip`, `abnormal_traffic` and `unauthorized_access` are excluded from accuracy because reputation, volume or a denial alone does not prove a technique. XSS maps to T1059.007 only as a candidate, because payload delivery does not prove execution.

### Q6. How is risk calculated?

A transparent weighted sum of seven normalized factors: severity 0.22, confidence 0.13, asset criticality 0.13, threat intelligence 0.16, event volume 0.08, attack impact 0.23 and recurrence 0.05. The score is `100 * sum(weight * factor)`. Thresholds are LOW <= 24, MEDIUM <= 49, HIGH <= 74, CRITICAL >= 75. Every factor's raw value, normalized value, weight and contribution is stored and shown in the dashboard. These are project parameters, not standards, and the score is not a calibrated probability.

### Q7. Why require human approval?

Containment actions can disrupt users and services, and the classifier can be wrong. HIGH and CRITICAL incidents therefore stop at `AWAITING_APPROVAL`; an authenticated analyst or admin must approve. The decision is durable in the database and audit-logged. Rejection requires a reason and prevents execution. This is a deliberate safety gate, not a UI formality: the executor refuses to run gated actions without approval.

### Q8. How is prompt injection handled?

Log content is treated as data, never as instructions. Normalization flags instruction-like patterns and records them as evidence. The LLM prompt puts event data inside an `UNTRUSTED_SECURITY_DATA` envelope and states that log text must not be followed. Output is parsed by a strict Pydantic schema with `extra="forbid"`, classification must be in an allowlist, and destructive-command patterns are rejected. The LLM has no tools and no execution path, so even a successful injection cannot select an action.

### Q9. How is LLM hallucination handled?

The LLM is advisory. Deterministic triage produces the authoritative classification and severity; policy produces the action plan; the executor enforces the allowlist. LLM text is validated, bounded and compared with the deterministic result. A disagreement is recorded but not obeyed. If the output is invalid or unavailable, the deterministic provider is used.

### Q10. What happens if the LLM fails or is not configured?

The system uses `DEMO_TEMPLATE`, a deterministic evidence-based summary. The API reports `LLM: DEMO_TEMPLATE`, so the mode is visible. No result is presented as a hosted-model result.

### Q11. What happens if threat intelligence fails?

A configured live provider failure falls back to the mock provider with mode `DEMO_MOCK_FALLBACK`, and provider errors are recorded. Private indicators return `NO_EXTERNAL_LOOKUP`; invalid indicators return `INVALID`. The incident still proceeds with a neutral TI factor, and the mode is shown in the dashboard and API.

### Q12. How are incidents correlated?

Alerts are attached to an open incident when they share the source IP or username within the correlation window (default 10 minutes). Nearby events with the same key are attached so the timeline includes context, not just alerting events. Severity uses the maximum observed rank, and category uses a deterministic priority. The initial category is provisional; evidence-driven triage can reclassify it.

### Q13. How is the system evaluated?

Two separate evaluations:

1. **Event-level ML** on 4,200 synthetic HTTP events (2,940 train / 1,260 test, seed 42) with Random Forest, Logistic Regression and Isolation Forest.
2. **Incident-level scenarios**: 100 scenarios, 10 per category, each run in a fresh SQLite database for both the rule-only baseline and the agentic pipeline. ML is disabled in both arms so the comparison isolates incident-level re-triage and policy.

The second evaluation also checks approval-gate correctness, allowlist and simulation compliance, verification and audit-chain validity, and measures latency.

### Q14. What exactly is the baseline?

The baseline is a rule-only queue: the earliest rule alert determines the incident category, with no correlation-driven re-triage. Both arms share the same rule stage and the same events. This is a realistic simple comparator, though a stateful rule engine with success-after-failure logic would be stronger.

### Q15. Why is the Random Forest 100%?

Because the synthetic classes are generated from templates with highly separable features such as status code, path length, scanner user agent and POST method. It is an upper bound, not evidence of real-world performance. The Isolation Forest result (attack F1 60.24%, ROC-AUC 79.24%, 24.64% test FPR) is more informative and is documented as too noisy for unassisted paging.

### Q16. How is reproducibility ensured?

Seed 42 for generation, split and models; a fixed dataset anchor timestamp so `hour` and event times do not depend on the run date; `n_jobs=1` for Isolation Forest threshold selection; a fresh SQLite database per scenario; deterministic mock TI and deterministic LLM templates. The generated report records Python version, platform, dependency-relevant environment and git commit. Wall-clock latency is explicitly not claimed as reproducible.

### Q17. How does the audit trail work?

Each audit row stores `entry_hash = SHA256(previous_hash + canonical_json(entry_without_hash))`. Verification recomputes the chain and reports the first mismatch. Tests modify an entry and confirm detection. Limitation: it detects edits and insertions inside the chain, but not tail truncation or a wholesale database replacement by someone with write access; there is no external anchor.

### Q18. What is simulated, exactly?

`SIMULATE_BLOCK_IP`, `SIMULATE_DISABLE_SESSION`, `SIMULATE_RESET_CREDENTIAL`, `SIMULATE_QUARANTINE` and the notification actions record an intended effect with `simulated: true`, `mode: SIMULATION` and `effect: "No real system was modified."` There is no `subprocess`, shell, `eval`, `exec` or network mutation in the response path. `simulation_mode=false` raises a policy error.

### Q19. What happens if an incident is rejected?

Execution is refused. The rejection, approver, timestamp and reason are persisted and audited. The incident remains rejected. A later execution attempt cannot bypass the state check.

### Q20. What are the main limitations?

Synthetic data; a small 100-scenario benchmark; template-separable ML features; project-defined MITRE ground truth; no ground-truth risk labels; no live LLM; no live threat-intelligence keys; no real containment; SQLite single-process deployment; in-memory rate limiting; audit chain without external anchoring; and no browser-automation test of every dashboard control. These are documented rather than hidden.

### Q21. What is novel here?

Not a new detection algorithm. The contribution is an integrated, inspectable pipeline that connects evidence correlation, advisory LLM enrichment, MITRE mapping, transparent risk, deterministic response policy, a durable human approval gate, simulation-only execution, verification and a tamper-evident audit trail, with a reproducible baseline comparison. The safety design (LLM as advisory, allowlist re-checked at execution, approval modeled as durable state) is the main engineering contribution.

### Q22. Why SQLite?

Zero setup for an academic demonstration and a single-process workload. The data layer uses SQLAlchemy, so a PostgreSQL URL can be supplied for concurrency. The report explicitly does not claim production throughput.

### Q23. What would production require?

TLS and network isolation; a concurrent database and migrations; external secret management; MFA/SSO and token revocation; a shared rate-limit store; signed or externally anchored audit logs; retention and privacy controls; real change-controlled integrations only if the organization explicitly requires them; and penetration/adversarial testing. None of these is claimed now.

### Q24. How do you know the dashboard works?

The API and Streamlit server were started for real, `/health` and `/docs` returned 200, a real login returned a JWT, protected metrics were read with it, and the dashboard returned HTTP 200. A full click-through browser automation of every tab was **NOT MEASURED**, and the guide says so.

### Q25. Are the datasets real?

No. All bundled data is `synthetic_demo_data`. No public dataset was downloaded or processed for the measured results, so the project does not claim CICIDS2017, UNSW-NB15 or any other external dataset. `scripts/import_dataset.py` exists for future dataset work, but no import is claimed.

## 4. Numbers you may quote

From the measured run recorded in `docs/EVALUATION.md` and `results/reports/evaluation_report.md`:

| Measure | Value |
|---|---|
| ML dataset | 4,200 events, 2,940/1,260 split, 14 features, seed 42 |
| Random Forest test accuracy | 100.00% (synthetic artifact) |
| Logistic Regression test accuracy | 97.78% |
| Isolation Forest attack F1 / ROC-AUC | 60.24% / 79.24% |
| Scenario detection precision / recall | 100.00% / 100.00% |
| Baseline / agentic classification accuracy | 90.00% / 100.00% |
| McNemar exact p | 0.001953 |
| MITRE micro F1 (60 eligible) | 100.00% |
| Approval gate | 90/90 |
| Simulated action records | 390/390 |
| Unauthorized executions | 0 |
| Audit chain valid | 100/100 scenarios |
| Demo final status | `VERIFIED`, 41-entry valid chain |

Always add: synthetic data, deterministic LLM template, mock/no-lookup threat intelligence, simulation-only response.

## 5. Things not to claim

- Do not say the system detected a real attack or blocked a real IP.
- Do not say the LLM performed the classification or chose the response.
- Do not present 100% Random Forest accuracy as real-world performance.
- Do not say threat intelligence was live.
- Do not say MITRE mappings were validated by independent experts.
- Do not claim risk-score calibration or predictive accuracy.
- Do not claim production readiness, SLA, throughput or resistance to a determined attacker.
- Do not claim a public dataset was used.

## 6. Recovery during a live demo

| Problem | Recovery |
|---|---|
| Demo fails on a stale database | Delete `data/demo.db` and rerun; the demo creates a disposable database. |
| Model artifact missing | Run `scripts/train_model.py`; detection still works with the ML signal unavailable. |
| Dashboard cannot reach API | Check `SOC_API_URL`, the API port and that both processes use the same database URL. |
| Login fails | Re-run `scripts/seed_database.py`; read the generated credentials from the console or `data/demo_credentials.json`. |
| Risk score differs from this guide | Expected: the demo uses the current timestamp and a fresh recurrence count. Read the actual score and explain the formula. |
| A tab is empty | That stage may not have run for the selected incident; use the demo incident or investigate first. |
| Evaluation takes too long | Show the committed report and run `scripts/evaluate.py --samples 1200 --per-class 5` only if asked; label it a smaller run, not the reported benchmark. |

Keep the demonstration honest. A correct explanation of a limitation is stronger than an inflated claim.
