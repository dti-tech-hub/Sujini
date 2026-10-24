# An AI-Agent-Assisted Pipeline for Web Application Security Incident Response with Human-Approved, Simulation-Only Containment

**Project paper draft — B.Tech Computer Science and Engineering**

## Abstract

Web-application security operations require more than signature alerts: analysts must correlate low-level events into incidents, collect evidence, enrich indicators, map behavior to a shared taxonomy, assess risk, choose a proportionate response, and preserve an auditable record. This paper presents a runnable prototype that connects these stages in a two-phase LangGraph workflow. Deterministic normalization, signature rules, behavioural rules and an optional Isolation Forest produce alerts; incident correlation and weighted evidence support a deterministic triage stage; an advisory language-model layer produces structured explanations without authority over classification or action; local MITRE ATT&CK mapping and a transparent seven-factor risk model drive a policy-based response plan. HIGH and CRITICAL incidents stop at a durable human-approval gate, and all containment, remediation and notification effects are simulated. The executor independently re-checks the action allowlist, simulation mode and approval state, then verification confirms the recorded outcome. On a synthetic evaluation, the agentic pipeline classified 100/100 scenarios correctly versus 90/100 for a rule-only earliest-alert baseline (paired McNemar exact p = 0.001953), reproduced project-defined ATT&CK sets on all 60 eligible scenarios, executed 390/390 action records in simulation mode with zero unauthorized executions, and produced a valid audit chain for 100/100 scenarios. These results are limited to generated data, a deterministic LLM template and mock threat intelligence; no real-world detection or containment performance is claimed.

**Keywords:** incident response, security operations centre, AI agents, LangGraph, MITRE ATT&CK, threat intelligence, human-in-the-loop, simulation, audit trail

## 1. Introduction

Security operations centres (SOCs) face a volume and context problem. A web server can emit thousands of requests per minute, while the events that matter are often a short sequence: repeated authentication failures, a successful login, an unusual administrative request, and an attempt to manipulate the tooling that reads the logs. Turning that sequence into a tracked incident requires correlation, evidence, reputation context, behavioural classification, risk prioritisation and a controlled response.

NIST SP 800-61 describes incident response as a lifecycle of preparation, detection and analysis, containment, eradication, recovery and post-incident activity [1]. In practice, much of the analysis is manual and tool-specific. Recent work on large language models (LLMs) suggests that parts of the narrative and triage work can be assisted, but giving a generative model direct control of containment is unsafe: model output is non-deterministic, can be influenced by hostile input, and cannot be trusted to respect policy.

This paper asks a narrower engineering question: can a small, auditable agent pipeline improve incident-level classification and response discipline over a rule-only queue while keeping every safety-relevant decision deterministic and human-approved? The contributions are:

1. an end-to-end, runnable pipeline from event ingestion to hash-chained audit;
2. a two-phase LangGraph design in which the human approval decision is durable state rather than a long-running process;
3. a defence-in-depth treatment of untrusted log text and advisory LLM output;
4. a simulation-only response executor with independent allowlist, approval and simulation checks;
5. a reproducible evaluation that separates event-level ML metrics from incident-level policy metrics and reports a paired baseline comparison.

This is an academic prototype. It is not a production SOC product, and the evaluation uses synthetic data only.

## 2. Related work

Signature and rule-based detection remains the high-precision backbone of web-security monitoring, and the OWASP Top 10 documents the dominant web risk categories, including injection and broken access control [2]. Machine learning for intrusion detection has a long literature, but Sommer and Paxson caution that supervised results on separable benchmarks can fail to transfer to the open-world setting [3]. Random Forests [4] and Isolation Forest [5] are established baselines for supervised and unsupervised anomaly detection respectively. MITRE ATT&CK provides a curated vocabulary of adversary tactics and techniques [6]. NIST SP 800-61 provides the incident-response lifecycle used here [1].

Agent orchestration frameworks make multi-stage LLM workflows easier to express, but they do not by themselves provide policy enforcement. This work therefore uses an agent graph for stage decomposition and observability while keeping classification, risk and response policy in deterministic code.

## 3. System design

### 3.1 Architecture

```text
web logs / alerts
  -> normalization, sanitization, deduplication
  -> signature rules + behavioural rules + optional Isolation Forest
  -> alerts
  -> incident correlation (source IP / username / time window)
  -> evidence collection and timeline
  -> LangGraph investigation:
       evidence -> triage -> threat intelligence -> MITRE
                -> risk -> response plan -> approval gate
  -> human approval for HIGH / CRITICAL
  -> LangGraph response: simulated execute -> verify
  -> hash-chained audit -> FastAPI / Streamlit
```

The FastAPI service exposes ingestion, investigation, approval, execution, metrics and audit endpoints. The Streamlit dashboard is a thin client over the API. SQLite is the default store; any SQLAlchemy URL can be supplied.

### 3.2 Normalization and detection

Normalization maps heterogeneous field aliases, parses Apache/Nginx combined-log lines, validates IP addresses, sanitizes untrusted text, redacts secret-like values, bounds field sizes and computes a SHA-256 deduplication hash. A duplicate event is rejected and audited but can still attach to an existing incident.

Seven declarative signature rules cover SQL injection, cross-site scripting, command injection, path traversal, sensitive-path reconnaissance, scanner user agents and prompt-injection text. Six behavioural checks cover failed-login bursts, success-after-failure, request rate, server-error bursts, unauthorized-access attempts and a configured malicious-IP watchlist. Unauthorized access is detected as a burst of access denials (`ACCESS-001`) or an explicit denial on a privileged administrative endpoint (`ACCESS-002`). Failed-login and success-after-failure counters are scoped to authentication endpoints, so generic 401/403 responses do not inflate brute-force evidence. Rules are passive: captured payloads are never replayed or executed.

An optional Isolation Forest consumes 14 numeric HTTP features and contributes an additive anomaly alert. Deterministic rules remain authoritative; a missing or incompatible model artifact is reported rather than replaced.

### 3.3 Investigation graph and deterministic triage

The investigation graph has seven nodes: evidence collection, alert triage, threat intelligence, MITRE mapping, risk assessment, response planning and the approval gate. Each node records duration, provider and outcome in an `agent_runs` table and writes an audit entry. A failure is recorded and re-raised rather than swallowed.

The authoritative classifier is deterministic. It chooses a candidate category by precedence over alert types, starts from a per-category confidence, adds bounded corroboration for multiple alert types and high correlation confidence, and clamps confidence to [0.30, 0.97]. Severity is the maximum of the category default and observed alert severities. The reasoning string records the inputs to the decision.

### 3.4 Advisory LLM layer

The LLM is an optional provider behind an interface with a deterministic template implementation and an OpenAI-compatible implementation. The default is `DEMO_TEMPLATE`. The model cannot select actions and has no tools or execution path. Untrusted log text is serialized inside an `UNTRUSTED_SECURITY_DATA` envelope, with any delimiter occurrence neutralized. Output is parsed by a Pydantic schema with `extra="forbid"`; classification must be in the allowed set, confidence in [0, 1], list fields are bounded, and destructive-command patterns are rejected. A disagreement with deterministic triage is recorded, not obeyed.

### 3.5 Threat intelligence

Threat intelligence is scope-aware. Private and loopback indicators are not queried externally (`NO_EXTERNAL_LOOKUP`). Documentation ranges use deterministic labelled mock data (`DEMO_MOCK`). Public indicators use configured VirusTotal/AbuseIPDB providers when keys exist (`LIVE`), otherwise labelled mock fallback. Provider failure falls back to `DEMO_MOCK_FALLBACK` with errors recorded. Conflicting verdicts are surfaced rather than averaged. Only IP indicators are accepted, which also bounds server-side request forgery risk.

### 3.6 MITRE ATT&CK mapping

The mapper derives behaviours from classification and alert types and matches a local catalog containing base confidence, tactics, rationale and triggers. Corroboration adds 0.02 per evidence item, capped at four. Investigation confidence below 0.60 caps technique confidence at 0.70. A technique is `confirmed` at >= 0.75 and `candidate` otherwise. Cross-site scripting maps to T1059.007 only as a `candidate`, because delivery of a payload does not prove execution. Reputation-only, volume-only and authorization-only scenarios are excluded from accuracy claims.

### 3.7 Risk model

The risk score is a transparent weighted sum:

```text
score = 100 * sum_i (w_i * f_i)
```

with weights severity 0.22, investigation confidence 0.13, asset criticality 0.13, threat-intelligence reputation 0.16, event volume 0.08, attack impact 0.23 and recurrence 0.05. Each factor has an explicit normalization. Levels are LOW <= 24, MEDIUM <= 49, HIGH <= 74 and CRITICAL >= 75. Every assessment stores raw values, normalized values, weights and contributions, together with a readable explanation. These are project parameters, not standards, and the score is not a calibrated probability.

### 3.8 Response, approval and verification

Response planning selects actions from a YAML policy by risk level and category. LOW incidents record a notification. MEDIUM incidents notify and may recommend blocking as advisory. HIGH incidents require approval for block and session-disable actions. CRITICAL incidents also require approval for credential reset and quarantine. Category-specific actions are advisory at lower levels and approval-gated at HIGH/CRITICAL.

Approval is modeled as durable state:

```text
NEW -> INVESTIGATING -> AWAITING_APPROVAL (PENDING)
                           -> approve -> APPROVED -> CONTAINMENT -> VERIFIED
                           -> reject  -> REJECTED (audited, no execution)
```

Only an authenticated analyst or admin may decide. The approver, timestamp, decision and reason are persisted. Rejection requires a reason.

The executor independently checks that simulation mode is enabled, the incident is approved, no gated action is pending, and every action is in the allowlist. All actions are simulated and record `simulated: true`, `mode: SIMULATION` and an explicit no-effect result. No shell, `subprocess`, `eval`, `exec` or network-mutating call exists in the response path. Verification checks action records, execution status, simulation metadata, advisory non-execution, audit presence and unresolved actions before setting `VERIFIED`.

### 3.9 Audit chain

Audit rows are chained with:

```text
entry_hash = SHA256(previous_hash + canonical_json(entry_without_hash))
```

Verification recomputes the chain and reports the first mismatch. The design detects edits and insertions within the chain. It does not prevent tail truncation or replacement of the entire database by an actor with write access, and there is no external anchor.

## 4. Evaluation methodology

### 4.1 Event-level ML evaluation

The synthetic dataset contains 4,200 HTTP events with 14 numeric features and eight labels: benign, SQL injection, command injection, path traversal, brute force, reconnaissance, suspicious user agent and prompt-injection attempt. A stratified 70/30 split gives 2,940 training and 1,260 test events (seed 42). Random Forest uses 300 trees with balanced subsample weights. Logistic Regression uses standard scaling, balanced class weights and a maximum of 3,000 iterations. The Isolation Forest is fitted on benign training traffic only; its operating threshold is chosen on a labelled 20% validation split, never on the test split. A fixed dataset anchor timestamp and `n_jobs=1` make the split, features and threshold reproducible.

### 4.2 Incident-level scenario benchmark

One hundred synthetic scenarios are generated: ten each for brute force, account compromise, SQL injection, cross-site scripting, command injection, path traversal, unauthorized access, malicious IP, abnormal traffic and benign browsing. Each scenario runs in a fresh temporary SQLite database for both arms to prevent cross-scenario correlation.

Both arms share the same rule stage and the same events. The baseline is a rule-only queue: the earliest alert determines the incident category, with no contextual re-triage. The agentic arm runs evidence collection, deterministic re-triage, threat intelligence, MITRE mapping, risk scoring, response planning, the approval gate, simulated execution and verification. ML anomaly detection is disabled in both arms so the comparison isolates incident-level classification and policy; ML is measured separately.

### 4.3 Metrics

Detection is reported with precision, recall, F1, accuracy and Wilson 95% intervals. Classification is reported with accuracy, macro F1 and per-class F1, with McNemar's exact test for the paired comparison. MITRE is scored as micro precision/recall/F1 and exact-set match over eligible categories. Response evaluation checks approval-gate correctness, expected key-action coverage, allowlist compliance, simulation compliance, verification and unauthorized executions. Audit validity is checked per scenario. Latency is reported as mean, median, p95 and maximum wall-clock time per stage.

### 4.4 Reproducibility and ethics

All data is `synthetic_demo_data` and every response is simulated. No live LLM or live threat-intelligence key was configured for the measured run. Seeds, the dataset anchor, Isolation Forest `n_jobs=1`, per-scenario databases and deterministic mock/template modes are documented. Wall-clock latency is not claimed as reproducible.

## 5. Results

### 5.1 Event-level ML

| Model | Accuracy | Macro F1 | Attack F1 | Attack ROC-AUC |
|---|---:|---:|---:|---:|
| Random Forest | 100.00% | 100.00% | 100.00% | 100.00% |
| Logistic Regression | 97.78% | 97.37% | 96.33% | 99.34% |
| Isolation Forest (threshold-calibrated) | 73.49% (attack vs benign) | n/a | 60.24% | 79.24% |

The Random Forest score is an upper-bound artifact: the synthetic classes are template-generated and highly separable. It must not be read as real-world accuracy. The Isolation Forest's operating threshold is -0.045324; test attack precision is 53.49%, recall 68.94% and false-positive rate 24.64%. That false-positive rate is too high for unassisted paging and is treated as an additive signal only.

### 5.2 Detection and classification

| Measure | Rule-only baseline | Agentic pipeline |
|---|---:|---:|
| Detection precision | 100.00% | 100.00% |
| Detection recall | 100.00% | 100.00% |
| Classification accuracy | 90.00% | 100.00% |
| Classification macro F1 | 86.67% | 100.00% |

Both arms detected all 90 attack scenarios and none of the 10 benign scenarios. The baseline's only classification errors were the ten account-compromise scenarios, which the earliest-alert rule labelled `brute_force`; the agentic pipeline re-triaged them after evidence correlation. The paired McNemar exact two-sided p-value is 0.001953 over ten discordant pairs. This is valid for the generated sample but should not be extrapolated to enterprise traffic.

### 5.3 MITRE, correlation and policy

| Measure | Result |
|---|---:|
| Incident correlation | 100/100 (100.00%) |
| MITRE micro F1 (60 eligible scenarios) | 100.00% |
| MITRE exact-set match | 100.00% |
| Approval-gate correctness | 90/90 (100.00%) |
| Expected key action present | 90/90 (100.00%) |
| Response allowlist compliance | 100.00% |
| Simulation-only compliance | 100.00% |
| Verified incidents | 90/90 |
| Executed action records | 390 |
| Simulated action records | 390 |
| Non-simulated action records | 0 |
| Unauthorized executions | 0 |
| Audit-chain valid scenarios | 100/100 |

All attack scenarios reached HIGH or CRITICAL risk, so the approval gate applied to all 90. The benchmark verified that each incident was pending before approval and executed only afterwards. The MEDIUM/LOW auto-execution path was not exercised by these scenarios; it is covered by unit tests.

### 5.4 Risk scores

Risk scores (n = 90) have mean 60.33, minimum 49.95 and maximum 76.75; 80 are HIGH and 10 are CRITICAL. Account-compromise scenarios average 76.75 (CRITICAL), while abnormal-traffic scenarios average 49.95. These scores are deterministic for the fixed scenario composition. There are no ground-truth risk labels, so accuracy, calibration and discrimination are **NOT MEASURED**.

### 5.5 Latency

Wall-clock measurements from one local run on Windows 11 with SQLite:

| Stage | n | Mean (ms) | Median (ms) | p95 (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|
| Ingestion | 100 | 173.76 | 118.71 | 546.27 | 622.76 |
| Investigation | 90 | 279.15 | 273.39 | 361.68 | 1101.15 |
| Response | 90 | 216.27 | 227.14 | 290.65 | 319.11 |
| Total | 100 | 717.11 | 741.83 | 1240.09 | 1506.70 |

These values include Python orchestration, database I/O and audit hashing. They vary with host load and are not a production throughput or SLA claim.

### 5.6 End-to-end demonstration

The demonstration scenario comprises five failed logins, a successful login, a SQL-injection-shaped administrative request, an administrative audit access and prompt-injection text. The measured result is `account_compromise` with confidence 0.97, risk 90.21 (CRITICAL), techniques T1078/T1110/T1190, 16 evidence records, status `AWAITING_APPROVAL` before the analyst decision, six simulated actions after approval, verification passed and a valid 41-entry audit chain.

## 6. Discussion

The pipeline's value is not a new classifier. It is the connection between stages and the placement of trust boundaries. Deterministic triage makes the classification reproducible and auditable. The risk model exposes its arithmetic instead of hiding it in a learned score. Response policy is declarative and re-checked at execution. The approval gate is durable state, so a restart does not lose the decision and a human is not asked to keep a process alive. The LLM adds narrative value without authority. The audit chain provides tamper evidence for the record.

The baseline comparison isolates one meaningful effect: contextual re-triage corrects incidents whose first alert is not their best label. It does not show that agents improve detection, because both arms share detection. Nor does it show generalization, because the scenarios are synthetic and their ground truth is project-defined.

## 7. Limitations and threats to validity

- **Synthetic data.** The ML dataset and scenarios are generated, not captured. The benchmark is small (100 scenarios, 10 per class).
- **Circularity.** Scenarios, ground truth and heuristics share project assumptions; perfect scores may reflect that alignment.
- **Weak baseline.** A stateful rule engine with success-after-failure logic would narrow the classification gap.
- **No live LLM.** Results describe deterministic templates, not a hosted model's reasoning, latency or injection robustness.
- **No live threat intelligence.** Mock and no-lookup modes only; no claim about provider accuracy or coverage.
- **Project-defined ATT&CK ground truth.** The mapper is not validated by independent analysts.
- **No risk labels.** The score is transparent but not calibrated.
- **Simulation only.** Verification proves the workflow and records, not real remediation.
- **Operational limits.** SQLite single-process deployment, in-memory rate limiting, no TLS, no MFA, no external audit anchor.
- **Dashboard validation.** API and server startup were tested; a full browser automation of every control was not measured.

## 8. Conclusion and future work

This paper presented a runnable, safety-oriented agent pipeline for web-application incident response. It connects normalization, hybrid detection, evidence correlation, advisory LLM analysis, threat intelligence, ATT&CK mapping, transparent risk scoring, policy-based response, durable human approval, simulation-only execution, verification and a hash-chained audit trail. On synthetic scenarios it improved incident classification over a rule-only baseline without any unauthorized or non-simulated action, while honestly bounding every claim.

Future work should evaluate on a permitted, privacy-reviewed real web-log dataset with independently labelled incidents; add a stronger stateful rule baseline; test a live LLM with adversarial injection cases and blinded human scoring; validate ATT&CK mappings with independent analysts; calibrate risk against analyst severity ratings; add failure injection and concurrency testing; and integrate a sandboxed response target while keeping simulation as the default.

## References

[1] P. Cichonski, T. Millar, T. Grance, and K. Scarfone, "Computer Security Incident Handling Guide," NIST Special Publication 800-61 Revision 2, National Institute of Standards and Technology, 2012.

[2] OWASP Foundation, "OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks," 2021. [Online]. Available: https://owasp.org/Top10/

[3] R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *Proceedings of the IEEE Symposium on Security and Privacy*, 2010, pp. 305–316.

[4] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.

[5] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proceedings of the Eighth IEEE International Conference on Data Mining*, 2008, pp. 413–422.

[6] B. E. Strom, A. Applebaum, D. P. Miller, K. C. Nickels, A. G. Pennington, and C. B. Thomas, "MITRE ATT&CK: Design and Philosophy," The MITRE Corporation, Technical Report, 2018.

## Appendix A. Reproduction

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\seed_database.py
.\.venv\Scripts\python.exe scripts\train_model.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe scripts\evaluate.py
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Generated artifacts include `results/reports/evaluation_report.md`, `results/metrics/*.json`, `results/metrics/*.csv`, `results/figures/*.png` and `results/reports/demo_run.json`. The evaluation uses seed 42 and a fixed dataset anchor. Latency values vary by host.
