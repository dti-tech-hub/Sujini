# Evaluation methodology and measured results

All numbers below were produced by the documented commands on 23 October 2026 from commit `b0ade44a34ea` on Python 3.14.5, Windows 11 (`Windows-11-10.0.26200-SP0`), 12 logical CPUs, scalar SQLite. The data provenance is **`synthetic_demo_data`**. No value in this document is estimated.

Generated source of truth: `results/reports/evaluation_report.md`. Machine-readable artifacts: `results/metrics/ml_metrics.json`, `results/metrics/scenario_metrics.json`, `results/metrics/scenario_results.csv`, `results/metrics/summary.json`, `results/metrics/saved_model_evaluation.json`.

## 1. Research questions

The evaluation is organized around five practical questions:

1. Can the detection layer separate the generated attack families from benign traffic?
2. Does evidence-driven re-triage improve incident classification over a rule-only baseline?
3. Does the MITRE mapping agree with project-defined scenario ground truth?
4. Does the approval and simulation policy prevent unauthorized or real-world execution?
5. What latency does the local prototype exhibit under the benchmark workload?

These questions are deliberately narrow. The project does **not** claim production detection accuracy, real-world risk calibration or live threat-intelligence performance.

## 2. Two separate evaluations

### 2.1 Event-level ML evaluation

Purpose: measure supervised classifiers and the anomaly signal on individual synthetic HTTP events.

- 4,200 generated events.
- 14 numeric features.
- 8 labels: `benign`, `sql_injection`, `command_injection`, `path_traversal`, `brute_force`, `recon_scanning`, `suspicious_user_agent`, `prompt_injection_attempt`.
- Stratified 70/30 split: 2,940 train, 1,260 test.
- Seed 42.
- Fixed dataset anchor timestamp so `hour` and timestamps do not depend on execution date.

### 2.2 Incident-level scenario benchmark

Purpose: compare a rule-only baseline with the full agentic workflow on multi-event incidents and measure response policy.

- 100 scenarios: 10 per category across nine attack categories plus 10 benign.
- Each scenario executes in a **fresh temporary SQLite database** for both arms. This prevents cross-scenario correlation and ordering effects.
- ML anomaly detection is disabled in both arms (`enable_ml=False`) so the difference isolates incident-level re-triage and policy. ML is evaluated separately.
- Seed 42.
- 650 events processed.
- 120 alerts created in the agentic arm.
- 90 incidents investigated (all attack scenarios; benign scenarios produce no incident).

The baseline is intentionally simple: the **earliest rule alert** determines the incident category and there is no contextual re-triage. This is a realistic "rules-only queue" comparator, not a straw man with removed detection: both arms share the same rule stage. The agentic arm runs evidence collection, deterministic re-triage, threat intelligence, MITRE mapping, risk scoring, response planning and the approval gate.

## 3. Synthetic ML dataset

Class counts:

| Class | Count | Share |
|---|---:|---:|
| benign | 2,975 | 70.83% |
| sql_injection | 214 | 5.10% |
| command_injection | 173 | 4.12% |
| path_traversal | 217 | 5.17% |
| brute_force | 182 | 4.33% |
| recon_scanning | 194 | 4.62% |
| suspicious_user_agent | 121 | 2.88% |
| prompt_injection_attempt | 124 | 2.95% |
| **Total** | **4,200** | **100%** |

Features:

```text
status_code, method_post, path_length, query_length,
has_sql_meta, has_traversal, has_cmd_meta,
is_login, failed_login, ua_suspicious,
body_length, hour, response_size, missing_username
```

`dataset_label="synthetic_demo_data"` is kept separate from the supervised `class_label`. This prevents downstream code from confusing provenance with a model target.

### 3.1 Supervised models

- **Random Forest:** 300 trees, balanced subsample class weights, seed 42.
- **Logistic Regression:** standard scaling + L2 logistic regression, balanced class weights, max 3,000 iterations, seed 42.

Measured test performance (n = 1,260):

| Model | Accuracy | Macro F1 | Weighted F1 | Attack precision | Attack recall | Attack F1 | Attack ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Logistic Regression | 97.78% | 97.37% | 97.98% | 92.91% | 100.00% | 96.33% | 99.34% |

Random Forest binary counts: TP 367, FP 0, TN 893, FN 0.
Logistic Regression binary counts: TP 367, FP 28, TN 865, FN 0; FPR 3.14%.

Per-class Random Forest results:

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| benign | 100.00% | 100.00% | 100.00% | 893 |
| sql_injection | 100.00% | 100.00% | 100.00% | 64 |
| command_injection | 100.00% | 100.00% | 100.00% | 52 |
| path_traversal | 100.00% | 100.00% | 100.00% | 65 |
| brute_force | 100.00% | 100.00% | 100.00% | 55 |
| recon_scanning | 100.00% | 100.00% | 100.00% | 58 |
| suspicious_user_agent | 100.00% | 100.00% | 100.00% | 36 |
| prompt_injection_attempt | 100.00% | 100.00% | 100.00% | 37 |

Top impurity-based feature importances:

| Feature | Importance |
|---|---:|
| status_code | 0.2336 |
| path_length | 0.2066 |
| ua_suspicious | 0.1413 |
| method_post | 0.1230 |
| body_length | 0.0852 |
| query_length | 0.0625 |
| is_login | 0.0467 |
| failed_login | 0.0425 |

**Critical interpretation:** the Random Forest's perfect score is an upper-bound artifact. The synthetic classes are generated by templates with highly separable fields (status code, path length, scanner user-agent, POST method). A perfect score on this data does not predict real-world performance. The Logistic Regression result is a more informative sanity check, and even it benefits from template separability.

### 3.2 Isolation Forest anomaly signal

- Fitted only on **benign** training traffic (1,666 rows).
- 300 estimators, seed 42, `n_jobs=1` for reproducible threshold selection.
- Operating threshold selected by maximizing attack F1 on a labelled 20% validation split drawn from the training partition (588 rows; 172 attack).
- The test split is never used to choose the threshold.
- Threshold: **-0.045324**.
- Validation F1: 63.24%, precision 56.68%, recall 71.51%, FPR **22.60%**.

Test performance (n = 1,260):

| Measure | Value |
|---|---:|
| TP | 253 |
| FP | 220 |
| TN | 673 |
| FN | 114 |
| Precision | 53.49% |
| Recall | 68.94% |
| F1 | 60.24% |
| ROC-AUC | 79.24% |
| Accuracy (attack vs benign) | 73.49% |
| False-positive rate | 24.64% |

This is a **threshold-calibrated anomaly detector**, not a fully unsupervised evaluation: the model is fitted without labels, but the operating threshold uses labelled validation data. Its role in the product is an additive signal; deterministic rules remain authoritative. A 24.64% test FPR is too high for unassisted paging and is documented as a limitation.

## 4. Scenario definitions and ground truth

Each attack scenario has a project-defined expected category, MITRE set and key action.

| Category | n | Example sequence | Expected MITRE | Expected key action |
|---|---:|---|---|---|
| `brute_force` | 10 | 6 failed logins | T1110 | `SIMULATE_BLOCK_IP` |
| `account_compromise` | 10 | 5 failures → success → SQLi-shaped admin request → admin audit access | T1110, T1078, T1190 | `SIMULATE_DISABLE_SESSION` |
| `sql_injection` | 10 | UNION SELECT in product search | T1190 | `SIMULATE_BLOCK_IP` |
| `xss` | 10 | `<script>alert(document.cookie)</script>` in a search parameter | T1059.007 (candidate) | `SIMULATE_BLOCK_IP` |
| `command_injection` | 10 | `ip=127.0.0.1; whoami` | T1059, T1190 | `SIMULATE_QUARANTINE` |
| `path_traversal` | 10 | `../../../../etc/passwd` | T1190 | `SIMULATE_BLOCK_IP` |
| `unauthorized_access` | 10 | four HTTP 403 responses on admin endpoints | none (excluded) | `SIMULATE_BLOCK_IP` |
| `malicious_ip` | 10 | request from a watchlisted documentation IP | none (excluded) | `SIMULATE_BLOCK_IP` |
| `abnormal_traffic` | 10 | 35 requests in a short window | none (excluded) | `SIMULATE_NOTIFY_ADMIN` |
| `benign` | 10 | 5 normal page views | none | — |

The account-compromise scenario includes the SQLi-shaped admin request specifically so that T1190 is defensible. Without it, T1190 would be an unsupported mapping.

### 4.1 MITRE eligibility

MITRE accuracy is computed over **60 eligible scenarios**: brute force, account compromise, SQL injection, XSS, command injection and path traversal. The 40 reputation-only, volume-only or authorization-only scenarios are excluded because the project does not claim that reputation, volume or a denied request alone proves a technique. Ground truth is project-defined from scenario construction, not an independent expert-labelled corpus.

## 5. Scenario results

### 5.1 Detection

| Measure | Rule-only baseline | Agentic pipeline |
|---|---:|---:|
| TP | 90 | 90 |
| FP | 0 | 0 |
| TN | 10 | 10 |
| FN | 0 | 0 |
| Precision | 100.00% | 100.00% |
| Recall | 100.00% | 100.00% |
| F1 | 100.00% | 100.00% |
| Accuracy | 100.00% | 100.00% |
| Recall 95% Wilson CI | [95.91%, 100%] | [95.91%, 100%] |

Detection is shared: the agentic pipeline does not replace the rule stage. The scenario benchmark therefore does not claim an agentic detection improvement; it isolates classification and policy.

### 5.2 Incident correlation

| Measure | Result |
|---|---:|
| Correct | 100/100 |
| Accuracy | 100.00% |
| 95% Wilson CI | [96.30%, 100%] |

Criterion: each attack scenario must yield exactly one incident; each benign scenario must yield zero.

### 5.3 Incident classification

| Measure | Rule-only baseline | Agentic pipeline |
|---|---:|---:|
| Correct | 90/100 | 100/100 |
| Accuracy | 90.00% | 100.00% |
| Macro F1 | 86.67% | 100.00% |

Per-class F1:

| Class | Support | Baseline F1 | Agentic F1 |
|---|---:|---:|---:|
| brute_force | 10 | 66.67% | 100.00% |
| account_compromise | 10 | 0.00% | 100.00% |
| sql_injection | 10 | 100.00% | 100.00% |
| xss | 10 | 100.00% | 100.00% |
| command_injection | 10 | 100.00% | 100.00% |
| path_traversal | 10 | 100.00% | 100.00% |
| unauthorized_access | 10 | 100.00% | 100.00% |
| malicious_ip | 10 | 100.00% | 100.00% |
| abnormal_traffic | 10 | 100.00% | 100.00% |
| benign_or_unknown | 10 | 100.00% | 100.00% |

The baseline's only error mode is account compromise: the failed-login alert fires first, so the earliest alert is `brute_force`. The baseline also has a brute-force F1 of 66.67% because the 10 misclassified account-compromise scenarios are counted as brute-force false positives.

Paired McNemar exact test:

- baseline-only correct: 0
- agentic-only correct: 10
- discordant pairs: 10
- exact two-sided p = **0.001953**

This is a valid paired comparison for these 100 generated scenarios. It is not evidence that the same improvement generalizes to real enterprise traffic.

### 5.4 MITRE ATT&CK mapping

Over 60 eligible scenarios:

| Measure | Value |
|---|---:|
| Eligible scenarios | 60 |
| Excluded scenarios | 40 |
| TP | 90 |
| FP | 0 |
| FN | 0 |
| Micro precision | 100.00% |
| Micro recall | 100.00% |
| Micro F1 | 100.00% |
| Exact set match | 100.00% |

This means the local mapper reproduced the project-defined sets exactly. It does **not** validate the mapping against an independent ATT&CK ground truth.

### 5.5 Risk scoring

Risk scores for 90 attack incidents:

| Statistic | Value |
|---|---:|
| n | 90 |
| Mean | 60.33 |
| Min | 49.95 |
| Max | 76.75 |
| HIGH | 80 |
| CRITICAL | 10 |

By category:

| Category | n | Mean | Min | Max | Levels |
|---|---:|---:|---:|---:|---|
| brute_force | 10 | 59.28 | 59.28 | 59.28 | HIGH=10 |
| account_compromise | 10 | 76.75 | 76.75 | 76.75 | CRITICAL=10 |
| sql_injection | 10 | 58.49 | 58.49 | 58.49 | HIGH=10 |
| xss | 10 | 55.67 | 55.67 | 55.67 | HIGH=10 |
| command_injection | 10 | 67.60 | 67.60 | 67.60 | HIGH=10 |
| path_traversal | 10 | 53.99 | 53.99 | 53.99 | HIGH=10 |
| unauthorized_access | 10 | 60.15 | 60.15 | 60.15 | HIGH=10 |
| malicious_ip | 10 | 61.13 | 61.13 | 61.13 | HIGH=10 |
| abnormal_traffic | 10 | 49.95 | 49.95 | 49.95 | HIGH=10 |

The scores are deterministic for these scenarios because the event composition is fixed. There are no ground-truth risk labels, so accuracy, calibration and discrimination are **NOT MEASURED**. The value of the model is transparency and policy consistency, not validated predictive power.

### 5.6 Response, approval and safety

| Measure | Value |
|---|---:|
| Attack scenarios investigated | 90 |
| Approval-gated scenarios | 90 |
| Auto-executed | 0 |
| Approval gate correct | 90/90 (100.00%) |
| Expected key action present | 90/90 (100.00%) |
| Allowlist compliance | 100.00% |
| Simulation compliance | 100.00% |
| Verified incidents | 90/90 (100.00%) |
| Executed action records | 390 |
| Simulated action records | 390 |
| Non-simulated action records | 0 |
| Unauthorized executions | 0 |
| Audit-chain valid scenarios | 100/100 (100.00%) |

Every attack scenario reached HIGH or CRITICAL risk, so the approval gate applied to all 90. The benchmark explicitly checks that the incident was pending before approval, then approves as an analyst, executes and verifies. No MEDIUM/LOW auto-execution path was exercised by these scenarios; that path is covered by unit tests rather than by this benchmark.

### 5.7 Latency

Wall-clock measurements, local SQLite:

| Stage | n | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Ingestion | 100 | 173.76 | 118.71 | 546.27 | 60.22 | 622.76 |
| Investigation | 90 | 279.15 | 273.39 | 361.68 | 144.42 | 1101.15 |
| Response | 90 | 216.27 | 227.14 | 290.65 | 85.69 | 319.11 |
| Total | 100 | 717.11 | 741.83 | 1240.09 | 84.42 | 1506.70 |

Ingestion includes parsing, normalization, rule evaluation, incident assignment and audit writes. Investigation includes seven LangGraph stages and their database writes. Response includes approval in the benchmark, simulated execution and verification. These numbers are not a throughput or SLA claim; they include Python overhead and synchronous SQLite I/O.

### 5.8 Runtime modes

| Dimension | Mode | Incidents |
|---|---|---:|
| LLM | `DEMO_TEMPLATE` | 90 |
| Threat intelligence | `NO_EXTERNAL_LOOKUP` | 80 |
| Threat intelligence | `DEMO_MOCK` | 10 |

No live LLM or live TI provider was configured for this run. The reported investigation and enrichment behavior is therefore fully reproducible local behavior, not an evaluation of a hosted model or live reputation feed.

## 6. End-to-end demo

`scripts/run_demo.py` uses the real FastAPI application through `TestClient` and a disposable database. Measured result:

| Field | Value |
|---|---|
| Scenario | `brute_force_account_compromise` |
| Data label | `synthetic_demo_data` |
| Classification | `account_compromise` |
| Confidence | 0.97 |
| Risk score / level | 90.21 / CRITICAL |
| Status before approval | `AWAITING_APPROVAL` |
| MITRE techniques | T1078, T1110, T1190 |
| Evidence records | 16 |
| TI mode | `DEMO_MOCK` |
| LLM mode | `DEMO_TEMPLATE` |
| Response action records | 6 |
| Executed actions | 6, all simulated |
| Verification checks | 6/6 passed |
| Final status | `VERIFIED` |
| Audit chain | valid, 41 entries |

The demo risk score (90.21) is higher than the benchmark account-compromise mean (76.75) because the demo uses the current timestamp, the account name `admin`, and the `/admin` + `/login` asset-criticality prefixes; recurrence is computed against a fresh database, so that factor is zero. This is a real output of the same scoring formula, not a hard-coded value.

## 7. Metric definitions

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2PR / (P + R)
- **Macro F1** = unweighted mean of per-class F1 over all labels, including classes with zero support
- **False-positive rate** = FP / (FP + TN)
- **Wilson 95% interval** = score interval for a binomial proportion; used for detection and correlation rates
- **McNemar exact** = two-sided exact binomial test over discordant paired outcomes
- **MITRE micro F1** = aggregate TP/FP/FN over eligible technique sets
- **Latency p95** = nearest-rank 95th percentile of the observed durations

## 8. Reproduction

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe scripts\evaluate.py
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Optional controlled variations:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate.py --samples 4200 --per-class 10 --seed 42
.\.venv\Scripts\python.exe scripts\evaluate.py --skip-ml
.\.venv\Scripts\python.exe scripts\evaluate.py --skip-scenarios
```

Reproducibility controls:

- fixed dataset anchor for ML and scenario generation;
- seed 42 for data generation, train/test split, Random Forest, Logistic Regression and Isolation Forest;
- `n_jobs=1` for Isolation Forest threshold selection;
- fresh SQLite per scenario;
- deterministic mock TI for documentation-range IPs;
- deterministic LLM template mode.

Wall-clock latency will vary by host and load even when all non-latency metrics reproduce.

## 9. Threats to validity

### Internal validity

- Synthetic scenarios are generated from the same project's templates and mapping catalog. This creates a risk of circularity: the agentic pipeline can appear perfect because its heuristics and the ground truth share assumptions.
- The account-compromise scenario was extended with a SQLi-shaped request so T1190 is defensible. This is a legitimate ground-truth correction, but it also makes the scenario more separable.
- XSS ground truth uses T1059.007 (JavaScript) and is reported as a candidate mapping because the observed request proves delivery, not execution.
- The baseline is intentionally simple. A stronger baseline (for example, a stateful rule engine with success-after-failure logic) would narrow the classification gap.
- Mitigation: keep both arms on the same rule stage, use a fresh database per scenario, and report exact per-class results and the baseline definition.

### External validity

- The data is synthetic and small (4,200 events, 100 scenarios). It is not representative of production traffic, attacker adaptation or enterprise asset diversity.
- The LLM was not live. Results do not evaluate a hosted model's reasoning quality, latency or prompt-injection robustness.
- Threat intelligence was mock/no-lookup. No claim is made about live provider accuracy or coverage.
- All response actions are simulated. There is no evidence about real containment success or blast radius.

### Construct validity

- Random Forest's 100% is a template-separability artifact.
- MITRE ground truth is project-defined, not independently adjudicated.
- Risk has no ground-truth labels; scores are not calibrated probabilities.
- "Approval-gate accuracy" verifies policy behavior, not whether a human made a good decision.
- "Verification rate" verifies that simulated actions were recorded and marked simulation-only; it does not verify real-world remediation.

### Conclusion validity

- The McNemar p-value is valid for the paired 100-scenario sample but should not be extrapolated.
- Per-class support is only 10 scenarios, so per-class F1 is coarse.
- No confidence intervals are reported for F1 because the class supports are small; detection and correlation use Wilson intervals.

## 10. Non-claims

This project does **not** claim:

- real-world detection accuracy or generalization;
- that the LLM improves security outcomes;
- that mock threat intelligence reflects real reputation;
- that MITRE mappings are externally validated;
- that risk scores predict real incident severity;
- that simulated responses would work against a real adversary;
- production throughput, availability or SLA;
- resistance to a determined attacker with host or database access.

## 11. What would strengthen the evaluation

1. Capture a permitted, privacy-reviewed real web-log dataset and label incidents independently.
2. Add a stronger stateful rule baseline.
3. Evaluate a live LLM with adversarial prompt-injection cases and blinded human scoring.
4. Validate MITRE mappings with independent analysts.
5. Calibrate risk against analyst severity ratings.
6. Integrate a real, sandboxed response target (for example, a disposable firewall lab) while keeping the production default simulation-only.
7. Increase scenario count and report bootstrap confidence intervals.
8. Measure concurrency, failure injection and recovery.
