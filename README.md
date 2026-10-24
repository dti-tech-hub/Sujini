# Sujini: AI Agent-Based Automated Cybersecurity Incident Response System

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/orchestration-LangGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![Streamlit](https://img.shields.io/badge/dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Safety](https://img.shields.io/badge/mode-Simulation%20Only-success.svg)](docs/SECURITY.md)
[![Tests](https://img.shields.io/badge/tests-84%20passed-brightgreen.svg)](tests/)

An academic and production-modeled **Autonomous & Human-in-the-Loop Cybersecurity Incident Response System** designed specifically for web application security.

The system ingests raw security logs and alerts, normalizes them, detects threats using hybrid signature rules and machine learning anomaly detection, correlates multi-stage alerts into unified incidents, orchestrates an AI investigation pipeline using **LangGraph**, enriches context with **Threat Intelligence** and **MITRE ATT&CK** mappings, computes a transparent **weighted risk score**, devises an allowlisted response plan, enforces a mandatory **Human-in-the-Loop approval gate** for high-risk actions, executes simulated containment/remediation safely, verifies the outcome, and maintains a tamper-evident **SHA-256 cryptographic audit chain**.

---

## Table of Contents

- [1. What Is This Project About?](#1-what-is-this-project-about)
- [2. Why Was It Built? (Problem & Motivation)](#2-why-was-it-built-problem--motivation)
- [3. What We Use and Why (Tech Stack & Architecture)](#3-what-we-use-and-why-tech-stack--architecture)
- [4. Incident Response Pipeline (How It Works)](#4-incident-response-pipeline-how-it-works)
- [5. Supported Attack & Anomaly Scenarios](#5-supported-attack--anomaly-scenarios)
- [6. Non-Negotiable Safety Invariants](#6-non-negotiable-safety-invariants)
- [7. Project Directory Structure](#7-project-directory-structure)
- [8. Quickstart Guide (Step-by-Step)](#8-quickstart-guide-step-by-step)
- [9. REST API Overview](#9-rest-api-overview)
- [10. Empirical Evaluation & Benchmark Results](#10-empirical-evaluation--benchmark-results)
- [11. Comprehensive Documentation Index](#11-comprehensive-documentation-index)
- [12. Academic Notice & Limitations](#12-academic-notice--limitations)

---

## 1. What Is This Project About?

Modern Security Operations Centers (SOCs) are overwhelmed with hundreds or thousands of daily security alerts from web application firewalls (WAFs), reverse proxies, and identity providers. 

**Sujini** is an intelligent, multi-agent cyber incident response platform that closes the gap between passive alert generation and active threat mitigation:

- **Full Lifecycle Automation:** From raw log ingestion to post-incident verification.
- **Explainable Multi-Agent AI:** Uses LangGraph to coordinate specialized agents (Triage, Evidence, Threat Intel, MITRE ATT&CK, Risk, and Response).
- **Human-in-the-Loop Safeguards:** Low-risk, non-destructive actions can be automated, while HIGH and CRITICAL severity actions require explicit analyst or administrator approval.
- **Strictly Simulated Execution:** All containment actions (e.g., IP blocks, session invalidation, credential resets) are simulated safely. No real network devices or servers are mutated.
- **Tamper-Evident Auditability:** Every action, decision, prompt, approval, and verification is chained via a cryptographic SHA-256 hash log.

---

## 2. Why Was It Built? (Problem & Motivation)

| Real-World SOC Challenge | How Sujini Addresses It |
|---|---|
| **Alert Fatigue**<br>SOC analysts face alert fatigue from thousands of disconnected alerts, missing actual multi-stage compromises. | **Correlation & Deduplication Engine** groups related HTTP requests, source IPs, and target endpoints into a single coherent incident within a configurable time window. |
| **High MTTR (Mean Time to Respond)**<br>Triaging an alert manually, looking up threat intel, and checking MITRE techniques takes 15–45 minutes per incident. | **Agentic Investigation Pipeline** enriches threat intelligence, maps MITRE tactics/techniques, and scores transparent risk in under 1 second. |
| **Black-Box AI Hallucinations**<br>Blindly trusting generative LLMs to make security decisions can lead to dangerous, destructive shell commands or hallucinations. | **Deterministic Rule Primacy & Schema Validation:** LLM output is strictly advisory. Response actions must come from a pre-approved YAML allowlist. Unsafe modes are hard-rejected. |
| **Premature Automation / Service Disruption**<br>Aggressive automated SOAR playbooks can accidentally lock out legitimate users or block vital business IP ranges. | **Dual-Phase Approval Gate:** Phase 1 stops at `AWAITING_APPROVAL` for High/Critical incidents. Phase 2 only executes after an authorized human reviews and signs off. |
| **Lack of Forensics & Compliance Audit**<br>Many SOC tools do not log internal agent decisions or provide tamper-proof records for post-breach audits. | **Cryptographic SHA-256 Hash Chain:** Every state change and analyst decision forms an unbroken ledger verifiable at any time via the API or SOC dashboard. |

---

## 3. What We Use and Why (Tech Stack & Architecture)

| Component / Library | Purpose in Sujini | Why We Chose It |
|---|---|---|
| **Python 3.11+** | Core Programming Language | Rich cybersecurity and AI ecosystem, native type hinting, performance optimizations, and broad library support. |
| **FastAPI & Starlette** | Backend REST API Service | Asynchronous high-throughput request handling, automatic OpenAPI/Swagger interactive documentation (`/docs`), and robust dependency injection. |
| **Pydantic v2** | Data Validation & Serialization | Strict data contracts for events, alerts, incidents, and LLM input/output schemas to prevent malformed data or prompt-injection leakage. |
| **LangGraph & LangChain** | Agentic Workflow Orchestration | Provides a stateful, cyclic/acyclic graph engine with state persistence. Allows the investigation to halt cleanly at a durable SQLite approval gate without holding memory or hanging processes. |
| **Scikit-learn** | Machine Learning & Anomaly Detection | Lightweight, reproducible training and inference. Provides **Isolation Forest** for unsupervised anomaly detection over 14 HTTP features, plus **Random Forest** and **Logistic Regression** baselines. |
| **SQLAlchemy 2.0 & SQLite** | Database & Persistence Layer | Clean declarative ORM with zero configuration. Runs portable local databases for production and spawns clean in-memory/temp databases for deterministic, isolated benchmark runs. |
| **Streamlit** | Security Operations Center (SOC) Console | Enables a reactive, real-time analyst dashboard with incident filtering, visual timelines, live event streams, risk score breakdowns, and one-click approvals without complex frontend build tools. |
| **Cryptographic Hash Chain** | Tamper-Evident Audit Trail | Generates SHA-256 hash chains over every ingested log, agent decision, approval, and action execution to ensure strict forensics integrity. |
| **Threat Intel Adapters** | External Threat Context | Modular provider pattern supporting **VirusTotal**, **AbuseIPDB**, and deterministic **Mock Providers** for offline, free demonstration without requiring paid external API subscriptions. |
| **MITRE ATT&CK Catalog** | Threat Standardization | Built-in mapping of web attacks to standardized Tactics and Techniques (T1190, T1059, T1078, T1110, etc.) with confidence scores and evidence traces. |
| **Pytest** | Automated Testing Suite | 84 comprehensive unit and integration tests verifying detection accuracy, rate-limiting, authentication, authorization, risk scoring, response allowlists, and audit chains. |

---

## 4. Incident Response Pipeline (How It Works)

```text
 ┌────────────────────────────────────────────────────────┐
 │ 1. Ingestion: HTTP Logs, Apache/Nginx, JSON Alerts     │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 2. Normalization & Sanitization (Deduplication, Alias) │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 3. Detection Engine: Signature Rules + ML Anomaly     │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 4. Incident Correlation (IP, Username, Time Window)    │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 5. LangGraph Phase 1: Investigation Agent Pipeline     │
 │    • Evidence Collection & Aggregation                 │
 │    • Threat Intelligence (AbuseIPDB / VirusTotal)      │
 │    • MITRE ATT&CK Mapping & Confidence Scoring         │
 │    • Transparent 7-Factor Weighted Risk Scoring        │
 │    • Allowlisted Response Action Recommendation        │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
            ┌──────────────────────────────────┐
            │ Is Incident HIGH or CRITICAL?    │
            └───────┬──────────────────┬───────┘
           YES      │                  │  NO (Low / Medium)
                    ▼                  ▼
    ┌──────────────────────┐    ┌─────────────────────────┐
    │ Human Approval Gate  │    │ Automatic Authorization │
    │ (Awaiting Analyst)   │    └────────────┬────────────┘
    └───────┬──────────────┘                 │
   APPROVED │ (or Rejected)                  │
            └───────────────┬────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │ 6. LangGraph Phase 2: Response Execution               │
 │    • Strict Simulation Mode Enforcement (`SIMULATE_*`) │
 │    • Multi-Step Response Verification                  │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 7. Tamper-Evident SHA-256 Audit Trail & SOC Reporting  │
 └────────────────────────────────────────────────────────┘
```

---

## 5. Supported Attack & Anomaly Scenarios

The detection and investigation modules classify and handle 9 major categories of web security incidents:

1. **SQL Injection (SQLi):** Detection of union-based, boolean-based, and stacked query payloads across GET parameters and POST bodies.
2. **Cross-Site Scripting (XSS):** Reflected, stored, and DOM-based `<script>`, `onerror=`, and encoded JavaScript attack vectors.
3. **Command Injection:** Operating system command separators (`;`, `&&`, `|`) and shell execution directives.
4. **Path Traversal / LFI:** Directory climbing patterns (`../`, `..\\`, `/etc/passwd`, `win.ini`).
5. **Reconnaissance & Vulnerability Scanning:** Automated scanning tools, dirbuster probes, and known scanner user-agents (Nikto, SQLMap, Nmap).
6. **Prompt Injection Attempts:** Direct prompt injection, jailbreak keywords, and system instruction overrides targeting LLM interfaces.
7. **Brute Force & Account Compromise:** Rapid bursts of failed logins against authentication endpoints followed by successful authenticated sessions.
8. **Unauthorized Access Attempts:** Direct attempts to access restricted `/admin`, `/api/internal`, or privileged endpoints without valid tokens.
9. **Abnormal Traffic / Server Error Bursts:** Abnormal request volumes and sustained 5xx HTTP response bursts indicating availability or exploit stress.

---

## 6. Non-Negotiable Safety Invariants

This repository operates under strict safety and defensive principles:

1. **100% Simulation Mode:** Every response action (e.g., `SIMULATE_BLOCK_IP`, `SIMULATE_REVOKE_SESSION`, `SIMULATE_RESET_CREDENTIALS`) has simulated effects only. The system refuses to mutate real firewalls, operating systems, or containers. Setting `simulation_mode=false` will explicitly raise a `PolicyError`.
2. **Deterministic Response Allowlist:** Every action must be defined in `config/response_rules.yaml`. The executor re-verifies the allowlist independently before simulated dispatch.
3. **Advisory LLM Role:** Large Language Model outputs are strictly advisory. The LLM never selects or executes code or actions.
4. **Mandatory Human Approval Gate:** HIGH and CRITICAL severity incidents require explicit analyst/admin authorization before any response execution can proceed.
5. **Prompt Injection as Passive Data:** All ingested event payloads, user agents, and usernames are treated strictly as untrusted data and never interpolated into executable positions or shell commands.
6. **Tamper-Evident Hash Chain:** All events, decisions, approvals, and executions are recorded into a SHA-256 cryptographic chain. Any modification invalidates the chain.

---

## 7. Project Directory Structure

```text
Sujini/
├── config/                      # YAML configuration policies
│   ├── config.yaml              # Core system, server, and LLM settings
│   ├── detection_rules.yaml     # Regex patterns, thresholds, and signatures
│   ├── mitre_mapping.yaml       # ATT&CK tactics, techniques, and rationales
│   ├── response_rules.yaml      # Allowlisted response actions by category & risk
│   └── risk_rules.yaml          # Transparent weights and threshold scoring
├── dashboard/
│   └── app.py                   # Streamlit SOC Analyst Console
├── data/
│   └── datasets/                # Synthetic baseline and benchmark datasets
├── docs/                        # Complete technical documentation
│   ├── API.md                   # REST API endpoints, schemas, and curl examples
│   ├── ARCHITECTURE.md          # Multi-agent LangGraph architecture details
│   ├── CONFERENCE_PAPER.md      # Publication-ready academic manuscript
│   ├── conference_paper.tex     # LaTeX source of academic paper
│   ├── DEMO.md                  # Detailed walkthrough of the SOC demo
│   ├── EVALUATION.md            # Benchmark methodology, validity, and metrics
│   ├── FINAL_VALIDATION.md      # Validation reports, test results, and checks
│   ├── METHODOLOGY.md           # Detection, risk, and response methodologies
│   ├── SECURITY.md              # Threat model and safety invariants
│   ├── SETUP.md                 # Deployment, virtualenv, and system setup
│   └── VIVA_GUIDE.md            # Comprehensive project presentation & viva guide
├── models/                      # ML model storage (Isolation Forest artifacts)
├── results/                     # Evaluation metrics, figures, reports, and logs
├── scripts/                     # Operational scripts
│   ├── seed_database.py         # Initializes default admin, analyst, viewer roles
│   ├── train_model.py           # Trains the runtime anomaly Isolation Forest
│   ├── evaluate.py              # Executes 100-scenario benchmark & generates reports
│   ├── run_demo.py              # Automated 1-command end-to-end incident demo
│   └── import_logs.py           # CLI to import Apache/Nginx combined access logs
├── src/
│   ├── agents/                  # LangGraph orchestrator and specialized agent nodes
│   ├── api/                     # FastAPI application, routes, and error handlers
│   ├── database/                # SQLAlchemy declarative models and repository
│   ├── detection/               # Rule engine, log normalization, and incident correlation
│   ├── evaluation/              # Synthetic datasets, metrics, and benchmark runners
│   ├── investigation/           # Evidence collection, timeline, and triage analysis
│   ├── llm/                     # Advisory LLM adapters, prompt sanitization, schemas
│   ├── mitre/                   # MITRE ATT&CK mapper and confidence scoring
│   ├── ml/                      # 14-feature engineering, training, and inference
│   ├── response/                # Action planner, approval gates, simulated executor
│   ├── risk/                    # Explainable 7-factor weighted risk engine
│   ├── security/                # JWT auth, PBKDF2 hashing, audit hash chain
│   ├── services/                # Central SOC service facade and scenario logic
│   └── utils/                   # Helpers, logging, and configuration loader
├── tests/                       # 84 automated unit and integration tests
├── AGENTS.md                    # Working rules and invariants for AI agents
├── requirements.txt             # Python dependencies
└── README.md                    # Project overview and reference guide
```

---

## 8. Quickstart Guide (Step-by-Step)

### Prerequisites

- **Python 3.11+** installed on Windows, Linux, or macOS.
- PowerShell (Windows) or Bash (Linux/macOS).

---

### Step 1: Clone Repository & Create Virtual Environment

```powershell
git clone https://github.com/dti-tech-hub/Sujini.git
cd Sujini

# Create virtual environment
python -m venv .venv

# Activate environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Or activate on Linux/macOS
# source .venv/bin/activate

# Install dependencies
python -m pip install -r requirements.txt
```

---

### Step 2: Seed Default User Accounts

```powershell
.\.venv\Scripts\python.exe scripts\seed_database.py
```

*This creates `admin`, `analyst`, and `viewer` accounts with randomized secure passwords stored locally in `data/credentials.json` (git-ignored).*

---

### Step 3: Train the Anomaly Detection Model

```powershell
.\.venv\Scripts\python.exe scripts\train_model.py
```

*Trains the Isolation Forest on 14 HTTP features and validates accuracy against synthetic event baselines.*

---

### Step 4: Run the Automated 1-Command Demo

To experience the entire end-to-end incident response flow instantly without starting servers:

```powershell
.\.venv\Scripts\python.exe scripts\run_demo.py
```

**What this does automatically:**
1. Spawns an isolated database and authenticates a demo admin.
2. Ingests a brute-force and account compromise scenario.
3. Automatically triggers the LangGraph investigation agent.
4. Collects evidence, maps MITRE techniques (`T1078`, `T1110`, `T1190`), and scores risk (`90.21` → **CRITICAL**).
5. Halts at the durable **Human Approval Gate** (`AWAITING_APPROVAL`).
6. Approves the response plan, executes simulated actions, and verifies the outcome (`VERIFIED`).
7. Checks and validates the SHA-256 cryptographic audit chain.

---

### Step 5: Start the FastAPI Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive API Documentation (Swagger UI):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **API Health Check:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **OpenAPI Schema:** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

### Step 6: Launch the Streamlit SOC Dashboard

In a new terminal window:

```powershell
$env:SOC_API_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Open your browser at **[http://localhost:8501](http://localhost:8501)** and sign in with the credentials generated in Step 2 or Step 4.

**Dashboard Features:**
- **Metrics Bar:** Open incidents, critical alerts, pending approvals, and MTTR.
- **Incident Explorer:** Filter by severity, status, and classification.
- **Incident Detail View:** Timeline, collected evidence weights, MITRE matrix, risk factor breakdown.
- **Human Approval Panel:** Approve or reject response actions with mandatory audit comments.
- **Audit Ledger:** Visual inspector for the SHA-256 tamper-evident chain.

---

### Step 7: Run Automated Tests

Execute the 84 unit and integration tests:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

---

## 9. REST API Overview

All API endpoints are documented with OpenAPI schemas at `/docs`. Authentication is managed via JWT bearer tokens.

| Method | Endpoint | Access Role | Description |
|---|---|---|---|
| `POST` | `/auth/login` | Public | Authenticates username/password and issues a JWT token. |
| `GET` | `/auth/me` | Authenticated | Returns current authenticated user details and role. |
| `POST` | `/api/events` | Analyst / Admin | Ingests a single HTTP security log or event. |
| `POST` | `/api/events/batch` | Analyst / Admin | Ingests up to 500 events in a single batch. |
| `GET` | `/api/events` | Viewer+ | Retrieves and filters ingested security events. |
| `GET` | `/api/alerts` | Viewer+ | Lists detected security alerts. |
| `GET` | `/api/incidents` | Viewer+ | Lists correlated incidents with severity filters. |
| `GET` | `/api/incidents/{id}` | Viewer+ | Retrieves complete incident record with timeline and evidence. |
| `POST` | `/api/incidents/{id}/investigate` | Analyst / Admin | Triggers the LangGraph investigation workflow. |
| `POST` | `/api/incidents/{id}/approve` | Analyst / Admin | Approves a pending incident response plan. |
| `POST` | `/api/incidents/{id}/reject` | Analyst / Admin | Rejects a response plan with a required reason. |
| `POST` | `/api/incidents/{id}/execute` | Analyst / Admin | Executes approved simulated response actions and verifies. |
| `GET` | `/api/audit` | Analyst / Admin | Retrieves and validates the SHA-256 cryptographic audit chain. |
| `GET` | `/api/metrics` | Viewer+ | Retrieves aggregated SOC performance and latency metrics. |
| `POST` | `/api/demo/scenario` | Admin | Ingests a pre-built synthetic attack scenario. |

---

## 10. Empirical Evaluation & Benchmark Results

The system was evaluated using 4,200 synthetic events (stratified 70/30 split) and a 100-scenario independent benchmark (90 attacks, 10 benign). ML detection was held constant across arms to isolate the contribution of agentic triage and policy.

### Headline Benchmark Results

| Metric | Rule-Only Baseline | Sujini Agentic Pipeline | Significance / Notes |
|---|---:|---:|---|
| **Incident Detection Recall** | 100.00% | **100.00%** | Both systems detect all 90 attacks. |
| **Incident Detection Precision** | 100.00% | **100.00%** | Zero false positives on 10 benign scenarios. |
| **Classification Accuracy** | 90.00% | **100.00%** | Paired McNemar test **p = 0.001953** (10 discordant pairs). |
| **Account Compromise Triage** | 0.00% (labeled brute force) | **100.00%** | Agent successfully detects transition to successful session. |
| **MITRE ATT&CK Micro F1** | N/A | **100.00%** | Across all 60 eligible scenarios. |
| **Human Approval Gate Accuracy** | N/A | **100.00%** | 90/90 high-risk incidents held at gate. |
| **Simulation Compliance** | 100.00% | **100.00%** | 390/390 actions simulated; 0 unsafe executions. |
| **Audit Chain Validity** | 100.00% | **100.00%** | 100/100 scenarios maintain valid hash chains. |

### Mean Pipeline Latency (Local Benchmark)

| Stage | Mean Duration (ms) | Median Duration (ms) | p95 Duration (ms) |
|---|---:|---:|---:|
| **Event Ingestion & Normalization** | 173.76 ms | 118.71 ms | 546.27 ms |
| **Multi-Agent Investigation (Phase 1)** | 279.15 ms | 273.39 ms | 361.68 ms |
| **Simulated Response & Verification (Phase 2)** | 216.27 ms | 227.14 ms | 290.65 ms |
| **Total Incident Lifecycle** | **717.11 ms** | **741.83 ms** | **1240.09 ms** |

---

## 11. Comprehensive Documentation Index

Explore the detailed architecture and technical guides in [`docs/`](docs/):

- **[System Architecture (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md):** Detailed agent state diagrams, LangGraph node transitions, and data models.
- **[Setup & Deployment Guide (`docs/SETUP.md`)](docs/SETUP.md):** Complete installation, environment variables, and configuration steps.
- **[REST API Reference (`docs/API.md`)](docs/API.md):** Comprehensive curl commands, request bodies, and JSON responses.
- **[Security & Threat Model (`docs/SECURITY.md`)](docs/SECURITY.md):** Formal safety invariants, prompt injection defenses, and risk boundaries.
- **[Methodology Guide (`docs/METHODOLOGY.md`)](docs/METHODOLOGY.md):** Mathematical formulas for risk scoring, normalization rules, and detection algorithms.
- **[Evaluation & Metrics (`docs/EVALUATION.md`)](docs/EVALUATION.md):** Complete empirical analysis, confusion matrices, and threats to validity.
- **[Interactive Demo Walkthrough (`docs/DEMO.md`)](docs/DEMO.md):** Step-by-step SOC analyst walkthrough using the web dashboard.
- **[Viva & Project Defense Guide (`docs/VIVA_GUIDE.md`)](docs/VIVA_GUIDE.md):** Presentation script, architectural rationale, and examiner Q&A.
- **[Academic Conference Paper (`docs/CONFERENCE_PAPER.md`)](docs/CONFERENCE_PAPER.md):** Complete academic research paper ready for conference submission.
- **[Agent Working Rules (`AGENTS.md`)](AGENTS.md):** Repository rules, invariants, and coding guidelines for AI pair-programmers.

---

## 12. Academic Notice & Limitations

- **Dataset Provenance:** All datasets and event scenarios in this project are labeled `synthetic_demo_data`. No real-world production or enterprise traffic was captured.
- **Simulated Response:** All response actions are purely simulated (`SIMULATION_ONLY`). This software will not alter production network infrastructure.
- **Threat Intelligence:** In standard demo mode, external IP lookups use a labelled `DEMO_MOCK` adapter to avoid requiring paid commercial API keys and prevent data leakage of private IP ranges (RFC 1918 / RFC 5737).
- **Advisory AI:** All generative AI components are schema-bounded and advisory; authoritative incident triage and response gates are enforced deterministically by policy.

---

## License

This project is developed for academic research and educational demonstration as a final-year B.Tech Computer Science & Engineering capstone project.
