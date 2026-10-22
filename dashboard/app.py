"""Streamlit SOC dashboard for the AI-agent incident-response system.

The dashboard is a thin client over the FastAPI service. It never reads the
database directly and never invents values: every number, label, action and
audit entry shown here comes from an API response.

Run the API first, then:

    streamlit run dashboard/app.py

Environment:
    SOC_API_URL   Base URL of the API (default http://127.0.0.1:8000)
    SOC_API_TIMEOUT  Request timeout in seconds (default 30)
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("SOC_API_TIMEOUT", "30"))

SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#0891b2",
    "INFO": "#475569",
}
RISK_COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#059669"}
STATUS_COLORS = {
    "NEW": "#64748b",
    "TRIAGED": "#0ea5e9",
    "INVESTIGATING": "#6366f1",
    "AWAITING_APPROVAL": "#d97706",
    "APPROVED": "#7c3aed",
    "EXECUTING": "#7c3aed",
    "VERIFIED": "#059669",
    "REJECTED": "#b91c1c",
    "FAILED": "#b91c1c",
    "CLOSED": "#334155",
}


class ApiError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _headers() -> dict[str, str]:
    token = st.session_state.get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def api(
    method: str,
    path: str,
    *,
    json: Any = None,
    params: dict[str, Any] | None = None,
    authenticated: bool = True,
) -> Any:
    """Call the API and return decoded JSON, raising a readable error."""
    headers = _headers() if authenticated else {}
    try:
        response = requests.request(
            method,
            f"{API_URL}{path}",
            json=json,
            params=params,
            headers=headers,
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ApiError(0, f"Cannot reach the API at {API_URL}: {exc}") from exc
    if response.status_code >= 400:
        try:
            payload = response.json()
            detail = payload.get("detail", response.text)
            if isinstance(detail, list):
                detail = "; ".join(str(item) for item in detail)
        except ValueError:
            detail = response.text[:800]
        raise ApiError(response.status_code, str(detail))
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(response.status_code, "API returned a non-JSON response") from exc


def logout() -> None:
    for key in ("token", "user", "api_url"):
        st.session_state.pop(key, None)
    st.rerun()


def login_screen() -> None:
    st.markdown(
        """
        <div style="max-width:560px;margin:8vh auto 0 auto;">
          <h1 style="margin-bottom:0;">AI-Agent Incident Response</h1>
          <p style="color:#64748b;margin-top:4px;">
            Web-application security operations console. All response actions are simulated.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, center, right = st.columns([1, 1.2, 1])
    with center:
        with st.form("login_form"):
            st.subheader("Sign in")
            username = st.text_input("Username", autocomplete="username")
            password = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
        st.caption(f"API: `{API_URL}`")
        if submitted:
            if not username or not password:
                st.error("Enter both username and password.")
                return
            try:
                payload = api(
                    "POST",
                    "/auth/login",
                    json={"username": username, "password": password},
                    authenticated=False,
                )
            except ApiError as exc:
                st.error(exc.detail)
                return
            st.session_state["token"] = payload["access_token"]
            st.session_state["user"] = payload["user"]
            st.session_state["api_url"] = API_URL
            st.rerun()
        st.info(
            "Use a local account created by `scripts/seed_database.py`, or run "
            "`python scripts/run_demo.py` to create a disposable demo admin.",
            icon="🔐",
        )


def require_session() -> None:
    if not st.session_state.get("token"):
        login_screen()
        st.stop()
    if st.session_state.get("api_url") != API_URL:
        # The configured API changed between runs; an old token is not valid.
        logout()
    try:
        me = api("GET", "/auth/me")
    except ApiError as exc:
        if exc.status_code in {401, 403}:
            st.session_state.clear()
            st.warning("Session expired. Sign in again.")
            st.stop()
        st.error(exc.detail)
        if st.button("Retry connection"):
            st.rerun()
        st.stop()
    st.session_state["user"] = me


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f"## {title}")
    st.caption(subtitle)


def mode_banner(metrics: dict[str, Any]) -> None:
    system = metrics.get("system", {})
    llm = system.get("llm", {})
    ti = system.get("threat_intel", {})
    modes = [
        f"LLM: **{llm.get('mode', 'UNKNOWN')}**",
        f"Threat intel: **{ti.get('mode', 'UNKNOWN')}**",
        "Response: **SIMULATION ONLY**",
        "Data: **synthetic_demo_data** in demo datasets",
    ]
    st.info(" · ".join(modes), icon="🧪")
    with st.expander("Runtime and integration status"):
        st.json(system)


def severity_chart(severity: dict[str, int]) -> go.Figure:
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    values = [int(severity.get(label, 0)) for label in labels]
    figure = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            marker_color=[SEVERITY_COLORS[label] for label in labels],
            text=values,
            textposition="auto",
        )
    )
    figure.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=20, b=10),
        yaxis_title="Incidents",
        xaxis_title=None,
        showlegend=False,
    )
    return figure


def donut_chart(mapping: dict[str, int], colors: dict[str, str] | None = None) -> go.Figure:
    labels = list(mapping.keys())
    values = [int(value) for value in mapping.values()]
    figure = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker_colors=[(colors or {}).get(label, "#64748b") for label in labels],
            textinfo="label+value",
        )
    )
    figure.update_layout(height=300, margin=dict(l=10, r=10, t=20, b=10), showlegend=False)
    return figure


def bar_chart(mapping: dict[str, int], title: str, color: str = "#0ea5e9") -> go.Figure:
    if not mapping:
        figure = go.Figure()
        figure.add_annotation(text="No data", showarrow=False)
        figure.update_layout(height=300)
        return figure
    labels = list(reversed(list(mapping.keys())))
    values = list(reversed(list(mapping.values())))
    figure = go.Figure(go.Bar(x=values, y=labels, orientation="h", marker_color=color, text=values, textposition="auto"))
    figure.update_layout(
        height=max(260, 30 * len(labels) + 80),
        margin=dict(l=10, r=10, t=30, b=10),
        title=title,
        xaxis_title="Incidents",
        yaxis_title=None,
    )
    return figure


def overview_page() -> None:
    page_header(
        "Security operations overview",
        "Live aggregates computed by the API from the current database. No client-side synthetic values.",
    )
    try:
        metrics = api("GET", "/api/metrics")
    except ApiError as exc:
        st.error(exc.detail)
        return
    mode_banner(metrics)
    totals = metrics.get("totals", {})
    columns = st.columns(5)
    columns[0].metric("Incidents", totals.get("incidents", 0))
    columns[1].metric("Security events", totals.get("events", 0))
    columns[2].metric("Alerts", totals.get("alerts", 0))
    columns[3].metric("Pending approvals", totals.get("pending_approvals", 0))
    columns[4].metric("Verified incidents", totals.get("verified_incidents", 0))

    audit = metrics.get("audit", {})
    if audit.get("chain_valid"):
        st.success(f"Audit hash chain valid across {audit.get('entries', 0)} entries.", icon="✅")
    else:
        st.error(f"Audit hash chain INVALID: {audit.get('error') or 'verification failed'}", icon="🚨")

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Incidents by severity")
        st.plotly_chart(severity_chart(metrics.get("severity", {})), width="stretch")
    with right:
        st.subheader("Incident status")
        status = metrics.get("status", {})
        if status:
            st.plotly_chart(donut_chart(status, STATUS_COLORS), width="stretch")
        else:
            st.caption("No incidents recorded yet.")

    timeseries = pd.DataFrame(metrics.get("timeseries", []))
    st.subheader("14-day activity")
    if not timeseries.empty:
        figure = px.line(
            timeseries,
            x="date",
            y=["events", "incidents"],
            markers=True,
            labels={"value": "Count", "variable": "Series", "date": "Date"},
        )
        figure.update_layout(height=300, margin=dict(l=10, r=10, t=20, b=10), legend_title=None)
        st.plotly_chart(figure, width="stretch")
    else:
        st.caption("No activity in the last 14 days.")

    left, right = st.columns([1, 1])
    with left:
        st.plotly_chart(
            bar_chart(metrics.get("attack_categories", {}), "Attack categories", "#6366f1"),
            width="stretch",
        )
    with right:
        mitre_rows = metrics.get("mitre_techniques", [])
        if mitre_rows:
            st.subheader("Most-mapped ATT&CK techniques")
            st.dataframe(pd.DataFrame(mitre_rows), width="stretch", hide_index=True)
        else:
            st.subheader("Most-mapped ATT&CK techniques")
            st.caption("No MITRE mappings recorded yet.")

    st.subheader("Pipeline timing")
    timing_columns = st.columns(3)
    response_time = metrics.get("response_time", {})
    approval_time = metrics.get("approval_time", {})
    investigation_time = metrics.get("investigation_time", {})
    response_avg = response_time.get("average_seconds")
    approval_avg = approval_time.get("average_seconds")
    investigation_avg = investigation_time.get("average_ms")
    timing_columns[0].metric(
        "Mean create-to-verify",
        f"{response_avg:.1f} s" if response_avg is not None else "NOT MEASURED",
        help=f"Samples: {response_time.get('samples', 0)}",
    )
    timing_columns[1].metric(
        "Mean create-to-approval",
        f"{approval_avg:.1f} s" if approval_avg is not None else "NOT MEASURED",
        help=f"Samples: {approval_time.get('samples', 0)}",
    )
    timing_columns[2].metric(
        "Mean investigation stage sum",
        f"{investigation_avg:.1f} ms" if investigation_avg is not None else "NOT MEASURED",
        help=f"Samples: {investigation_time.get('samples', 0)}",
    )

    st.subheader("Top source IPs")
    ips = metrics.get("top_source_ips", [])
    if ips:
        st.dataframe(pd.DataFrame(ips), width="stretch", hide_index=True)
    else:
        st.caption("No source IPs recorded.")


def _incident_filter_options(items: list[dict[str, Any]], field: str) -> list[str]:
    return sorted({str(item.get(field)) for item in items if item.get(field)})


def incidents_page() -> None:
    page_header(
        "Incidents",
        "Correlated incidents, evidence, agent reasoning, threat intelligence, MITRE mappings, risk and response.",
    )
    with st.container(border=True):
        columns = st.columns(4)
        limit = columns[0].selectbox("Limit", [25, 50, 100, 250], index=1)
        severity = columns[1].selectbox(
            "Severity", ["ANY", "CRITICAL", "HIGH", "MEDIUM", "LOW"], index=0
        )
        status = columns[2].selectbox(
            "Status",
            [
                "ANY",
                "NEW",
                "TRIAGED",
                "INVESTIGATING",
                "AWAITING_APPROVAL",
                "APPROVED",
                "VERIFIED",
                "REJECTED",
                "FAILED",
                "CLOSED",
            ],
            index=0,
        )
        approval = columns[3].selectbox(
            "Approval", ["ANY", "PENDING", "APPROVED", "REJECTED", "NOT_REQUIRED"], index=0
        )
    params: dict[str, Any] = {"limit": limit}
    if severity != "ANY":
        params["severity"] = severity
    if status != "ANY":
        params["status"] = status
    if approval != "ANY":
        params["approval_status"] = approval
    try:
        payload = api("GET", "/api/incidents", params=params)
    except ApiError as exc:
        st.error(exc.detail)
        return
    items = payload.get("items", [])
    if not items:
        st.info("No incidents match the selected filters.")
        return

    table = pd.DataFrame(
        [
            {
                "Incident": item["id"],
                "Created": item["created_at"],
                "Severity": item["severity"],
                "Risk": item.get("risk_score"),
                "Category": item.get("attack_category"),
                "Source IP": item.get("source_ip"),
                "Events": item.get("event_count"),
                "Status": item.get("status"),
                "Approval": item.get("approval_status"),
                "Title": item.get("title"),
            }
            for item in items
        ]
    )
    st.dataframe(table, width="stretch", hide_index=True)
    incident_id = st.selectbox("Open incident", [item["id"] for item in items])
    if not incident_id:
        return
    try:
        detail = api("GET", f"/api/incidents/{incident_id}")
    except ApiError as exc:
        st.error(exc.detail)
        return
    render_incident(detail)


def _fmt_time(value: str | None) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return value


def render_incident(detail: dict[str, Any]) -> None:
    incident = detail["incident"]
    risk = detail.get("risk") or {}
    response = detail.get("response") or {}
    st.divider()
    header_left, header_right = st.columns([3, 1])
    with header_left:
        st.subheader(f"{incident['id']} · {incident['title']}")
        st.caption(
            f"Created {_fmt_time(incident.get('created_at'))} · "
            f"source {incident.get('source_ip') or 'unknown'} · "
            f"updated {_fmt_time(incident.get('updated_at'))}"
        )
    with header_right:
        risk_level = risk.get("level") or incident.get("severity")
        st.markdown(
            f"<div style='text-align:right;'><span style='font-size:0.8rem;color:#64748b;'>RISK</span><br>"
            f"<span style='font-size:2rem;font-weight:700;color:{RISK_COLORS.get(risk_level, '#334155')};'>"
            f"{risk.get('score', incident.get('risk_score', 0)):.2f}</span>"
            f"<span style='color:#64748b;'> / 100 · {risk_level}</span></div>",
            unsafe_allow_html=True,
        )

    columns = st.columns(5)
    columns[0].metric("Severity", incident.get("severity"))
    columns[1].metric("Status", incident.get("status"))
    columns[2].metric("Category", incident.get("attack_category"))
    columns[3].metric("Confidence", f"{float(incident.get('confidence') or 0):.2f}")
    columns[4].metric("Approval", incident.get("approval_status"))

    tabs = st.tabs(
        [
            "Summary",
            "Timeline",
            "Evidence",
            "Threat intel",
            "MITRE",
            "Risk",
            "Response",
            "Approval",
            "Agent runs",
            "Audit",
        ]
    )
    with tabs[0]:
        st.write(incident.get("investigation_summary") or incident.get("description") or "No summary.")
        st.markdown("**Deterministic reasoning**")
        reasoning = incident.get("reasoning") or []
        if reasoning:
            for line in reasoning:
                st.markdown(f"- {line}")
        else:
            st.caption("No reasoning recorded.")
        st.markdown("**System modes**")
        st.json(detail.get("system", {}))
    with tabs[1]:
        timeline = detail.get("timeline", [])
        if timeline:
            st.dataframe(pd.DataFrame(timeline), width="stretch", hide_index=True)
        else:
            st.caption("No timeline entries.")
    with tabs[2]:
        evidence = detail.get("evidence", [])
        if evidence:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Type": item.get("evidence_type"),
                            "Description": item.get("description"),
                            "Weight": item.get("weight"),
                            "Event": item.get("event_id"),
                            "Created": item.get("created_at"),
                        }
                        for item in evidence
                    ]
                ),
                width="stretch",
                hide_index=True,
            )
            with st.expander("Evidence details (JSON)"):
                st.json(evidence)
        else:
            st.caption("No evidence records.")
    with tabs[3]:
        intel = detail.get("threat_intelligence", [])
        if intel:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Indicator": item.get("indicator"),
                            "Type": item.get("indicator_type"),
                            "Provider": item.get("provider"),
                            "Verdict": item.get("verdict"),
                            "Score": item.get("score"),
                            "Malicious": item.get("malicious"),
                            "Mode": item.get("mode"),
                            "Mock": item.get("is_mock"),
                            "Fetched": item.get("fetched_at"),
                            "Error": item.get("error"),
                        }
                        for item in intel
                    ]
                ),
                width="stretch",
                hide_index=True,
            )
            st.warning("DEMO/MOCK intelligence is labelled and must not be treated as live reputation.", icon="🧪")
        else:
            st.caption("No threat-intelligence records.")
    with tabs[4]:
        mappings = detail.get("mitre", [])
        if mappings:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Technique": item.get("technique_id"),
                            "Name": item.get("technique_name"),
                            "Sub-technique": item.get("subtechnique"),
                            "Tactic": item.get("tactic"),
                            "Confidence": item.get("confidence"),
                            "Status": item.get("mapping_status"),
                            "Rationale": item.get("rationale"),
                        }
                        for item in mappings
                    ]
                ),
                width="stretch",
                hide_index=True,
            )
            st.caption(
                "Confidence is a heuristic from configured base values plus corroborating evidence; "
                "it is not a statistical probability."
            )
        else:
            st.caption("No defensible ATT&CK mapping was produced for this incident.")
    with tabs[5]:
        if not risk:
            st.caption("No risk assessment recorded.")
        else:
            factors = risk.get("factors", {})
            rows = []
            for name, item in factors.items():
                if not isinstance(item, dict):
                    continue
                rows.append(
                    {
                        "Factor": name,
                        "Raw": str(item.get("raw")),
                        "Normalized": item.get("normalized"),
                        "Weight": item.get("weight"),
                        "Contribution": item.get("contribution"),
                    }
                )
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            st.progress(min(1.0, max(0.0, float(risk.get("score", 0)) / 100)))
            st.write(risk.get("explanation", ""))
            st.caption("Formula: score = 100 × Σ(weight × normalized factor). Weights are project-defined.")
    with tabs[6]:
        actions = response.get("actions", [])
        if actions:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Action": item.get("action_type"),
                            "Description": item.get("description"),
                            "Risk": item.get("risk_level"),
                            "Approval": item.get("requires_approval"),
                            "Policy": item.get("policy_mode"),
                            "Status": item.get("status"),
                            "Simulated": item.get("is_simulated"),
                            "Executed": item.get("executed_at"),
                            "Result": str(item.get("result")),
                        }
                        for item in actions
                    ]
                ),
                width="stretch",
                hide_index=True,
            )
            with st.expander("Full response plan (JSON)"):
                st.json(actions)
        else:
            st.caption("No response plan recorded.")
        if response.get("approval_required"):
            st.warning(
                "This incident contains approval-gated actions. They cannot execute until an "
                "authorized analyst or admin approves the complete plan.",
                icon="🔒",
            )
    with tabs[7]:
        approvals = detail.get("approvals", [])
        if approvals:
            st.dataframe(pd.DataFrame(approvals), width="stretch", hide_index=True)
        else:
            st.caption("No approval decisions recorded.")
        render_approval_controls(detail)
    with tabs[8]:
        runs = detail.get("agent_runs", [])
        if runs:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Stage": item.get("stage"),
                            "Status": item.get("status"),
                            "Duration (ms)": item.get("duration_ms"),
                            "Provider": item.get("provider"),
                            "Started": item.get("started_at"),
                            "Finished": item.get("finished_at"),
                        }
                        for item in runs
                    ]
                ),
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No agent-run records.")
    with tabs[9]:
        audit = detail.get("audit", [])
        if audit:
            st.dataframe(pd.DataFrame(audit), width="stretch", hide_index=True)
        else:
            st.caption("No audit entries for this incident.")


def render_approval_controls(detail: dict[str, Any]) -> None:
    incident = detail["incident"]
    user = st.session_state.get("user", {})
    role = (user.get("role") or "viewer").lower()
    response = detail.get("response") or {}
    status = incident.get("status")

    st.markdown("### Decision")
    if role not in {"analyst", "admin"}:
        st.info("Viewer accounts are read-only. Approval and execution require analyst or admin role.")
        return
    if status == "AWAITING_APPROVAL":
        pending = [
            action
            for action in response.get("actions", [])
            if action.get("requires_approval") and action.get("status") == "PENDING_APPROVAL"
        ]
        st.caption(f"{len(pending)} approval-gated action(s) are waiting. Partial approval is not supported.")
        with st.form(f"approve_{incident['id']}"):
            reason = st.text_area(
                "Decision reason (recorded in the audit chain)",
                value="Reviewed evidence and risk; approved for simulated execution.",
            )
            confirm = st.checkbox("I understand every response action is simulated and allowlisted.")
            approve = st.form_submit_button("Approve plan", type="primary", disabled=not confirm)
            reject = st.form_submit_button("Reject plan", disabled=not confirm)
        if approve:
            if len(reason.strip()) < 3:
                st.error("Provide a reason of at least 3 characters.")
            else:
                try:
                    api(
                        "POST",
                        f"/api/incidents/{incident['id']}/approve",
                        json={
                            "reason": reason.strip(),
                            "action_ids": [action["id"] for action in pending],
                        },
                    )
                    st.success("Plan approved. You may now execute the simulated actions.")
                    st.rerun()
                except ApiError as exc:
                    st.error(exc.detail)
        if reject:
            if len(reason.strip()) < 3:
                st.error("Rejection reason must be at least 3 characters.")
            else:
                try:
                    api(
                        "POST",
                        f"/api/incidents/{incident['id']}/reject",
                        json={"reason": reason.strip()},
                    )
                    st.warning("Plan rejected. No action will execute.")
                    st.rerun()
                except ApiError as exc:
                    st.error(exc.detail)
    elif status == "APPROVED" and incident.get("approval_status") == "APPROVED":
        st.caption(
            "The plan is approved. Execution is simulated, allowlist-checked and verified by the backend."
        )
        confirm = st.checkbox("Execute approved simulated actions", key=f"exec_confirm_{incident['id']}")
        if st.button(
            "Execute simulated plan",
            type="primary",
            disabled=not confirm,
            key=f"exec_{incident['id']}",
        ):
            try:
                result = api("POST", f"/api/incidents/{incident['id']}/execute")
                verification = result.get("verification") or {}
                st.success(
                    "Execution complete. Verification: "
                    + ("PASSED" if verification.get("verified") else "FAILED")
                )
                st.json(result.get("execution") or {})
                st.rerun()
            except ApiError as exc:
                st.error(exc.detail)
    elif status in {"VERIFIED", "REJECTED", "CLOSED", "FAILED"}:
        st.caption(f"Incident is {status}; no approval decision is pending.")
    else:
        st.caption(f"No approval-gated action is available in status {status}.")


def audit_page() -> None:
    page_header(
        "Audit trail",
        "Tamper-evident, hash-chained record of ingestion, investigation, approvals, execution and verification.",
    )
    user = st.session_state.get("user", {})
    role = (user.get("role") or "viewer").lower()
    if role not in {"analyst", "admin"}:
        st.info("Audit-log access requires analyst or admin role.")
        return
    try:
        system = api("GET", "/api/system")
    except ApiError as exc:
        st.error(exc.detail)
        return
    chain = system.get("audit", {})
    if chain.get("valid"):
        st.success(f"Hash chain valid · {chain.get('entries', 0)} entries.", icon="✅")
    else:
        st.error(f"Hash chain INVALID · {chain.get('error') or 'verification failed'}", icon="🚨")
    with st.container(border=True):
        columns = st.columns([1, 2, 2])
        limit = columns[0].selectbox("Limit", [50, 100, 250, 500, 1000], index=1)
        action = columns[1].text_input("Action filter (exact)", placeholder="RESPONSE_APPROVED")
        incident_id = columns[2].text_input("Incident filter", placeholder="INC-0001")
    params: dict[str, Any] = {"limit": limit}
    if action.strip():
        params["action"] = action.strip()
    if incident_id.strip():
        params["incident_id"] = incident_id.strip()
    try:
        payload = api("GET", "/api/audit", params=params)
    except ApiError as exc:
        st.error(exc.detail)
        return
    entries = payload.get("entries", [])
    if not entries:
        st.info("No audit entries match the filters.")
        return
    frame = pd.DataFrame(
        [
            {
                "ID": item.get("id"),
                "Timestamp": item.get("timestamp"),
                "Actor": item.get("actor"),
                "Role": item.get("actor_role"),
                "Action": item.get("action"),
                "Outcome": item.get("outcome"),
                "Incident": item.get("incident_id"),
                "Entity": item.get("entity_id"),
                "Hash": (item.get("entry_hash") or "")[:12],
            }
            for item in entries
        ]
    )
    st.dataframe(frame, width="stretch", hide_index=True)
    with st.expander("Selected entry details"):
        selected = st.selectbox("Audit entry ID", [item.get("id") for item in entries])
        record = next((item for item in entries if item.get("id") == selected), None)
        st.json(record or {})


def main() -> None:
    st.set_page_config(
        page_title="AI-Agent Incident Response",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
          .block-container {padding-top: 2rem; padding-bottom: 3rem;}
          div[data-testid="stMetric"] {border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px 14px;}
          div[data-testid="stMetricLabel"] {font-size: 0.78rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )
    require_session()
    user = st.session_state.get("user", {})
    with st.sidebar:
        st.markdown("## 🛡️ SOC Console")
        st.caption(f"Signed in as **{user.get('username')}** ({user.get('role')})")
        page = st.radio("View", ["Overview", "Incidents", "Audit trail"], label_visibility="collapsed")
        st.divider()
        st.caption(f"API: `{API_URL}`")
        st.caption("All response actions are simulated. The LLM is advisory only.")
        if st.button("Sign out", width="stretch"):
            logout()
    if page == "Overview":
        overview_page()
    elif page == "Incidents":
        incidents_page()
    else:
        audit_page()


if __name__ == "__main__":
    main()
