"""Feature engineering shared by ML training, prediction, and evaluation."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from src.utils.helpers import safe_float, safe_int, utcnow

FEATURE_NAMES = [
    "status_code",
    "method_post",
    "path_length",
    "query_length",
    "has_sql_meta",
    "has_traversal",
    "has_cmd_meta",
    "is_login",
    "failed_login",
    "ua_suspicious",
    "body_length",
    "hour",
    "response_size",
    "missing_username",
]

_SQL = re.compile(r"(?i)(union\s+select|or\s+1=1|sleep\s*\(|information_schema|xp_cmdshell|'\s*or\s*')")
_TRAV = re.compile(r"(\.\./)|(\.\.\\)|(%2e%2e)")
_CMD = re.compile(r"(?i)(;\s*(whoami|id|cat|curl|wget|bash|sh|nc|powershell|cmd\.exe))|(\|\|\s*(whoami|id|cat))|(\$\((whoami|id|cat))")
_UA = re.compile(r"(?i)(sqlmap|nikto|nuclei|nmap|masscan|hydra|acunetix|nessus|dirbuster|gobuster|wpscan|metasploit|zgrab)")


def _field(event: Any, name: str, default: Any = None) -> Any:
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


def features_from_event(event: Any) -> list[float]:
    """Extract the fixed-length numeric feature vector for one event."""
    endpoint = str(_field(event, "endpoint") or _field(event, "destination") or "")
    message = str(_field(event, "message") or "")
    user_agent = str(_field(event, "user_agent") or "")
    raw = _field(event, "raw_event") or {}
    if isinstance(raw, str):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    body = str(
        raw.get("_sanitized_request_body")
        or raw.get("request_body")
        or _field(event, "request_body")
        or ""
    )
    text = f"{endpoint} {message} {body}"
    query = endpoint.split("?", 1)[1] if "?" in endpoint else ""
    ts = _field(event, "timestamp") or utcnow()
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = utcnow()
    response_size = safe_float(raw.get("response_size", raw.get("size", 0)))
    event_type = str(_field(event, "event_type") or "")
    status = safe_int(_field(event, "status_code"), 0)
    return [
        float(status),
        1.0 if str(_field(event, "method") or "").upper() == "POST" else 0.0,
        float(len(endpoint)),
        float(len(query)),
        1.0 if _SQL.search(text) else 0.0,
        1.0 if _TRAV.search(text) else 0.0,
        1.0 if _CMD.search(text) else 0.0,
        1.0 if any(token in endpoint.lower() for token in ("/login", "/signin", "/auth")) else 0.0,
        1.0 if event_type == "failed_login" or status == 401 else 0.0,
        1.0 if _UA.search(user_agent) else 0.0,
        float(len(body)),
        float(ts.hour if hasattr(ts, "hour") else 0),
        response_size,
        0.0 if _field(event, "username") else 1.0,
    ]


def rows_from_events(events: list[Any]) -> list[list[float]]:
    return [features_from_event(event) for event in events]
