"""Normalization of heterogeneous security events into one schema."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from src.security.sanitization import (
    detect_prompt_injection, redact_secrets, sanitize_endpoint,
    sanitize_text, sanitize_user_agent, sanitize_username,
)
from src.utils.helpers import (
    dumps, is_documentation_ip, normalize_ip, parse_timestamp, stable_hash,
    truncate, utcnow,
)

_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[^"]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

_ALIASES = {
    "source_ip": ("source_ip", "src_ip", "ip", "remote_addr", "client_ip", "sourceAddress"),
    "destination_ip": ("destination_ip", "dst_ip", "dest_ip", "server_ip"),
    "username": ("username", "user", "account", "user_name"),
    "method": ("method", "http_method", "verb"),
    "endpoint": ("endpoint", "url", "path", "destination", "request_uri", "uri"),
    "status_code": ("status_code", "status", "response_code", "http_status"),
    "user_agent": ("user_agent", "ua", "http_user_agent"),
    "event_type": ("event_type", "type", "alert_type", "category"),
    "severity": ("severity", "level", "priority"),
    "message": ("message", "msg", "description", "alert", "detail"),
    "timestamp": ("timestamp", "ts", "time", "@timestamp", "datetime", "event_time"),
    "request_body": ("request_body", "body", "payload", "post_data"),
    "dataset_label": ("dataset_label", "label", "ground_truth"),
}

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

DEFAULT_AUTH_ENDPOINT_TOKENS = (
    "/login", "/signin", "/sign-in", "/sign_in", "/auth", "/session",
    "/token", "/oauth", "/mfa", "/password", "/sso",
)


def is_auth_endpoint(endpoint: str | None, tokens: tuple[str, ...] | None = None) -> bool:
    """Return True when the path belongs to an authentication flow.

    Authorization failures outside these paths are access-control events, not
    failed logins, and must not inflate brute-force counters.
    """
    path = (endpoint or "").lower()
    return any(token in path for token in (tokens or DEFAULT_AUTH_ENDPOINT_TOKENS))


def _first(payload: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return default


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {sanitize_text(k, 100): _bounded(v, depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, list):
        return [_bounded(v, depth + 1) for v in value[:50]]
    if isinstance(value, str):
        return sanitize_text(redact_secrets(value), 2000)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_text(str(value), 500)


def parse_web_log_line(line: str) -> dict[str, Any]:
    """Parse an Apache/Nginx combined-log line into raw fields."""
    match = _CLF.match(line.strip())
    if not match:
        return {"message": line, "event_type": "web_log_unparsed"}
    groups = match.groupdict()
    return {
        "source_ip": groups.get("ip"),
        "username": groups.get("user") if groups.get("user") not in {"-", None} else None,
        "timestamp": groups.get("ts"),
        "method": groups.get("method"),
        "endpoint": groups.get("path"),
        "status_code": groups.get("status"),
        "user_agent": groups.get("ua") if groups.get("ua") not in {"-", None} else None,
        "message": "web access log",
        "event_type": "http_request",
        "raw_line": line,
    }


def infer_event_type(endpoint: str | None, status_code: int | None) -> str:
    path = (endpoint or "").lower()
    if any(token in path for token in ("/login", "/signin", "/auth")):
        if status_code in {401, 403}:
            return "failed_login"
        if status_code in {200, 201, 302, 303}:
            return "successful_login"
    if status_code == 401:
        return "unauthorized_access"
    if status_code == 403:
        return "forbidden_access"
    if status_code is not None and status_code >= 500:
        return "server_error"
    return "http_request"


def infer_severity(event_type: str, status_code: int | None) -> str:
    mapping = {
        "failed_login": "LOW",
        "successful_login": "INFO",
        "unauthorized_access": "MEDIUM",
        "forbidden_access": "MEDIUM",
        "server_error": "LOW",
        "sql_injection": "HIGH",
        "xss": "HIGH",
        "command_injection": "CRITICAL",
        "path_traversal": "HIGH",
        "brute_force": "HIGH",
        "malicious_ip": "HIGH",
    }
    return mapping.get(event_type, "INFO")


def normalize_event(payload: dict[str, Any], *, source: str = "api") -> dict[str, Any]:
    """Convert an arbitrary alert/log record into a SecurityEvent payload.

    Returns a dictionary ready for `repository.add_event`, including
    normalization warnings in `raw_event["_normalization"]`.
    """
    original: dict[str, Any] = dict(payload or {})
    if isinstance(original.get("line"), str):
        parsed = parse_web_log_line(original["line"])
        original.pop("line", None)
        merged = {**parsed, **original}
        original = merged

    now = utcnow()
    ts_raw = _first(original, _ALIASES["timestamp"])
    timestamp, timestamp_missing = parse_timestamp(ts_raw, default=now)

    raw_ip = _first(original, _ALIASES["source_ip"])
    source_ip, ip_valid = normalize_ip(raw_ip)
    dst_raw = _first(original, _ALIASES["destination_ip"])
    destination_ip, dst_valid = normalize_ip(dst_raw)
    username = sanitize_username(_first(original, _ALIASES["username"], "")) or None

    endpoint = sanitize_endpoint(_first(original, _ALIASES["endpoint"], "")) or None
    if endpoint:
        # If a full URL was supplied, retain only its path/query.
        if "://" in endpoint:
            split = urlsplit(endpoint)
            endpoint = sanitize_endpoint((split.path or "/") + (("?" + split.query) if split.query else ""))
        elif not endpoint.startswith("/"):
            endpoint = "/" + endpoint

    method = sanitize_text(_first(original, _ALIASES["method"], ""), 12).upper() or None
    status_raw = _first(original, _ALIASES["status_code"])
    try:
        status_code = int(status_raw) if status_raw not in (None, "") else None
    except (TypeError, ValueError):
        status_code = None
    user_agent = sanitize_user_agent(_first(original, _ALIASES["user_agent"], "")) or None
    message = sanitize_text(_first(original, _ALIASES["message"], ""), 2000)
    request_body = sanitize_text(_first(original, _ALIASES["request_body"], ""), 2000)

    event_type = sanitize_text(_first(original, _ALIASES["event_type"], ""), 64).lower().replace(" ", "_")
    if not event_type or event_type in {"alert", "security_alert"}:
        event_type = infer_event_type(endpoint, status_code)

    severity = str(_first(original, _ALIASES["severity"], "") or "").upper()
    if severity not in _SEVERITIES:
        severity = infer_severity(event_type, status_code)

    dataset_label = _first(original, _ALIASES["dataset_label"])
    dataset_label = sanitize_text(dataset_label, 64) or None

    combined_text = " ".join(filter(None, [endpoint, message, user_agent, request_body]))
    injection_flags = detect_prompt_injection(combined_text)
    warnings: list[str] = []
    if timestamp_missing:
        warnings.append("timestamp_missing_or_invalid: receipt time used")
    if raw_ip and not ip_valid:
        warnings.append("invalid_source_ip: value preserved only in raw_event")
    if dst_raw and not dst_valid:
        warnings.append("invalid_destination_ip")
    if injection_flags:
        warnings.append("prompt_injection_pattern_detected: treated as untrusted data")
    if not username:
        warnings.append("username_missing")

    dedup_hash = stable_hash(
        timestamp.replace(microsecond=0).isoformat(),
        source_ip or sanitize_text(raw_ip, 64),
        username,
        method,
        endpoint,
        status_code,
        event_type,
        message[:300],
        request_body[:200],
        length=64,
    )

    raw = _bounded(original)
    raw["_normalization"] = {
        "warnings": warnings,
        "prompt_injection_flags": len(injection_flags),
        "synthetic_documentation_ip": is_documentation_ip(source_ip),
        "source": source,
    }
    if request_body:
        raw["_sanitized_request_body"] = request_body

    return {
        "timestamp": timestamp,
        "received_at": now,
        "source": sanitize_text(source, 64) or "api",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "user_agent": user_agent,
        "event_type": event_type or "unknown",
        "severity": severity,
        "message": message,
        "raw_event": raw,
        "dedup_hash": dedup_hash,
        "dataset_label": dataset_label,
    }


def serialized_event_size(payload: dict[str, Any]) -> int:
    return len(dumps(payload))


def parse_jsonl(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records
