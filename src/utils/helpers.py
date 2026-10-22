"""Small, dependency-free helpers shared across the project."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

UTC = timezone.utc


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def ensure_utc(value: datetime | None = None) -> datetime:
    if value is None:
        return utcnow()
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_timestamp(value: Any, default: datetime | None = None) -> tuple[datetime, bool]:
    """Parse common timestamp representations.

    Returns (timestamp, was_missing_or_invalid). The boolean lets callers mark
    events that had to fall back to receipt time rather than silently
    pretending a timestamp was supplied.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return ensure_utc(default), True
    if isinstance(value, datetime):
        return ensure_utc(value), False
    if isinstance(value, (int, float)):
        try:
            # Heuristic: milliseconds vs seconds.
            seconds = float(value) / 1000.0 if float(value) > 10_000_000_000 else float(value)
            return datetime.fromtimestamp(seconds, tz=UTC), False
        except (OverflowError, OSError, ValueError):
            return ensure_utc(default), True
    text = str(value).strip()
    normalized = text.replace("Z", "+00:00")
    try:
        return ensure_utc(datetime.fromisoformat(normalized)), False
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S"):
        try:
            return ensure_utc(datetime.strptime(text, fmt)), False
        except ValueError:
            continue
    return ensure_utc(default), True


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return ensure_utc(value).isoformat()


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


def stable_hash(*parts: Any, length: int = 32) -> str:
    payload = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:length]


def hash_chain(previous_hash: str, payload: str) -> str:
    return hashlib.sha256(f"{previous_hash}:{payload}".encode("utf-8")).hexdigest()


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def round4(value: float) -> float:
    return round(float(value), 4)


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str, ensure_ascii=True))


def dumps(value: Any) -> str:
    return json.dumps(json_safe(value), ensure_ascii=True, sort_keys=True)


def truncate(value: str | None, limit: int) -> str:
    if not value:
        return ""
    return value if len(value) <= limit else value[: limit - 3] + "..."


def bucket_time(value: datetime, minutes: int) -> str:
    ts = ensure_utc(value)
    epoch_minutes = int(ts.timestamp() // (minutes * 60))
    return str(epoch_minutes)


def normalize_ip(value: Any) -> tuple[str | None, bool]:
    """Return (canonical IP or None, valid_flag)."""
    if value is None:
        return None, False
    text = str(value).strip()
    if not text:
        return None, False
    try:
        return str(ipaddress.ip_address(text)), True
    except ValueError:
        return None, False


def is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
        or ip.is_link_local or ip.is_unspecified
    )


def is_documentation_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def percent(part: int | float, total: int | float) -> float:
    if not total:
        return 0.0
    return round(100.0 * float(part) / float(total), 2)


def chunked(items: Iterable[Any], size: int) -> Iterable[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def parse_user_agent(value: str | None) -> str:
    return truncate(value or "unknown", 300)


def time_window(dt: datetime, minutes: int) -> tuple[datetime, datetime]:
    end = ensure_utc(dt)
    return end - timedelta(minutes=minutes), end


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def natural_sort_key(text: str) -> list[Any]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", text)]
