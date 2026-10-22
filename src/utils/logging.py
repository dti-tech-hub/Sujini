"""Structured JSON logging helpers."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.config import RESULTS_DIR, get_config

_CONFIGURED = False
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        context = []
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_") and key not in {
                "incident_id", "event_id", "action", "result", "duration_ms",
                "agent_stage", "request_id",
            }:
                continue
            if key not in _RESERVED and not key.startswith("_"):
                context.append(f"{key}={value}")
        return base + (" | " + " ".join(context) if context else "")


def setup_logging(level: str | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    cfg = get_config().get("logging", {})
    log_level = (level or cfg.get("level", "INFO")).upper()
    root = logging.getLogger()
    root.setLevel(log_level)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ConsoleFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)

    if cfg.get("json_logs", True):
        file_path = Path(cfg.get("file", "results/logs/app.jsonl"))
        if not file_path.is_absolute():
            file_path = RESULTS_DIR.parent / file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)

    # Reduce third-party noise.
    for noisy in ("httpx", "httpcore", "urllib3", "uvicorn.access", "streamlit"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)


def log_stage(logger: logging.Logger, stage: str, *, incident_id: str | None = None,
              duration_ms: float | None = None, result: str = "ok", **extra: Any) -> None:
    logger.info(
        "agent_stage",
        extra={
            "agent_stage": stage,
            "incident_id": incident_id,
            "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
            "result": result,
            **extra,
        },
    )
