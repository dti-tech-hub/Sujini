"""Application configuration loading and environment resolution.

Configuration is intentionally file-based (YAML) for project parameters, with
secrets and deployment-specific values supplied through environment variables.
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"
MODELS_DIR = PROJECT_ROOT / "models"

load_dotenv(PROJECT_ROOT / ".env")


def _ensure_directories() -> None:
    for path in (
        DATA_DIR,
        DATA_DIR / "raw",
        DATA_DIR / "processed",
        DATA_DIR / "sample_logs",
        DATA_DIR / "sample_alerts",
        DATA_DIR / "datasets",
        RESULTS_DIR / "metrics",
        RESULTS_DIR / "figures",
        RESULTS_DIR / "reports",
        RESULTS_DIR / "logs",
        MODELS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def _read_yaml(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file {path} must contain a mapping")
    return data


@lru_cache(maxsize=1)
def get_config() -> dict[str, Any]:
    """Load and cache the primary configuration."""
    config = _read_yaml("config.yaml")
    env_database = os.getenv("DATABASE_URL")
    if env_database:
        config.setdefault("database", {})["url"] = env_database
    env_cors = os.getenv("CORS_ORIGINS")
    if env_cors:
        config.setdefault("api", {})["cors_origins"] = [
            item.strip() for item in env_cors.split(",") if item.strip()
        ]
    env_demo = os.getenv("DEMO_MODE")
    if env_demo is not None:
        config.setdefault("app", {})["demo_mode"] = env_demo.lower() in {"1", "true", "yes"}
    return config


@lru_cache(maxsize=1)
def get_risk_rules() -> dict[str, Any]:
    return _read_yaml("risk_rules.yaml")


@lru_cache(maxsize=1)
def get_mitre_config() -> dict[str, Any]:
    return _read_yaml("mitre_mapping.yaml")


@lru_cache(maxsize=1)
def get_response_rules() -> dict[str, Any]:
    return _read_yaml("response_rules.yaml")


@lru_cache(maxsize=1)
def get_detection_rules() -> dict[str, Any]:
    return _read_yaml("detection_rules.yaml")


def reload_config() -> None:
    """Clear cached configuration (used by tests and long-running tooling)."""
    for func in (get_config, get_risk_rules, get_mitre_config, get_response_rules, get_detection_rules):
        func.cache_clear()


def get_secret_key() -> str:
    """Return the JWT signing secret.

    Priority: SOC_SECRET_KEY environment variable, then a locally generated
    key persisted in data/.secret_key. A random secret is never embedded in
    source code and the generated file is git-ignored.
    """
    env_secret = os.getenv("SOC_SECRET_KEY", "").strip()
    if env_secret:
        return env_secret
    _ensure_directories()
    key_path = DATA_DIR / ".secret_key"
    if key_path.exists():
        value = key_path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    key_path.write_text(value, encoding="utf-8")
    try:  # Best-effort restrictive permissions (POSIX; no-op semantics on Windows).
        key_path.chmod(0o600)
    except OSError:
        pass
    return value


def resolve_database_url(url: str | None = None) -> str:
    """Resolve a relative SQLite URL against the project root.

    This makes commands behave identically whether they are launched from the
    repository root, `scripts/`, or an IDE working directory.
    """
    value = url or os.getenv("DATABASE_URL") or str(get_config()["database"]["url"])
    if value.startswith("sqlite:///") and not value.startswith("sqlite:////"):
        raw = value[len("sqlite:///") :]
        if raw.startswith(":memory:") or raw == "":
            return value
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return f"sqlite:///{candidate.resolve().as_posix()}"
    return value


def get_bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def llm_settings() -> dict[str, Any]:
    cfg = get_config().get("llm", {})
    enabled_env = os.getenv("LLM_ENABLED")
    enabled = get_bool_env("LLM_ENABLED", bool(cfg.get("enabled", False))) if enabled_env is not None else bool(cfg.get("enabled", False))
    api_key = os.getenv("LLM_API_KEY", "").strip()
    # An explicit enabled flag without a key is treated as not configured.
    configured = enabled and bool(api_key)
    return {
        "enabled": enabled,
        "configured": configured,
        "api_key": api_key,
        "base_url": os.getenv("LLM_BASE_URL", str(cfg.get("base_url", "https://api.openai.com/v1"))).rstrip("/"),
        "model": os.getenv("LLM_MODEL", str(cfg.get("model", "gpt-4o-mini"))),
        "timeout_seconds": int(os.getenv("LLM_TIMEOUT_SECONDS", cfg.get("timeout_seconds", 25))),
        "max_tokens": int(cfg.get("max_tokens", 900)),
        "temperature": float(cfg.get("temperature", 0.0)),
    }


def threat_intel_settings() -> dict[str, Any]:
    cfg = dict(get_config().get("threat_intelligence", {}))
    cfg["virustotal_api_key"] = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    cfg["abuseipdb_api_key"] = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if os.getenv("THREAT_INTEL_ALLOW_MOCK_FALLBACK") is not None:
        cfg["mock_fallback"] = get_bool_env("THREAT_INTEL_ALLOW_MOCK_FALLBACK", True)
    return cfg


def runtime_summary() -> dict[str, Any]:
    """Non-secret configuration summary for health output and reproducibility."""
    llm = llm_settings()
    ti = threat_intel_settings()
    return {
        "app_version": get_config().get("app", {}).get("version", "unknown"),
        "demo_mode": bool(get_config().get("app", {}).get("demo_mode", True)),
        "llm_mode": "configured" if llm["configured"] else "demo_template",
        "threat_intel_mode": "configured" if (ti.get("virustotal_api_key") or ti.get("abuseipdb_api_key")) else "mock",
        "llm_model": llm["model"] if llm["configured"] else None,
        "database_url_scheme": resolve_database_url().split(":", 1)[0],
    }


_ensure_directories()
