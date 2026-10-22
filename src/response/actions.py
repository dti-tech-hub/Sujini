"""Response action catalog and allowlist enforcement."""
from __future__ import annotations

from typing import Any

from src.utils.config import get_response_rules


def action_catalog() -> dict[str, dict[str, Any]]:
    return get_response_rules().get("actions", {})


def allowlist() -> set[str]:
    return set(get_response_rules().get("allowlist", []))


def is_allowed_action(action_type: str) -> bool:
    return action_type in allowlist() and action_type in action_catalog()


def action_definition(action_type: str) -> dict[str, Any]:
    return action_catalog().get(action_type, {})


def simulation_mode() -> bool:
    return bool(get_response_rules().get("simulation_mode", True))
