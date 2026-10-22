"""Policy-based response planning."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.response.actions import action_definition, allowlist, simulation_mode
from src.utils.config import get_config, get_response_rules
from src.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PlannedAction:
    action_type: str
    description: str
    risk_level: str
    requires_approval: bool
    policy_mode: str  # auto | approval | advisory
    is_simulated: bool
    parameters: dict[str, Any] = field(default_factory=dict)
    recommendation_source: str = "policy_engine"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "description": self.description,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
            "policy_mode": self.policy_mode,
            "is_simulated": self.is_simulated,
            "parameters": self.parameters,
            "recommendation_source": self.recommendation_source,
        }


@dataclass
class ResponsePlan:
    actions: list[PlannedAction]
    approval_required: bool
    rationale: str
    policy_mode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [action.to_dict() for action in self.actions],
            "approval_required": self.approval_required,
            "rationale": self.rationale,
            "policy_mode": self.policy_mode,
        }


class ResponsePlanner:
    def __init__(self) -> None:
        self.rules = get_response_rules()
        self.config = get_config().get("response", {})
        self.allowed = allowlist()

    def _approval_for_level(self, level: str) -> bool:
        if level == "HIGH":
            return bool(self.config.get("require_approval_for_high", True))
        if level == "CRITICAL":
            return bool(self.config.get("require_approval_for_critical", True))
        if level == "MEDIUM":
            return bool(self.config.get("require_approval_for_medium", False))
        return False

    def _describe(self, action_type: str, source_ip: str | None, username: str | None) -> str:
        definition = action_definition(action_type)
        base = str(definition.get("description", action_type))
        target = []
        if source_ip and action_type in {"SIMULATE_BLOCK_IP", "SIMULATE_QUARANTINE"}:
            target.append(f"source {source_ip}")
        if username and action_type in {"SIMULATE_DISABLE_SESSION", "SIMULATE_RESET_CREDENTIAL"}:
            target.append(f"account '{username}'")
        return base + (f" Target: {', '.join(target)}." if target else "")

    def plan(self, *, incident_id: str, risk_level: str, category: str,
             source_ip: str | None, username: str | None, approval_required_hint: bool = False) -> ResponsePlan:
        level_rules = self.rules.get("levels", {}).get(risk_level, self.rules.get("levels", {}).get("MEDIUM", {}))
        selected: dict[str, PlannedAction] = {}

        def add(action_type: str, mode: str) -> None:
            if action_type in selected or action_type not in self.allowed:
                return
            definition = action_definition(action_type)
            if not definition:
                return
            requires = mode == "approval" and self._approval_for_level(risk_level)
            if mode == "auto" and definition.get("requires_approval") and self._approval_for_level(risk_level):
                # Catalog safety overrides an accidental auto assignment.
                mode = "approval"
                requires = True
            selected[action_type] = PlannedAction(
                action_type=action_type,
                description=self._describe(action_type, source_ip, username),
                risk_level=risk_level,
                requires_approval=requires,
                policy_mode=mode,
                is_simulated=bool(definition.get("simulated", True)),
                parameters={
                    "incident_id": incident_id,
                    "source_ip": source_ip,
                    "username": username,
                    "simulation": simulation_mode(),
                    "note": "Simulated response: no real firewall, session store, or credential is modified."
                    if definition.get("simulated", True) else "Record-only action.",
                },
            )

        for action_type in level_rules.get("auto", []):
            add(action_type, "auto")
        for action_type in level_rules.get("approval", []):
            add(action_type, "approval")
        for action_type in level_rules.get("advisory", []):
            add(action_type, "advisory")

        for action_type in self.rules.get("category_additions", {}).get(category, []):
            if action_type in selected:
                continue
            add(action_type, "approval" if risk_level in {"HIGH", "CRITICAL"} else "advisory")

        max_actions = int(self.config.get("max_actions_per_incident", 8))
        actions = list(selected.values())[:max_actions]
        approval_required = any(action.requires_approval for action in actions) or bool(approval_required_hint)
        category_note = self.rules.get("categories", {}).get(category, {}).get("description", "")
        rationale = (
            f"Risk level {risk_level} with category '{category}'. {category_note} "
            f"Policy requires human approval for {', '.join(action.action_type for action in actions if action.requires_approval) or 'no actions'}. "
            "All containment and remediation actions are simulated."
        )
        return ResponsePlan(
            actions=actions,
            approval_required=approval_required,
            rationale=rationale,
            policy_mode="simulation",
        )
