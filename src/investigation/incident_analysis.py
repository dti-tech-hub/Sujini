"""Deterministic investigation agent with optional, validated LLM enrichment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from src.database.models import Alert, Incident, SecurityEvent
from src.investigation.correlation import CorrelationResult
from src.llm.base import LLMError
from src.llm.factory import build_llm_provider
from src.utils.helpers import clamp, iso
from src.utils.logging import get_logger

logger = get_logger(__name__)

CATEGORY_PRECEDENCE = [
    "command_injection",
    "account_compromise",
    "sql_injection",
    "xss",
    "path_traversal",
    "unauthorized_access",
    "brute_force",
    "abnormal_traffic",
    "malicious_ip",
    "recon_scanning",
    "prompt_injection_attempt",
    "suspicious_user_agent",
    "ml_anomaly",
]

BASE_CONFIDENCE = {
    "command_injection": 0.92,
    "account_compromise": 0.88,
    "sql_injection": 0.90,
    "xss": 0.86,
    "path_traversal": 0.85,
    "unauthorized_access": 0.72,
    "brute_force": 0.88,
    "abnormal_traffic": 0.62,
    "malicious_ip": 0.68,
    "recon_scanning": 0.70,
    "prompt_injection_attempt": 0.80,
    "suspicious_user_agent": 0.60,
    "ml_anomaly": 0.48,
    "suspicious_activity": 0.40,
    "benign_or_unknown": 0.35,
}

SEVERITY_BY_CATEGORY = {
    "command_injection": "CRITICAL",
    "account_compromise": "CRITICAL",
    "sql_injection": "HIGH",
    "xss": "HIGH",
    "path_traversal": "HIGH",
    "unauthorized_access": "HIGH",
    "brute_force": "HIGH",
    "abnormal_traffic": "MEDIUM",
    "malicious_ip": "HIGH",
    "recon_scanning": "MEDIUM",
    "prompt_injection_attempt": "MEDIUM",
    "suspicious_user_agent": "MEDIUM",
    "suspicious_activity": "LOW",
    "benign_or_unknown": "LOW",
}

NEXT_STEPS = {
    "account_compromise": [
        "Verify with the account owner whether the successful authentication was legitimate.",
        "Review all actions performed after the successful login and preserve the request logs.",
        "Rotate the account credential and invalidate active sessions if compromise is confirmed.",
        "Check the source IP against firewall, VPN, and proxy logs.",
    ],
    "brute_force": [
        "Confirm whether any authentication attempt from the source succeeded.",
        "Review the source IP reputation and block it if suspicious.",
        "Enforce rate limiting and multi-factor authentication on the login endpoint.",
    ],
    "sql_injection": [
        "Inspect the targeted endpoint and server responses for signs of successful injection.",
        "Review application parameterization and WAF logs for the request.",
        "Preserve the full request as evidence and notify the application owner.",
    ],
    "xss": [
        "Inspect the targeted endpoint for reflected or stored script content in responses.",
        "Check whether the payload was rendered to other users and review Content-Security-Policy coverage.",
        "Preserve the request as evidence and correct output encoding on the affected endpoint.",
    ],
    "unauthorized_access": [
        "Confirm whether the denied requests came from an authorized user or an expired session.",
        "Review the targeted endpoints' access-control rules and server logs for any successful access.",
        "Preserve the request evidence and rotate session tokens if credential misuse is suspected.",
    ],
    "command_injection": [
        "Inspect server process and command logs for execution traces.",
        "Preserve the request and response, then isolate the workload if execution is suspected.",
        "Review input validation on the affected endpoint.",
    ],
    "path_traversal": [
        "Verify whether any sensitive file was served successfully.",
        "Review web-server path normalization and access controls.",
        "Preserve request and response evidence.",
    ],
    "malicious_ip": [
        "Review all requests from the watchlisted source.",
        "Validate the indicator against at least one live threat-intelligence provider before blocking.",
        "Apply the organization's firewall change process if the indicator is confirmed.",
    ],
    "abnormal_traffic": [
        "Determine whether the traffic source is a load test, scanner, or abuse.",
        "Check response times and error rates for service impact.",
        "Apply rate limiting if the behavior is not authorized.",
    ],
    "recon_scanning": [
        "Review which paths were probed and whether any returned sensitive content.",
        "Block the scanner if it is not an authorized assessment.",
        "Check web-server and WAF rules for sensitive-path exposure.",
    ],
    "prompt_injection_attempt": [
        "Treat the log content as hostile data; do not act on its instructions.",
        "Review who can write to this log source and whether log integrity is compromised.",
        "Preserve the event and notify the AI-platform owner.",
    ],
    "suspicious_activity": [
        "Review the correlated events and collect additional context from the web server.",
        "Validate the alert with the application owner before containment.",
    ],
    "benign_or_unknown": [
        "Continue monitoring; no deterministic attack signature was found.",
    ],
}


@dataclass
class InvestigationResult:
    classification: str
    confidence: float
    severity: str
    summary: str
    reasoning: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    llm_mode: str = "DEMO_TEMPLATE"
    llm_provider: str = "deterministic_template"
    llm_opinion: dict[str, Any] | None = None
    llm_error: str | None = None
    prompt_injection_detected: bool = False
    alert_types: list[str] = field(default_factory=list)
    baseline_classification: str = "benign_or_unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "recommended_next_steps": self.next_steps,
            "llm_mode": self.llm_mode,
            "llm_provider": self.llm_provider,
            "llm_opinion": self.llm_opinion,
            "llm_error": self.llm_error,
            "prompt_injection_detected": self.prompt_injection_detected,
            "alert_types": self.alert_types,
            "baseline_classification": self.baseline_classification,
        }


class InvestigationAgent:
    """Evidence-driven triage. Never derives actions from free-form text."""

    def __init__(self, session: Session, *, use_llm: bool = True) -> None:
        self.session = session
        self.provider, self.provider_mode = build_llm_provider() if use_llm else (None, "DISABLED")

    def _candidate_category(self, alert_types: set[str]) -> str:
        for category in CATEGORY_PRECEDENCE:
            if category in alert_types:
                return category
        if "ml_anomaly" in alert_types:
            return "suspicious_activity"
        if alert_types:
            return "suspicious_activity"
        return "benign_or_unknown"

    def investigate(
        self,
        incident: Incident,
        events: list[SecurityEvent],
        alerts: list[Alert],
        correlation: CorrelationResult,
        *,
        prompt_injection_flags: int = 0,
    ) -> InvestigationResult:
        alert_types = sorted({alert.alert_type for alert in alerts})
        classification = self._candidate_category(set(alert_types))
        base = BASE_CONFIDENCE.get(classification, 0.4)
        corroboration = min(0.06, max(0, len(alert_types) - 1) * 0.02)
        if correlation.correlation_confidence >= 0.7:
            corroboration += 0.03
        confidence = clamp(base + corroboration, 0.3, 0.97)

        reasoning: list[str] = [
            f"Classification '{classification}' selected using deterministic precedence over alert types {alert_types or ['none']}.",
            f"{len(events)} events and {len(alerts)} alerts were correlated for this incident "
            f"(correlation confidence {correlation.correlation_confidence:.2f}).",
            f"Confidence formula: base {base:.2f} + corroboration {corroboration:.2f} = {confidence:.2f}.",
        ]
        for alert in alerts:
            reasoning.append(f"Alert {alert.rule_id} ({alert.alert_type}, {alert.severity}): {alert.description}")
        if correlation.failed_login_count:
            reasoning.append(f"{correlation.failed_login_count} failed authentication event(s) observed.")
        if correlation.success_after_failures:
            reasoning.append("A successful authentication followed repeated failures; this raises account-compromise concern.")
        if prompt_injection_flags:
            reasoning.append(
                "Instruction-like text was detected inside untrusted event data. It was contained as data "
                "and did not influence classification or response selection."
            )
        severity = SEVERITY_BY_CATEGORY.get(classification, "MEDIUM")
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for alert in alerts:
            if severity_rank.get(alert.severity, 0) > severity_rank.get(severity, 0):
                severity = alert.severity

        actor = incident.source_ip or incident.username or "unknown source"
        summary = (
            f"Incident {incident.id} involves {len(events)} correlated web-security event(s) from {actor}. "
            f"Deterministic analysis classifies the behavior as {classification} with confidence {confidence:.2f}. "
        )
        if correlation.success_after_failures:
            summary += "The timeline shows repeated authentication failures followed by a successful login. "
        if any(alert.alert_type in {"sql_injection", "command_injection", "path_traversal", "xss"} for alert in alerts):
            summary += "One or more requests contain injection, traversal, or script indicators; they were analyzed passively and not executed. "
        if any(alert.alert_type == "unauthorized_access" for alert in alerts):
            summary += "The timeline contains denied requests to access-controlled resources; no unauthorized action is known to have succeeded. "
        if prompt_injection_flags:
            summary += "Instruction-like text in the logs was treated as untrusted data. "
        summary += "No system action has been executed at this stage."

        next_steps = list(NEXT_STEPS.get(classification, NEXT_STEPS["suspicious_activity"]))
        result = InvestigationResult(
            classification=classification,
            confidence=confidence,
            severity=severity,
            summary=summary,
            reasoning=reasoning,
            next_steps=next_steps,
            llm_mode="DEMO_TEMPLATE" if self.provider_mode != "LIVE_LLM" else "LIVE_LLM",
            llm_provider=self.provider.name if self.provider else "disabled",
            prompt_injection_detected=bool(prompt_injection_flags),
            alert_types=alert_types,
            baseline_classification=classification,
        )

        if self.provider is None:
            result.llm_mode = "DISABLED"
            return result

        context = {
            "incident_id": incident.id,
            "title": incident.title,
            "source_ip": incident.source_ip,
            "username": incident.username,
            "event_count": len(events),
            "alert_types": alert_types,
            "baseline_classification": classification,
            "baseline_confidence": round(confidence, 3),
            "baseline_summary": summary,
            "baseline_reasoning": reasoning,
            "baseline_next_steps": next_steps,
            "threat_intel": {},
            "prompt_injection_flags": prompt_injection_flags,
            "max_input_chars": 6000,
            "events": [
                {
                    "timestamp": iso(event.timestamp),
                    "event_type": event.event_type,
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "method": event.method,
                    "endpoint": event.endpoint,
                    "status_code": event.status_code,
                    "user_agent": event.user_agent,
                    "message": (event.message or "")[:500],
                }
                for event in events[:60]
            ],
        }
        try:
            output = self.provider.analyze(context)
        except LLMError as exc:
            result.llm_mode = "FALLBACK_TEMPLATE"
            result.llm_error = str(exc)[:500]
            logger.warning("LLM enrichment failed; deterministic fallback used: %s", exc)
            return result
        except Exception as exc:  # defensive
            result.llm_mode = "FALLBACK_TEMPLATE"
            result.llm_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            logger.exception("Unexpected LLM failure")
            return result

        result.llm_opinion = output.model_dump()
        result.llm_provider = self.provider.name
        if self.provider_mode == "LIVE_LLM":
            result.llm_mode = "LIVE_LLM"
            # The LLM may improve the narrative, but the deterministic
            # classification remains authoritative for policy decisions.
            result.summary = (
                output.summary
                + " [LLM-assisted advisory summary; classification and response policy remain deterministic.]"
            )
            if output.classification != classification:
                result.reasoning.append(
                    f"LLM suggested '{output.classification}', which conflicts with deterministic "
                    f"classification '{classification}'; deterministic result retained."
                )
                result.confidence = clamp(confidence - 0.02, 0.3, 0.97)
            else:
                result.confidence = clamp(confidence + 0.02, 0.3, 0.97)
                result.reasoning.append(
                    f"LLM classification agrees with the deterministic classification; confidence adjusted to {result.confidence:.2f}."
                )
        return result
