"""Rule-only baseline used for the scenario comparison.

The baseline consumes the same rule alerts as the full pipeline but performs no
evidence-driven re-triage: it reports the category of the earliest alert. This
deliberately models a conventional SIEM rule view in which a brute-force alert
that fires before a later successful login remains the analyst-facing label.
"""
from __future__ import annotations

from typing import Any, Iterable


def first_alert_prediction(alerts: Iterable[Any]) -> str:
    ordered = sorted(
        alerts,
        key=lambda alert: (
            getattr(alert, "created_at", None) is None,
            getattr(alert, "created_at", None),
            getattr(alert, "id", ""),
        ),
    )
    if not ordered:
        return "benign_or_unknown"
    return str(getattr(ordered[0], "alert_type", "benign_or_unknown"))


def baseline_result(alerts: Iterable[Any]) -> dict[str, Any]:
    alerts = list(alerts)
    return {
        "detected": bool(alerts),
        "predicted_category": first_alert_prediction(alerts),
        "alert_count": len(alerts),
        "alert_types": sorted({str(getattr(alert, "alert_type", "unknown")) for alert in alerts}),
    }
