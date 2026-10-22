"""Metric helpers for the scenario benchmark.

The functions are deliberately small and side-effect free so they can be unit
tested against hand-computed examples. Confidence intervals are Wilson score
intervals for proportions; the McNemar test is the exact two-sided binomial
version for paired classifier outcomes.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable


def wilson_interval(successes: int, total: int, z: float = 1.96) -> dict[str, float | None]:
    if total <= 0:
        return {"low": None, "high": None}
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return {
        "low": round(max(0.0, centre - margin), 4),
        "high": round(min(1.0, centre + margin), 4),
    }


def proportion(successes: int, total: int) -> dict[str, Any]:
    return {
        "successes": successes,
        "total": total,
        "rate": round(successes / total, 4) if total else 0.0,
        "ci95": wilson_interval(successes, total),
    }


def binary_detection_metrics(rows: Iterable[dict[str, Any]], prediction_key: str) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        actual = bool(row["is_attack"])
        predicted = bool(row[prediction_key])
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else 0.0,
        "recall_ci95": wilson_interval(tp, tp + fn),
    }


def classification_metrics(rows: Iterable[dict[str, Any]], prediction_key: str, labels: list[str]) -> dict[str, Any]:
    rows = list(rows)
    pairs = [(row["expected_category"], row[prediction_key]) for row in rows]
    correct = sum(1 for actual, predicted in pairs if actual == predicted)
    per_class: dict[str, Any] = {}
    for label in labels:
        tp = sum(1 for actual, predicted in pairs if actual == label and predicted == label)
        fp = sum(1 for actual, predicted in pairs if actual != label and predicted == label)
        fn = sum(1 for actual, predicted in pairs if actual == label and predicted != label)
        support = sum(1 for actual, _ in pairs if actual == label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
        }
    accuracy = correct / len(rows) if rows else 0.0
    macro_f1 = sum(per_class[label]["f1"] for label in labels) / len(labels) if labels else 0.0
    total_support = sum(per_class[label]["support"] for label in labels)
    weighted_f1 = (
        sum(per_class[label]["f1"] * per_class[label]["support"] for label in labels) / total_support
        if total_support else 0.0
    )
    confusion: dict[str, dict[str, int]] = {
        actual: {predicted: 0 for predicted in labels} for actual in labels
    }
    for actual, predicted in pairs:
        confusion.setdefault(actual, {predicted: 0 for predicted in labels})
        confusion[actual].setdefault(predicted, 0)
        confusion[actual][predicted] += 1
    return {
        "labels": labels,
        "accuracy": round(accuracy, 4),
        "accuracy_ci95": wilson_interval(correct, len(rows)),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "correct": correct,
        "total": len(rows),
        "per_class": per_class,
        "confusion_matrix": confusion,
        "predictions": Counter(row[prediction_key] for row in rows),
    }


def mcnemar_exact(baseline_correct: list[bool], agentic_correct: list[bool]) -> dict[str, Any]:
    if len(baseline_correct) != len(agentic_correct):
        raise ValueError("Paired outcome lists must have equal length")
    baseline_only = sum(1 for b, a in zip(baseline_correct, agentic_correct) if b and not a)
    agentic_only = sum(1 for b, a in zip(baseline_correct, agentic_correct) if a and not b)
    discordant = baseline_only + agentic_only
    if discordant == 0:
        p_value = 1.0
    else:
        smaller = min(baseline_only, agentic_only)
        tail = sum(math.comb(discordant, k) for k in range(smaller + 1)) / (2 ** discordant)
        p_value = min(1.0, 2 * tail)
    return {
        "baseline_only_correct": baseline_only,
        "agentic_only_correct": agentic_only,
        "discordant_pairs": discordant,
        "exact_two_sided_p": round(p_value, 6),
        "test": "McNemar exact binomial (two-sided)",
    }


def latency_summary(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"samples": 0, "mean": None, "median": None, "p95": None, "min": None, "max": None}
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "samples": len(ordered),
        "mean": round(sum(ordered) / len(ordered), 2),
        "median": round(ordered[len(ordered) // 2], 2),
        "p95": round(ordered[index], 2),
        "min": round(ordered[0], 2),
        "max": round(ordered[-1], 2),
    }


def risk_summary(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row["risk_score"]) for row in rows if row.get("risk_score") is not None]
    by_level: Counter[str] = Counter(row.get("risk_level", "UNKNOWN") for row in rows if row.get("risk_level"))
    by_category: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("risk_score") is None:
            continue
        entry = by_category.setdefault(row["category"], {"scores": [], "levels": Counter()})
        entry["scores"].append(float(row["risk_score"]))
        entry["levels"][row.get("risk_level", "UNKNOWN")] += 1
    category_payload = {}
    for category, entry in by_category.items():
        scores = entry["scores"]
        category_payload[category] = {
            "n": len(scores),
            "mean": round(sum(scores) / len(scores), 2),
            "min": round(min(scores), 2),
            "max": round(max(scores), 2),
            "levels": dict(entry["levels"]),
        }
    return {
        "samples": len(values),
        "mean": round(sum(values) / len(values), 2) if values else None,
        "min": round(min(values), 2) if values else None,
        "max": round(max(values), 2) if values else None,
        "levels": dict(by_level),
        "by_category": category_payload,
    }


def mitre_metrics(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    all_rows = list(rows)
    eligible = [row for row in all_rows if row.get("expected_mitre")]
    tp = fp = fn = exact = 0
    for row in eligible:
        expected = set(row["expected_mitre"])
        predicted = set(row.get("predicted_mitre") or [])
        tp += len(expected & predicted)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        exact += 1 if expected == predicted else 0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "eligible_scenarios": len(eligible),
        "excluded_scenarios": len(all_rows) - len(eligible),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "micro_precision": round(precision, 4),
        "micro_recall": round(recall, 4),
        "micro_f1": round(f1, 4),
        "exact_set_match_rate": round(exact / len(eligible), 4) if eligible else 0.0,
        "note": "Ground truth is project-defined from scenario construction; reputation-only and volume-only scenarios are excluded.",
    }


def detection_by_category(rows: Iterable[dict[str, Any]], prediction_key: str) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, int]] = {}
    for row in rows:
        entry = grouped.setdefault(row["category"], {"total": 0, "detected": 0})
        entry["total"] += 1
        if row[prediction_key]:
            entry["detected"] += 1
    return {
        category: {
            "total": value["total"],
            "detected": value["detected"],
            "rate": round(value["detected"] / value["total"], 4) if value["total"] else 0.0,
        }
        for category, value in grouped.items()
    }
