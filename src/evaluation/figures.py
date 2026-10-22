"""Matplotlib figures generated from measured evaluation outputs.

Figures are intentionally plain: every number shown comes from CSV/JSON output
produced by the same evaluation run. No hand-entered metric is plotted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

PALETTE = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2"]
INK = "#1f2937"
GRID = "#d1d5db"


def _style(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(GRID)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6, alpha=0.7)
    ax.set_axisbelow(True)


def _save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def plot_ml_confusion_matrix(matrix: np.ndarray, labels: list[str], path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7.4, 6.2))
    image = ax.imshow(matrix, cmap="Blues", aspect="auto")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8, color=INK)
    ax.set_yticklabels(labels, fontsize=8, color=INK)
    ax.set_xlabel("Predicted class", color=INK)
    ax.set_ylabel("Actual class", color=INK)
    ax.set_title("Random Forest confusion matrix\n(synthetic held-out test set)", color=INK, fontsize=11)
    threshold = matrix.max() / 2 if matrix.size else 0
    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            value = int(matrix[row, col])
            ax.text(
                col, row, str(value), ha="center", va="center", fontsize=7,
                color="white" if value > threshold else INK,
            )
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.03)
    _save(fig, path)


def plot_scenario_classification(scenario_metrics: dict[str, Any], path: Path) -> None:
    labels = [label for label in scenario_metrics["classification"]["labels"] if label != "benign"]
    baseline = scenario_metrics["classification"]["baseline"]["per_class"]
    agentic = scenario_metrics["classification"]["agentic"]["per_class"]
    x = np.arange(len(labels))
    width = 0.38
    fig, ax = plt.subplots(figsize=(9.6, 4.6))
    ax.bar(x - width / 2, [baseline[label]["f1"] for label in labels], width,
           label="Rule-only baseline", color=PALETTE[1], alpha=0.88)
    ax.bar(x + width / 2, [agentic[label]["f1"] for label in labels], width,
           label="Agentic pipeline", color=PALETTE[0], alpha=0.88)
    ax.set_xticks(x)
    ax.set_xticklabels([label.replace("_", "\n") for label in labels], fontsize=8)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Per-class F1", color=INK)
    ax.set_title("Incident classification by category (synthetic scenarios)", color=INK, fontsize=11)
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    _style(ax)
    _save(fig, path)


def plot_detection_rates(scenario_metrics: dict[str, Any], path: Path) -> None:
    rates = scenario_metrics["detection"]["by_category"]
    categories = list(rates.keys())
    values = [rates[item]["rate"] for item in categories]
    fig, ax = plt.subplots(figsize=(9.2, 4.2))
    bars = ax.bar(range(len(categories)), values, color=PALETTE[0], alpha=0.9)
    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels([item.replace("_", "\n") for item in categories], fontsize=8)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Detection rate", color=INK)
    ax.set_title("Detection rate by synthetic scenario category", color=INK, fontsize=11)
    for bar, item in zip(bars, categories):
        count = rates[item]
        ax.text(bar.get_x() + bar.get_width() / 2, min(bar.get_height() + 0.02, 1.1),
                f"{count['detected']}/{count['total']}", ha="center", fontsize=8, color=INK)
    _style(ax)
    _save(fig, path)


def plot_risk_by_category(rows: list[dict[str, Any]], path: Path) -> None:
    values: dict[str, list[float]] = {}
    for row in rows:
        if row.get("risk_score") is None:
            continue
        values.setdefault(row["category"], []).append(float(row["risk_score"]))
    categories = list(values.keys())
    data = [values[item] for item in categories]
    fig, ax = plt.subplots(figsize=(9.4, 4.4))
    box = ax.boxplot(data, patch_artist=True, widths=0.55, showmeans=True)
    for index, patch in enumerate(box["boxes"]):
        patch.set_facecolor(PALETTE[index % len(PALETTE)])
        patch.set_alpha(0.45)
    for median in box["medians"]:
        median.set_color(INK)
    ax.set_xticks(range(1, len(categories) + 1))
    ax.set_xticklabels([item.replace("_", "\n") for item in categories], fontsize=8)
    ax.set_ylabel("Risk score (0-100)", color=INK)
    ax.set_ylim(0, 105)
    ax.axhline(50, color=PALETTE[1], linestyle="--", linewidth=0.9, alpha=0.7)
    ax.axhline(75, color=PALETTE[1], linestyle=":", linewidth=0.9, alpha=0.7)
    ax.set_title("Risk scores by scenario category (project-defined scoring model)", color=INK, fontsize=11)
    _style(ax)
    _save(fig, path)


def plot_latency(rows: list[dict[str, Any]], path: Path) -> None:
    ingestion = [float(row["ingestion_ms"]) for row in rows if row.get("ingestion_ms") is not None]
    investigation = [float(row["investigation_ms"]) for row in rows if row.get("investigation_ms") is not None]
    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    bins = 24
    ax.hist(ingestion, bins=bins, alpha=0.7, label="Ingestion", color=PALETTE[0])
    ax.hist(investigation, bins=bins, alpha=0.7, label="Investigation", color=PALETTE[2])
    ax.set_yscale("log")
    ax.set_xlabel("Wall-clock duration (ms, log-scaled count)", color=INK)
    ax.set_ylabel("Scenario count", color=INK)
    ax.set_title("Per-scenario pipeline latency on a local SQLite database", color=INK, fontsize=11)
    ax.legend(frameon=False, fontsize=9)
    _style(ax)
    _save(fig, path)


def plot_pipeline_diagram(path: Path) -> None:
    stages = [
        "Security\nevents", "Normalize\nvalidate", "Hybrid\ndetection", "Incident\ncorrelation",
        "Agent\ninvestigation", "Threat\nintel", "MITRE\nmapping", "Risk\nscoring",
        "Approval\ngate", "Simulated\nresponse", "Verification", "Audit\nchain",
    ]
    fig, ax = plt.subplots(figsize=(12.6, 2.7))
    ax.set_xlim(0, len(stages))
    ax.set_ylim(0, 1)
    ax.axis("off")
    for index, stage in enumerate(stages):
        color = "#dbeafe"
        if stage in {"Approval\ngate", "Simulated\nresponse", "Verification"}:
            color = "#fef3c7"
        if stage == "Audit\nchain":
            color = "#dcfce7"
        ax.add_patch(plt.Rectangle((index + 0.06, 0.23), 0.88, 0.52,
                                   facecolor=color, edgecolor="#64748b", linewidth=0.9))
        ax.text(index + 0.5, 0.49, stage, ha="center", va="center", fontsize=7.4, color=INK)
        if index < len(stages) - 1:
            ax.annotate("", xy=(index + 1.04, 0.49), xytext=(index + 0.94, 0.49),
                        arrowprops=dict(arrowstyle="-|>", color="#475569", lw=1.1))
    ax.text(0.5, 0.93, "End-to-end incident-response pipeline (all response effects are simulated)",
            ha="center", fontsize=10, color=INK)
    _save(fig, path)


def plot_audit_and_approval(scenario_metrics: dict[str, Any], path: Path) -> None:
    response = scenario_metrics["response"]
    labels = ["Approval gate\ncorrect", "Expected action\npresent", "Allowlist\ncompliant", "Simulated\nactions", "Verified"]
    values = [
        response["approval_gate_accuracy"],
        response["key_action_coverage"],
        response["allowlist_compliance"],
        response["simulation_compliance"],
        response["verification_rate"],
    ]
    fig, ax = plt.subplots(figsize=(8.4, 4.0))
    bars = ax.bar(labels, values, color=[PALETTE[0], PALETTE[2], PALETTE[3], PALETTE[5], PALETTE[4]], alpha=0.85)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Measured proportion", color=INK)
    ax.set_title("Response-policy and verification outcomes (attack scenarios)", color=INK, fontsize=11)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, min(bar.get_height() + 0.02, 1.1),
                f"{value:.2f}", ha="center", fontsize=8, color=INK)
    _style(ax)
    _save(fig, path)
