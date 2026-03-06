"""
Chart generation for EASM reports using Matplotlib.

Produces in-memory SVG (for PDF embedding) or PNG (for DOCX embedding) charts.
All functions return raw bytes -- no files are written to disk.
"""

import base64
import io
import logging
from typing import Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

logger = logging.getLogger(__name__)

# -- Global font configuration (Inter with fallbacks) -------------------------

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Inter", "Liberation Sans", "DejaVu Sans", "Helvetica Neue"],
    "font.size": 10,
    "axes.labelsize": 9,
    "axes.titlesize": 10,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
})

# -- Colour palette matching the PushingTorPod brand --------------------------

SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "info": "#6B7280",
}

ASSET_COLORS: List[str] = [
    "#6366F1",  # indigo (brand primary)
    "#8B5CF6",  # violet
    "#818CF8",  # indigo light
    "#0891B2",  # cyan
    "#059669",  # emerald
    "#D97706",  # amber
]

GRADE_THRESHOLDS: List[Tuple[float, str, str]] = [
    (20, "A", "#16A34A"),
    (40, "B", "#2563EB"),
    (60, "C", "#CA8A04"),
    (80, "D", "#EA580C"),
    (100, "F", "#DC2626"),
]

# -- Helpers -------------------------------------------------------------------


def _render(fig: plt.Figure, fmt: str = "svg") -> bytes:
    """Render a Matplotlib figure to bytes and close it."""
    buf = io.BytesIO()
    fig.savefig(buf, format=fmt, bbox_inches="tight", dpi=150, transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def chart_to_data_uri(data: bytes, fmt: str = "svg") -> str:
    """Convert chart bytes to an HTML-embeddable data URI."""
    mime = "image/svg+xml" if fmt == "svg" else f"image/{fmt}"
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{b64}"


# -- Chart functions -----------------------------------------------------------


def generate_risk_gauge(score: float, grade: str, fmt: str = "svg") -> bytes:
    """
    Semicircular gauge chart -- thick ring, light background track.

    Light ``#E2E8F0`` background ring with a coloured arc overlay. Score and
    grade displayed as large text in the centre. No needle.

    Args:
        score: Risk score 0-100.
        grade: Letter grade (A-F).
        fmt: Output format, ``"svg"`` or ``"png"``.

    Returns:
        Raw image bytes.
    """
    fig, ax = plt.subplots(figsize=(4, 2.6), subplot_kw={"projection": "polar"})

    # Background ring (full semicircle, dark slate)
    theta_full = np.linspace(np.pi, 0, 200)
    for i in range(len(theta_full) - 1):
        ax.barh(
            1, theta_full[i] - theta_full[i + 1],
            left=theta_full[i + 1], height=0.45,
            color="#1E293B",
            edgecolor="none",
        )

    # Coloured arc overlay (only up to score%)
    clamped = max(0.0, min(score, 100.0))
    n_segments = max(int(clamped / 100.0 * 200), 1)
    theta_score = np.linspace(np.pi, np.pi - (clamped / 100.0) * np.pi, n_segments)
    colors_list = ["#16A34A", "#2563EB", "#6366F1", "#CA8A04", "#EA580C", "#DC2626"]
    cmap = LinearSegmentedColormap.from_list("gauge", colors_list, N=200)
    for i in range(len(theta_score) - 1):
        progress = i / max(len(theta_score) - 1, 1)
        ax.barh(
            1, theta_score[i] - theta_score[i + 1],
            left=theta_score[i + 1], height=0.45,
            color=cmap(clamped / 100.0 * progress),
            edgecolor="none",
        )

    # Score text in centre
    grade_color = "#6B7280"
    for threshold, g, color in GRADE_THRESHOLDS:
        if clamped <= threshold:
            grade_color = color
            break
    ax.text(
        np.pi / 2, 0.45, f"{score:.0f}",
        ha="center", va="center",
        fontsize=40, fontweight="bold", color="#0F172A",
    )
    ax.text(
        np.pi / 2, 0.0, grade,
        ha="center", va="center",
        fontsize=16, fontweight="bold", color=grade_color,
    )
    ax.text(
        np.pi / 2, -0.25, "out of 100",
        ha="center", va="center",
        fontsize=8, color="#94A3B8",
    )

    ax.set_ylim(0, 1.5)
    ax.set_thetamin(0)
    ax.set_thetamax(180)
    ax.axis("off")
    fig.patch.set_alpha(0)

    return _render(fig, fmt)


def generate_severity_chart(counts: Dict[str, int], fmt: str = "svg") -> bytes:
    """
    Horizontal bar chart -- thinner bars (0.48) with inline labels.

    Args:
        counts: Mapping ``{"critical": N, "high": N, ...}``.
        fmt: Output format.

    Returns:
        Raw image bytes.
    """
    ordered = ["critical", "high", "medium", "low", "info"]
    labels = [s.capitalize() for s in ordered]
    values = [counts.get(s, 0) for s in ordered]
    colors = [SEVERITY_COLORS[s] for s in ordered]
    max_val = max(max(values), 1)

    fig, ax = plt.subplots(figsize=(5, 2.8))

    bar_height = 0.48
    bars = ax.barh(
        labels, values, color=colors, height=bar_height,
        edgecolor="none", linewidth=0,
    )
    # Round the bar caps
    for bar_item in bars:
        bar_item.set_capstyle("round")

    # Labels: inside the bar if there's room, otherwise outside
    for bar_item, val in zip(bars, values):
        if val > 0:
            if val >= max_val * 0.15:
                # Inside
                ax.text(
                    bar_item.get_width() - max_val * 0.03,
                    bar_item.get_y() + bar_item.get_height() / 2,
                    str(val), va="center", ha="right",
                    fontsize=9, fontweight="bold", color="#FFFFFF",
                )
            else:
                # Outside
                ax.text(
                    bar_item.get_width() + max_val * 0.03,
                    bar_item.get_y() + bar_item.get_height() / 2,
                    str(val), va="center", ha="left",
                    fontsize=9, fontweight="bold", color="#374151",
                )

    ax.invert_yaxis()
    ax.set_xlabel("")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="x", which="both", length=0, labelbottom=False)
    ax.tick_params(axis="y", which="both", length=0)
    ax.set_xlim(0, max_val * 1.15)
    fig.tight_layout()
    fig.patch.set_alpha(0)

    return _render(fig, fmt)


def generate_asset_chart(counts: Dict[str, int], fmt: str = "svg") -> bytes:
    """
    Donut chart -- ring width 0.35, brand-first palette, light edge.

    Args:
        counts: Mapping ``{"domain": N, "subdomain": N, ...}``.
        fmt: Output format.

    Returns:
        Raw image bytes.
    """
    # Filter out zeros
    filtered = {k: v for k, v in counts.items() if v > 0}
    if not filtered:
        filtered = {"No assets": 0}

    labels = [k.capitalize() for k in filtered]
    values = list(filtered.values())
    colors = ASSET_COLORS[: len(values)]

    fig, ax = plt.subplots(figsize=(4, 3.6))
    wedges, texts = ax.pie(
        values if any(v > 0 for v in values) else [1],
        labels=None,
        colors=colors,
        startangle=90,
        wedgeprops={"width": 0.35, "edgecolor": "#F1F5F9", "linewidth": 2},
    )

    # Centre text
    total = sum(values)
    ax.text(0, 0.08, str(total), ha="center", va="center", fontsize=22, fontweight="bold", color="#0F172A")
    ax.text(0, -0.16, "Assets", ha="center", va="center", fontsize=9, color="#94A3B8")

    # Legend below the chart
    legend_patches = [
        mpatches.Patch(color=c, label=f"{lbl} ({v})")
        for c, lbl, v in zip(colors, labels, values)
    ]
    ax.legend(
        handles=legend_patches, loc="upper center", bbox_to_anchor=(0.5, -0.05),
        frameon=False, fontsize=8, ncol=min(len(legend_patches), 3),
    )

    fig.tight_layout()
    fig.patch.set_alpha(0)
    return _render(fig, fmt)


def generate_trend_chart(
    trend_data: List[Dict],
    fmt: str = "svg",
) -> Optional[bytes]:
    """
    Area chart -- indigo line with white-bordered markers and single fill.

    Args:
        trend_data: List of dicts with ``"date"`` and ``"score"`` keys.
        fmt: Output format.

    Returns:
        Raw image bytes, or ``None`` if insufficient data.
    """
    if len(trend_data) < 2:
        return None

    dates = [d["date"] for d in trend_data]
    scores = [d["score"] for d in trend_data]

    fig, ax = plt.subplots(figsize=(6, 2.8))

    # Single gradient fill
    ax.fill_between(dates, scores, alpha=0.08, color="#6366F1")
    ax.plot(
        dates, scores,
        color="#6366F1", linewidth=2.5,
        marker="o", markersize=5,
        markerfacecolor="#6366F1", markeredgecolor="#FFFFFF", markeredgewidth=1.5,
        zorder=5,
    )

    # Subtle horizontal grid
    ax.yaxis.grid(True, linestyle="-", linewidth=0.5, color="#E5E7EB", alpha=0.8)
    ax.set_axisbelow(True)

    ax.set_ylabel("Risk Score", fontsize=9, color="#6B7280")
    ax.set_ylim(0, 100)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#E5E7EB")
    ax.spines["bottom"].set_color("#E5E7EB")
    ax.tick_params(axis="both", labelsize=8, colors="#6B7280")
    fig.autofmt_xdate(rotation=30, ha="right")
    fig.tight_layout()
    fig.patch.set_alpha(0)

    return _render(fig, fmt)
