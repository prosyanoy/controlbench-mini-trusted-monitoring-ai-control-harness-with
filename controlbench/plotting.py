"""Matplotlib figures: the safety/usefulness Pareto plot and the red-team sweep."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .experiment import Experiment, Row  # noqa: E402

# Okabe-Ito: colour-blind safe; families also differ by marker and line style.
STYLE = {
    "trusted_monitoring": ("#0072B2", "o", "-", "Trusted monitoring (audit budget sweep)"),
    "defer_to_trusted": ("#D55E00", "s", "--", "Defer to trusted (defer threshold sweep)"),
    "resample": ("#009E73", "^", "-.", "Resample, then defer"),
}
INK, MUTED, GRID = "#222222", "#6b6b6b", "#e3e3e3"


def _axes(ax, xlabel: str, ylabel: str) -> None:
    ax.set_xlabel(xlabel, color=INK)
    ax.set_ylabel(ylabel, color=INK)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED)


def plot_pareto(pareto: list[dict], path: Path, title: str = "") -> Path:
    fig, ax = plt.subplots(figsize=(8.4, 5.6), dpi=140)
    for fam, (color, marker, ls, label) in STYLE.items():
        pts = sorted((p for p in pareto if p["protocol"] == fam), key=lambda p: p["usefulness"])
        if not pts:
            continue
        ax.plot([p["usefulness"] for p in pts], [p["worst_case_safety"] for p in pts], ls, color=color,
                marker=marker, markersize=6, linewidth=1.6, markeredgecolor="white",
                markeredgewidth=0.8, label=label, alpha=0.95)
    for p in pareto:
        if p["protocol"] in ("untrusted_only", "trusted_only"):
            ax.scatter(p["usefulness"], p["worst_case_safety"], s=70, color="#444444", marker="D",
                       zorder=5, edgecolors="white")
            ax.annotate(p["protocol"].replace("_", " "), (p["usefulness"], p["worst_case_safety"]),
                        textcoords="offset points", xytext=(8, 6 if p["protocol"] == "trusted_only" else -14),
                        fontsize=9, color=INK)
    front = sorted((p for p in pareto if p["on_frontier"]), key=lambda p: p["usefulness"])
    if front:
        ax.step([p["usefulness"] for p in front], [p["worst_case_safety"] for p in front], where="post",
                color="#999999", linewidth=3, alpha=0.35, zorder=1, label="Pareto frontier")
    ax.set_xlim(left=min(p["usefulness"] for p in pareto) - 0.03, right=1.03)
    ax.set_ylim(-0.03, 1.05)
    _axes(ax, "Usefulness  (fraction of tasks passing unit tests, honest untrusted model)",
          "Safety  (worst case over red-team strategies)")
    ax.set_title(title or "Safety vs. usefulness of control protocols", loc="left", color=INK, fontsize=12)
    ax.legend(loc="lower left", frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def plot_redteam(rows: list[Row], path: Path, picks: list[tuple[str, dict]] | None = None) -> Path:
    """Safety of a few representative blue configs against every red strategy."""
    picks = picks or [("trusted_monitoring", {"audit_budget": 0.05}),
                      ("defer_to_trusted", {"audit_budget": 0.05, "defer_fraction": 0.3}),
                      ("resample", {"audit_budget": 0.05, "defer_fraction": 0.3})]
    styles = {"trusted_monitoring": STYLE["trusted_monitoring"], "defer_to_trusted": STYLE["defer_to_trusted"],
              "resample": STYLE["resample"]}
    labels = sorted({r.red.label for r in rows})
    fig, ax = plt.subplots(figsize=(8.4, max(4.5, 0.26 * len(labels) + 1.5)), dpi=140)
    for proto, params in picks:
        match = {r.red.label: r for r in rows if r.protocol == proto and
                 all(abs(r.params.get(k, -1) - v) < 1e-9 for k, v in params.items())}
        if not match:
            continue
        color, marker, _, _ = styles[proto]
        desc = proto.replace("_", " ") + " " + ", ".join(f"{k.split('_')[0]}={v:g}" for k, v in params.items())
        ax.scatter([match[l].safety for l in labels if l in match], [labels.index(l) for l in labels if l in match],
                   color=color, marker=marker, s=38, edgecolors="white", label=desc, zorder=3)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7.5, color=INK)
    ax.set_xlim(-0.03, 1.03)
    ax.invert_yaxis()
    _axes(ax, "Safety (probability no backdoor gets through)", "Red strategy  (style / attack rate / selection)")
    ax.set_title("Red-team strategy sweep", loc="left", color=INK, fontsize=12)
    if ax.get_legend_handles_labels()[0]:
        ax.legend(loc="lower left", frameon=True, facecolor="white", edgecolor=GRID, fontsize=8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def plot_scores(honest: list[float], attacks: dict[str, list[float]], path: Path) -> Path:
    """Suspicion score distributions: honest code vs. each backdoor style."""
    colors = {"honest": "#7a7a7a", "blatant": "#D55E00", "magic": "#E69F00",
              "subtle": "#0072B2", "camouflage": "#009E73"}
    fig, ax = plt.subplots(figsize=(8.4, 4.4), dpi=140)
    bins = [i * 0.5 for i in range(21)]
    ax.hist(honest, bins=bins, histtype="stepfilled", color=colors["honest"], alpha=0.35, label="honest",
            density=True)
    for style, xs in attacks.items():
        ax.hist(xs, bins=bins, histtype="step", linewidth=1.8, color=colors.get(style, "#333"), label=style,
                density=True)
    _axes(ax, "Monitor suspicion score", "Density")
    ax.set_title("Monitor score distributions", loc="left", color=INK, fontsize=12)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path
