"""
experiments/evaluation/make_architecture_figure.py

Issue #51 (E6), Task 1 — system architecture figure (SYS1). Draws the
real pipeline order exactly as implemented in
`src/agent/soc_agent.py`'s `analyse_alert()`, not an idealized version:

  1. Evidence Pack built from the raw alert.
  2. Input guardrail (deterministic pattern match + ML classifier hybrid)
     — on a hit, returns a BLOCKED report immediately; the LLM is never
     called. This early-return matters (Sect. 3.2): a blocked alert
     produces no report for the output-side guardrails to check.
  3. LLM report generation (only reached if the input guardrail passed).
  4/5/6. Three independent per-stage guardrails over the generated
     report: CVE and ATT&CK each run the same two-stage pattern
     (grounding check, then authoritative-source verification --- NVD /
     MITRE ATT&CK STIX --- only for ungrounded citations, classified into
     the taxonomy), PII runs Presidio-based detection + redaction. Drawn
     side-by-side because each is independently toggleable (the
     component ablation study, Sect. 4.8, tests exactly this), not
     because the implementation runs them concurrently -- the code runs
     them sequentially in this order; the diagram's caption says so.
  7. Aggregation: requires_review is the OR of all three stages' own
     flags, per `analyse_alert()`'s actual aggregation logic.

Usage:
    python -m experiments.evaluation.make_architecture_figure
"""

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT_DIR = "docs/paper/figures"

plt.rcParams.update({
    "font.size": 9.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

COLOR_INPUT = "#4C72B0"
COLOR_LLM = "#55A868"
COLOR_GUARD = "#DD8452"
COLOR_AGG = "#8172B2"
COLOR_TERMINAL = "#333333"
COLOR_EVIDENCE = "#777777"
COLOR_BLOCKED = "#C44E52"


def _box(ax, x, y, w, h, lines, color, fontsize=8.5, text_color="white"):
    """lines: list of (text, fontweight, size_delta) tuples, stacked top to bottom, centered in the box."""
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=1.1, edgecolor=color, facecolor=color, alpha=0.94,
    )
    ax.add_patch(box)
    n = len(lines)
    line_h = h / (n + 1)
    for i, (text, weight, delta) in enumerate(lines):
        ty = y + h - line_h * (i + 1)
        ax.text(x + w / 2, ty, text, ha="center", va="center",
                 fontsize=fontsize + delta, fontweight=weight, color=text_color)
    return box


def _arrow(ax, xy_from, xy_to, color="#444444", lw=1.3, connectionstyle=None):
    arrow = FancyArrowPatch(
        xy_from, xy_to, arrowstyle="-|>", mutation_scale=13,
        linewidth=lw, color=color, shrinkA=2, shrinkB=2,
        connectionstyle=connectionstyle,
    )
    ax.add_patch(arrow)


def make():
    fig, ax = plt.subplots(figsize=(7.6, 8.4))
    ax.set_xlim(0, 10)
    ax.set_ylim(2.2, 15.4)
    ax.axis("off")
    ax.set_aspect("equal")

    cx = 4.6
    w_main = 6.6
    x_main = cx - w_main / 2

    # 1. Security alert
    _box(ax, x_main, 14.0, w_main, 1.0,
         [("Security alert", "bold", 0), ("(SIEM / rule engine / analyst)", "normal", -1)],
         COLOR_TERMINAL)

    # 2. Evidence pack
    _box(ax, x_main, 12.55, w_main, 1.0,
         [("Evidence Pack builder", "normal", 0), ("(structured facts extracted from the alert)", "normal", -1.3)],
         COLOR_EVIDENCE)
    _arrow(ax, (cx, 14.0), (cx, 13.55))

    # 3. Input guardrail
    _box(ax, x_main, 11.1, w_main, 1.0,
         [("Input guardrail", "bold", 0), ("deterministic pattern match + ML classifier, hybrid", "normal", -1.3)],
         COLOR_INPUT)
    _arrow(ax, (cx, 12.55), (cx, 12.1))

    # Blocked branch
    bx, by, bw, bh = 8.15, 10.85, 1.55, 0.95
    _box(ax, bx, by, bw, bh, [("BLOCKED report", "bold", -0.5), ("returned", "bold", -0.5)], COLOR_BLOCKED, fontsize=7.2)
    _arrow(ax, (x_main + w_main, 11.45), (bx, by + bh / 2), color=COLOR_BLOCKED,
           connectionstyle="arc3,rad=-0.2")
    ax.text(x_main + w_main + 0.05, 11.9, "injection detected", fontsize=6.3, color=COLOR_BLOCKED, ha="left", va="center")

    # 4. LLM
    _box(ax, x_main, 9.65, w_main, 1.0,
         [("LLM report generation", "bold", 0), ("gpt-oss-20b / qwen3.6-27b", "normal", -1.3)],
         COLOR_LLM)
    _arrow(ax, (cx, 11.1), (cx, 10.65))
    ax.text(x_main - 0.15, 10.35, "clean", fontsize=6.6, color=COLOR_INPUT, ha="right", va="center")

    # Generated report node
    _box(ax, x_main, 8.35, w_main, 0.85, [("Generated threat report (JSON)", "normal", -0.3)], "#999999")
    _arrow(ax, (cx, 9.65), (cx, 9.2))

    # --- Three parallel output-side guardrails ---
    y_g, gh, gw = 5.15, 2.55, 2.05
    gx_cve, gx_attack, gx_pii = 0.55, 3.3, 6.05

    _arrow(ax, (cx, 8.35), (gx_cve + gw / 2, y_g + gh), connectionstyle="arc3,rad=-0.15")
    _arrow(ax, (cx, 8.35), (gx_attack + gw / 2, y_g + gh))
    _arrow(ax, (cx, 8.35), (gx_pii + gw / 2, y_g + gh), connectionstyle="arc3,rad=0.15")

    _box(ax, gx_cve, y_g, gw, gh, [
        ("CVE checker", "bold", 0.2),
        ("Stage 1: grounded in", "normal", -1.6),
        ("alert evidence?", "normal", -1.6),
        ("Stage 2: verify vs. NVD", "normal", -1.6),
        ("→ taxonomy class", "normal", -1.6),
    ], COLOR_GUARD, fontsize=7.8)

    _box(ax, gx_attack, y_g, gw, gh, [
        ("ATT&CK checker", "bold", 0.0),
        ("Stage 1: grounded in", "normal", -1.6),
        ("alert evidence?", "normal", -1.6),
        ("Stage 2: verify vs.", "normal", -1.6),
        ("MITRE STIX → class", "normal", -1.6),
    ], COLOR_GUARD, fontsize=7.8)

    _box(ax, gx_pii, y_g, gw, gh, [
        ("PII guardrail", "bold", 0.2),
        ("", "normal", 0),
        ("Presidio-based", "normal", -1.6),
        ("detection → redact", "normal", -1.6),
        ("sensitive fields", "normal", -1.6),
    ], COLOR_GUARD, fontsize=7.8)

    # --- Aggregation ---
    _box(ax, x_main, 3.85, w_main, 0.95,
         [("Aggregate: requires_review =", "bold", -0.6),
          ("CVE_flag OR ATT&CK_flag OR PII_found", "normal", -1.6)],
         COLOR_AGG, fontsize=8.2)
    _arrow(ax, (gx_cve + gw / 2, y_g), (cx - 0.5, 4.8), connectionstyle="arc3,rad=0.15")
    _arrow(ax, (gx_attack + gw / 2, y_g), (cx, 4.8))
    _arrow(ax, (gx_pii + gw / 2, y_g), (cx + 0.5, 4.8), connectionstyle="arc3,rad=-0.15")

    # --- Final report ---
    _box(ax, x_main, 2.6, w_main, 1.0, [
        ("Final report to SOC analyst", "bold", 0),
        ("every field present regardless of which stages ran", "normal", -2.0),
    ], COLOR_TERMINAL, fontsize=7.3)
    _arrow(ax, (cx, 3.85), (cx, 3.6))

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_architecture.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_architecture.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_architecture.pdf/.png"))


if __name__ == "__main__":
    make()
