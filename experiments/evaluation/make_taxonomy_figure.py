"""
experiments/evaluation/make_taxonomy_figure.py

Issue #51 (E6), Task 2 — citation-taxonomy decision figure (TAX1). Draws
the classification pipeline exactly as implemented, in the exact
sequential order both `verify_cve()` (src/guardrails/output_guardrail.py)
and `verify_attack_technique()` (src/guardrails/attack_grounding.py)
actually check it -- both functions are structurally identical (the
second mirrors the first by design), so one diagram covers both citation
families:

  1. Stage 1 (grounding): is the identifier present in the alert's own
     Evidence Pack text? If yes -> GROUNDED, terminal, Stage 2 never
     runs.
  2. Stage 2 (authoritative lookup): does the source have a usable
     record at all (NVD reachable with an English description / local
     MITRE STIX snapshot loaded)? If not -> UNVERIFIED.
  3. Does the identifier exist in that source at all? If not ->
     FABRICATED.
  4. Is it formally withdrawn (NVD "REJECTED" / MITRE "revoked")? If
     yes -> REJECTED (CVE) / REVOKED (ATT&CK), drawn as one merged tier
     per Sect. 3.5's own table.
  5. Does its description topically overlap the alert's evidence above
     the calibrated threshold (0.15, stemmed bag-of-words)? ->
     REAL_AND_PLAUSIBLE if yes, REAL_BUT_IRRELEVANT if no.

REAL_AND_PLAUSIBLE is visually flagged (a distinct crimson, not the
"real=safe" green/blue family the other terminal-real outcomes get) to
match the paper's own point (Sect. 3.5): this is the highest-risk class
precisely because it looks correct, not the lowest.

Usage:
    python -m experiments.evaluation.make_taxonomy_figure
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

COLOR_ROOT = "#333333"
COLOR_DECISION = "#4C72B0"
COLOR_GROUNDED = "#55A868"
COLOR_UNVERIFIED = "#999999"
COLOR_FABRICATED = "#C44E52"
COLOR_REJECTED = "#8172B2"
COLOR_IRRELEVANT = "#DD8452"
COLOR_PLAUSIBLE = "#B22222"


def _rect(ax, x, y, w, h, lines, color, fontsize=8.3, text_color="white"):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=1.1, edgecolor=color, facecolor=color, alpha=0.95,
    )
    ax.add_patch(box)
    n = len(lines)
    line_h = h / (n + 1)
    for i, (text, weight, delta) in enumerate(lines):
        ty = y + h - line_h * (i + 1)
        ax.text(x + w / 2, ty, text, ha="center", va="center",
                 fontsize=fontsize + delta, fontweight=weight, color=text_color)
    return box


def _diamond(ax, cx, cy, w, h, lines, fontsize=7.8):
    # A rounded rectangle styled distinctly (thicker white border, "?"
    # marker) reads clearly as a decision node without a true rhombus's
    # text-vs-taper problems -- diamond text near the top/bottom apex
    # overflows the shape's narrow point at that height, which turned
    # into real clipping-looking bugs in an earlier draft of this
    # figure; a rectangle has no such taper.
    box = FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=1.8, edgecolor="white", facecolor=COLOR_DECISION, alpha=0.95,
    )
    ax.add_patch(box)
    n = len(lines)
    line_h = h / (n + 1)
    for i, text in enumerate(lines):
        ty = cy + h / 2 - line_h * (i + 1)
        ax.text(cx, ty, text, ha="center", va="center", fontsize=fontsize,
                 color="white", fontweight="bold" if i == 0 else "normal")
    ax.text(cx - w / 2 + 0.18, cy + h / 2 - 0.2, "?", fontsize=11, color="white",
             fontweight="bold", ha="left", va="top", alpha=0.65)


def _arrow(ax, xy_from, xy_to, color="#444444", lw=1.2, connectionstyle=None):
    arrow = FancyArrowPatch(
        xy_from, xy_to, arrowstyle="-|>", mutation_scale=12,
        linewidth=lw, color=color, shrinkA=1, shrinkB=1,
        connectionstyle=connectionstyle,
    )
    ax.add_patch(arrow)


def make():
    fig, ax = plt.subplots(figsize=(8.6, 8.2))
    ax.set_xlim(0, 11.6)
    ax.set_ylim(0, 17.3)
    ax.axis("off")
    ax.set_aspect("equal")

    cx = 4.6           # spine center
    dw, dh = 4.6, 1.55  # decision-node size
    leaf_x = 8.6
    leaf_w, leaf_h = 3.0, 1.55

    # Root
    _rect(ax, cx - 3.1, 15.6, 6.2, 1.0,
          [("Citation extracted from LLM report", "bold", 0), ("(CVE- or ATT&CK-shaped identifier)", "normal", -1.3)],
          COLOR_ROOT, fontsize=8.5)

    # D1: grounding
    d1y = 14.0
    _diamond(ax, cx, d1y, dw, dh, ["Present in the alert's own", "Evidence Pack text?", "(Stage 1: grounding)"])
    _arrow(ax, (cx, 15.6), (cx, d1y + dh / 2))

    _rect(ax, leaf_x, d1y - leaf_h / 2, leaf_w, leaf_h,
          [("GROUNDED", "bold", 0.3), ("Stage 2 never runs", "normal", -1.5)],
          COLOR_GROUNDED, fontsize=8.6)
    _arrow(ax, (cx + dw / 2, d1y), (leaf_x, d1y))
    ax.text(cx + dw / 2 + 0.15, d1y + 0.25, "yes", fontsize=7, color=COLOR_GROUNDED)

    # D2: source reachable / has a record
    d2y = 11.6
    _arrow(ax, (cx, d1y - dh / 2), (cx, d2y + dh / 2))
    ax.text(cx - 0.3, (d1y - dh / 2 + d2y + dh / 2) / 2, "no", fontsize=7, color="#555555", ha="right")
    _diamond(ax, cx, d2y, dw, dh, ["Authoritative source reachable,", "with a usable description?", "(NVD live / MITRE STIX snapshot)"])

    _rect(ax, leaf_x, d2y - leaf_h / 2, leaf_w, leaf_h,
          [("UNVERIFIED", "bold", 0.3), ("source couldn't confirm", "normal", -1.5), ("or deny", "normal", -1.5)],
          COLOR_UNVERIFIED, fontsize=8.4)
    _arrow(ax, (cx + dw / 2, d2y), (leaf_x, d2y))
    ax.text(cx + dw / 2 + 0.15, d2y + 0.25, "no", fontsize=7, color=COLOR_UNVERIFIED)

    # D3: exists at all
    d3y = 9.2
    _arrow(ax, (cx, d2y - dh / 2), (cx, d3y + dh / 2))
    ax.text(cx - 0.3, (d2y - dh / 2 + d3y + dh / 2) / 2, "yes", fontsize=7, color="#555555", ha="right")
    _diamond(ax, cx, d3y, dw, dh, ["Identifier exists in the", "source at all?"])

    _rect(ax, leaf_x, d3y - leaf_h / 2, leaf_w, leaf_h,
          [("FABRICATED", "bold", 0.3), ("doesn't exist in the", "normal", -1.5), ("authoritative source", "normal", -1.5)],
          COLOR_FABRICATED, fontsize=8.4)
    _arrow(ax, (cx + dw / 2, d3y), (leaf_x, d3y))
    ax.text(cx + dw / 2 + 0.15, d3y + 0.25, "no", fontsize=7, color=COLOR_FABRICATED)

    # D4: withdrawn
    d4y = 6.8
    _arrow(ax, (cx, d3y - dh / 2), (cx, d4y + dh / 2))
    ax.text(cx - 0.3, (d3y - dh / 2 + d4y + dh / 2) / 2, "yes", fontsize=7, color="#555555", ha="right")
    _diamond(ax, cx, d4y, dw, dh, ["Formally withdrawn?", "(NVD REJECTED /", "MITRE revoked)"])

    _rect(ax, leaf_x, d4y - leaf_h / 2, leaf_w, leaf_h,
          [("REJECTED / REVOKED", "bold", -0.5), ("formally withdrawn by", "normal", -1.5), ("its own authority", "normal", -1.5)],
          COLOR_REJECTED, fontsize=8.0)
    _arrow(ax, (cx + dw / 2, d4y), (leaf_x, d4y))
    ax.text(cx + dw / 2 + 0.15, d4y + 0.25, "yes", fontsize=7, color=COLOR_REJECTED)

    # D5: topical overlap
    d5y = 4.4
    _arrow(ax, (cx, d4y - dh / 2), (cx, d5y + dh / 2))
    ax.text(cx - 0.3, (d4y - dh / 2 + d5y + dh / 2) / 2, "no", fontsize=7, color="#555555", ha="right")
    _diamond(ax, cx, d5y, dw, dh, ["Topical overlap with alert", "evidence ≥ 0.15?", "(stemmed bag-of-words)"])

    _rect(ax, leaf_x, d5y - leaf_h / 2, leaf_w, leaf_h,
          [("REAL_BUT_IRRELEVANT", "bold", -1.1), ("real identifier, wrong", "normal", -1.5), ("context for this alert", "normal", -1.5)],
          COLOR_IRRELEVANT, fontsize=7.9)
    _arrow(ax, (cx + dw / 2, d5y), (leaf_x, d5y))
    ax.text(cx + dw / 2 + 0.15, d5y + 0.25, "no", fontsize=7, color=COLOR_IRRELEVANT)

    # Terminal: REAL_AND_PLAUSIBLE (straight down, flagged as highest-risk)
    leaf2_y = 1.1
    _arrow(ax, (cx, d5y - dh / 2), (cx, leaf2_y + leaf_h + 0.35))
    ax.text(cx + 0.25, (d5y - dh / 2 + leaf2_y + leaf_h) / 2, "yes", fontsize=7, color=COLOR_PLAUSIBLE)

    _rect(ax, cx - 3.3, leaf2_y, 6.6, leaf_h,
          [("REAL_AND_PLAUSIBLE", "bold", 0.5),
           ("real + topically matches -- this paper's central finding:", "normal", -1.3),
           ("the highest-risk class, precisely because it looks correct", "normal", -1.3)],
          COLOR_PLAUSIBLE, fontsize=8.2)

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_taxonomy.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_taxonomy.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_taxonomy.pdf/.png"))


if __name__ == "__main__":
    make()
