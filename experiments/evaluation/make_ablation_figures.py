"""
experiments/evaluation/make_ablation_figures.py

Issue #42 (R3), Task 3 — builds Figure F3 (taxonomy-class stacked bar per
ablation config) and Figure F4 (UpSet plot of unique-detection overlap),
from the now-complete `experiments/results/ablation_full.jsonl` (2,616
rows: 6 configs x 436 alerts, see docs/all_results.md #75-#83).

F3: per config, how many CVE/ATT&CK citation verifications landed in
each of the paper's taxonomy tiers (pooling both citation families,
since the taxonomy is defined identically across both — REJECTED (CVE)
and REVOKED (ATT&CK) are the same tier under this paper's taxonomy and
are merged here as "REJ/REV", matching the taxonomy figure issue #51 is
building separately). FABRICATED and UNVERIFIED never occurred in this
pool at any config — reported honestly as zero bars rather than omitted,
since a reviewer comparing this to Sect. 4.2-4.5's bait-test tiers
should see the same taxonomy vocabulary used consistently.

F4: for each config, the set of alert_ids where requires_review=True.
Answers "which alerts would NOT have been flagged, if this stage had
been removed?" — an UpSet plot instead of a 6-set Venn diagram, which
stops being readable past 3-4 sets.

Usage:
    python -m experiments.evaluation.make_ablation_figures
"""

import json
import os
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import upsetplot

RESULTS_PATH = "experiments/results/ablation_full.jsonl"
OUT_DIR = "docs/paper/figures"

CONFIG_ORDER = ["C0", "C1", "C2", "C3", "C4", "C5"]
CONFIG_LABELS = {
    "C0": "Full", "C1": "$-$Input", "C2": "$-$CVE",
    "C3": "$-$ATT&CK", "C4": "$-$PII", "C5": "None",
}
TIER_ORDER = ["FABRICATED", "REJ/REV", "REAL_BUT_IRRELEVANT", "UNVERIFIED", "REAL_AND_PLAUSIBLE"]
TIER_LABELS = {
    "FABRICATED": "FAB", "REJ/REV": "REJ/REV",
    "REAL_BUT_IRRELEVANT": "R&I", "UNVERIFIED": "UNV",
    "REAL_AND_PLAUSIBLE": "R&P",
}
TIER_COLORS = {
    "FABRICATED": "#C44E52", "REJ/REV": "#8172B2",
    "REAL_BUT_IRRELEVANT": "#DD8452", "UNVERIFIED": "#999999",
    "REAL_AND_PLAUSIBLE": "#4C72B0",
}

plt.rcParams.update({
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.5,
    "figure.dpi": 150,
})


def _load():
    tiers = defaultdict(lambda: defaultdict(int))
    flagged = defaultdict(set)
    with open(RESULTS_PATH, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            cfg = row["config_id"]
            rep = row.get("output_report") or {}
            if rep.get("requires_review"):
                flagged[cfg].add(row["alert_id"])
            for v in (rep.get("cve_verifications") or []) + (rep.get("attack_technique_verifications") or []):
                c = v.get("classification")
                if c in ("REJECTED", "REVOKED"):
                    c = "REJ/REV"
                tiers[cfg][c] += 1
    return tiers, flagged


def make_figure_f3(tiers):
    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    x = range(len(CONFIG_ORDER))
    bottoms = [0.0] * len(CONFIG_ORDER)

    for tier in TIER_ORDER:
        values = [tiers[cfg].get(tier, 0) for cfg in CONFIG_ORDER]
        ax.bar(x, values, bottom=bottoms, label=TIER_LABELS[tier],
               color=TIER_COLORS[tier], edgecolor="white", linewidth=0.6)
        bottoms = [b + v for b, v in zip(bottoms, values)]

    for xi, total in zip(x, bottoms):
        if total > 0:
            ax.annotate(str(int(total)), (xi, total), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8.5)

    ax.set_xticks(list(x))
    ax.set_xticklabels([CONFIG_LABELS[c] for c in CONFIG_ORDER])
    ax.set_ylabel("Citation verifications")
    ax.set_title("Ablation: citation-taxonomy tier by configuration", fontsize=10.5)
    ax.legend(loc="upper right", fontsize=8, frameon=False, ncol=1)

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_ablation_taxonomy_stacked.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_ablation_taxonomy_stacked.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_ablation_taxonomy_stacked.pdf/.png"))


def make_figure_f4(flagged):
    contents = {CONFIG_LABELS[cfg]: flagged[cfg] for cfg in CONFIG_ORDER}
    data = upsetplot.from_contents(contents)

    fig = plt.figure(figsize=(9.0, 4.6))
    # show_counts=True hits a real upsetplot 0.9.0 / matplotlib 3.11
    # incompatibility (TypeError in its internal count-label text
    # positioning -- reproduced on a minimal 3-set example too, not
    # specific to this data). Draw counts manually on the returned
    # "intersections" axis instead of using the broken built-in path.
    upset = upsetplot.UpSet(data, subset_size="count", show_counts=False,
                             sort_by="cardinality", min_subset_size=1)
    axes = upset.plot(fig=fig)
    for bar in axes["intersections"].patches:
        height = bar.get_height()
        if height > 0:
            axes["intersections"].annotate(
                str(int(height)), (bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 2), textcoords="offset points",
                ha="center", va="bottom", fontsize=7.5,
            )
    fig.suptitle("Ablation: overlap of alerts flagged \"requires review\" across configurations",
                 fontsize=10.5, y=1.01)

    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_ablation_upset_unique_alerts.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_ablation_upset_unique_alerts.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_ablation_upset_unique_alerts.pdf/.png"))


if __name__ == "__main__":
    tiers, flagged = _load()
    make_figure_f3(tiers)
    make_figure_f4(flagged)
