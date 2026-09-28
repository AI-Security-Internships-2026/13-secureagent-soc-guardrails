"""
experiments/evaluation/make_fig_f6.py

Issue #44 (R5), Task 2 -- Figure F6, the temperature-boundary curves.
Reads experiments/results/temperature_sweep_summary.json (built by
temperature_sweep_driver.py's --summarize, run automatically at the end
of a complete sweep) and plots all four required series across the
5-point temperature grid, each with a shaded 95% Wilson CI band:

  - P(volunteer any CVE)              -- blue
  - P(REAL_AND_PLAUSIBLE | volunteered) -- green
  - SelfCheckGPT recall on the confirmed-unsupported subset -- orange
  - LLMCite deterministic detection rate on that same subset -- red,
    flat at 1.0 by pipeline construction (Sect. 4.8's ablation
    docstring explains why: every ungrounded citation unconditionally
    sets requires_review=True, independent of temperature or class) --
    drawn as a dashed reference line, no CI band, since it has no
    sampling variance to show.

Usage:
    python -m experiments.evaluation.make_fig_f6
"""

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS_PATH = "experiments/results/temperature_sweep_summary.json"
OUT_DIR = "docs/paper/figures"

plt.rcParams.update({
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.5,
    "figure.dpi": 150,
})

COLOR_VOLUNTEER = "#4C72B0"
COLOR_PLAUSIBLE = "#55A868"
COLOR_RECALL = "#DD8452"
COLOR_DETECTION = "#C44E52"


def _band(ax, x, ci_lo, ci_hi, color):
    ax.fill_between(x, ci_lo, ci_hi, color=color, alpha=0.15, linewidth=0)


def make():
    with open(RESULTS_PATH, encoding="utf-8") as f:
        summary = json.load(f)

    rows = summary["per_temperature"]
    temps = [r["temperature"] for r in rows]

    volunteer = [r["p_volunteer"] for r in rows]
    volunteer_lo = [r["p_volunteer_wilson_ci_95"][0] for r in rows]
    volunteer_hi = [r["p_volunteer_wilson_ci_95"][1] for r in rows]

    plausible = [r["p_correct_but_unsupported"] for r in rows]
    plausible_lo = [r["p_correct_but_unsupported_wilson_ci_95"][0] for r in rows]
    plausible_hi = [r["p_correct_but_unsupported_wilson_ci_95"][1] for r in rows]

    recall = [r["selfcheckgpt_recall_on_unsupported"] for r in rows]
    recall_lo = [r["selfcheckgpt_recall_wilson_ci_95"][0] for r in rows]
    recall_hi = [r["selfcheckgpt_recall_wilson_ci_95"][1] for r in rows]

    detection = [r["llmcite_detection_rate_on_unsupported"] for r in rows]

    fig, ax = plt.subplots(figsize=(7.0, 4.6))

    _band(ax, temps, volunteer_lo, volunteer_hi, COLOR_VOLUNTEER)
    ax.plot(temps, volunteer, marker="o", color=COLOR_VOLUNTEER, linewidth=1.8,
             label="% volunteered any CVE")

    _band(ax, temps, plausible_lo, plausible_hi, COLOR_PLAUSIBLE)
    ax.plot(temps, plausible, marker="o", color=COLOR_PLAUSIBLE, linewidth=1.8,
             label="% REAL_AND_PLAUSIBLE (confirmed unsupported)")

    _band(ax, temps, recall_lo, recall_hi, COLOR_RECALL)
    ax.plot(temps, recall, marker="o", color=COLOR_RECALL, linewidth=1.8,
             label="SelfCheckGPT recall on unsupported")

    ax.plot(temps, detection, marker="s", color=COLOR_DETECTION, linewidth=1.8,
             linestyle="--", label="LLMCite detection rate on unsupported")

    ax.set_xlabel("Sampling temperature")
    ax.set_ylabel("Rate (0-1), 95% Wilson CI shaded")
    ax.set_xticks(temps)
    ax.set_ylim(-0.03, 1.05)
    ax.set_title("Temperature sensitivity: citation volunteering and detection\n"
                  "(30 withheld-CVE alerts, 3 resamples each)", fontsize=10.5)
    ax.legend(loc="center right", fontsize=8, frameon=False)

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_f6_temperature_boundary.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_f6_temperature_boundary.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_f6_temperature_boundary.pdf/.png"))


if __name__ == "__main__":
    make()
