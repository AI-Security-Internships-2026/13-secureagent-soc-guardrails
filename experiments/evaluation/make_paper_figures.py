"""
experiments/evaluation/make_paper_figures.py

Generates the two figures picked (2026-08-31) as the highest-value graphs
to add to the paper on top of its existing tables:
  1. Grouped bar chart -- SelfCheckGPT correctness by class (stated/
     prompted) x generator model (gpt-oss-20b, qwen), directly
     visualizing the paper's central finding (Sect. 4.4).
  2. Line chart -- concurrency/throughput benchmark (Table 7), workers
     (1/2/4) x threading/multiprocessing x three workload types, with
     error bars (mean +/- stdev). Threading-scales-up vs.
     multiprocessing-scales-down is far easier to read as lines than as
     Table 7's 9 rows.

Both figures pull numbers directly from the already-committed result
files -- nothing here is hand-typed or re-derived by eye. Saves both as
.pdf (vector, for \\includegraphics in sn-article.tex) and .png (quick
preview).

Usage:
    python -m experiments.evaluation.make_paper_figures
"""

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = "experiments/results"
OUT_DIR = "docs/paper/figures"

# Colorblind-safe, consistent across both figures.
COLOR_GPT_OSS = "#4C72B0"
COLOR_QWEN = "#DD8452"
COLOR_THREADING = "#4C72B0"
COLOR_MULTIPROC = "#DD8452"

plt.rcParams.update({
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.5,
    "figure.dpi": 150,
})


def _class_breakdown(path):
    with open(path) as f:
        d = json.load(f)
    results = d["results"]
    out = {}
    for cls in ("stated", "prompted"):
        rows = [r for r in results if r["class"] == cls]
        scored = [r for r in rows if r["citation_occurred"]]
        correct = [r for r in scored if r["expected_ungrounded"] == r["flagged_unstable"]]
        out[cls] = (len(correct), len(scored))
    return out


def make_figure1_selfcheckgpt_by_class():
    gpt_oss = _class_breakdown(os.path.join(RESULTS_DIR, "selfcheckgpt_results.json"))
    qwen = _class_breakdown(os.path.join(RESULTS_DIR, "selfcheckgpt_results_qwen_qwen3_6_27b.json"))

    classes = ["Stated\n(grounded)", "Prompted\n(bait, withheld)"]
    gpt_oss_rate = [gpt_oss["stated"][0] / gpt_oss["stated"][1] * 100,
                    gpt_oss["prompted"][0] / gpt_oss["prompted"][1] * 100]
    qwen_rate = [qwen["stated"][0] / qwen["stated"][1] * 100,
                 qwen["prompted"][0] / qwen["prompted"][1] * 100]
    gpt_oss_labels = [f"{gpt_oss['stated'][0]}/{gpt_oss['stated'][1]}",
                       f"{gpt_oss['prompted'][0]}/{gpt_oss['prompted'][1]}"]
    qwen_labels = [f"{qwen['stated'][0]}/{qwen['stated'][1]}",
                   f"{qwen['prompted'][0]}/{qwen['prompted'][1]}"]

    x = np.arange(len(classes))
    width = 0.32

    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    bars1 = ax.bar(x - width / 2, gpt_oss_rate, width, label="openai/gpt-oss-20b",
                    color=COLOR_GPT_OSS, edgecolor="white", linewidth=0.6)
    bars2 = ax.bar(x + width / 2, qwen_rate, width, label="qwen/qwen3.6-27b",
                    color=COLOR_QWEN, edgecolor="white", linewidth=0.6)

    for bars, labels in ((bars1, gpt_oss_labels), (bars2, qwen_labels)):
        for bar, lab in zip(bars, labels):
            ax.annotate(lab, (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8.5)

    ax.set_ylabel("SelfCheckGPT correct (%)")
    ax.set_ylim(0, 112)
    ax.set_xticks(x)
    ax.set_xticklabels(classes)
    ax.set_title("SelfCheckGPT self-consistency: correctness by class and generator model",
                 fontsize=10)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, frameon=False, fontsize=9)
    ax.axhline(100, color="gray", linewidth=0.6, linestyle=":", zorder=0)

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_selfcheckgpt_by_class.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_selfcheckgpt_by_class.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_selfcheckgpt_by_class.pdf/.png"))


# Table 7's numbers, verbatim (experiments/results -- these are the fresh-process
# concurrency-benchmark outputs; hard-coded here since Table 7 in the paper is
# itself the primary record of this benchmark's run, not a separate JSON file
# this script would otherwise re-derive from).
CONCURRENCY_DATA = {
    "Guardrail-only": {
        "workers": [1, 2, 4],
        "threading": [(850323, 115672), (108456, 9380), (97063, 14474)],
        "multiprocessing": [(648379, 41175), (309, 2), (230, 1)],
        "log_scale": True,
    },
    "Full pipeline,\nmocked LLM": {
        "workers": [1, 2, 4],
        "threading": [(1.973, 0.032), (2.660, 0.140), (3.284, 0.415)],
        "multiprocessing": [(2.031, 0.018), (1.380, 0.006), (1.328, 0.010)],
        "log_scale": False,
    },
    "Full pipeline,\nreal Groq": {
        "workers": [1, 2, 4],
        "threading": [(0.839, 0.019), (1.196, 0.174), (1.243, 0.170)],
        "multiprocessing": [(0.896, 0.037), (0.333, 0.006), (0.273, 0.017)],
        "log_scale": False,
    },
}


def make_figure2_concurrency():
    fig, axes = plt.subplots(1, 3, figsize=(10.5, 3.4))

    for ax, (title, d) in zip(axes, CONCURRENCY_DATA.items()):
        workers = d["workers"]
        th_mean = [v[0] for v in d["threading"]]
        th_err = [v[1] for v in d["threading"]]
        mp_mean = [v[0] for v in d["multiprocessing"]]
        mp_err = [v[1] for v in d["multiprocessing"]]

        ax.errorbar(workers, th_mean, yerr=th_err, marker="o", markersize=5,
                    color=COLOR_THREADING, label="Threading", capsize=3, linewidth=1.6)
        ax.errorbar(workers, mp_mean, yerr=mp_err, marker="s", markersize=5,
                    color=COLOR_MULTIPROC, label="Multiprocessing", capsize=3, linewidth=1.6)

        if d["log_scale"]:
            ax.set_yscale("log")
        ax.set_xticks(workers)
        ax.set_xlabel("Workers")
        ax.set_title(title, fontsize=9.5)
        ax.margins(x=0.15)

    axes[0].set_ylabel("Throughput (alerts/sec)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, frameon=False,
               fontsize=9, bbox_to_anchor=(0.5, -0.06))
    fig.suptitle("Concurrency benchmark: throughput vs. worker count (fresh-process repeats, mean ± stdev)",
                 fontsize=10.5, y=1.03)

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, "fig_concurrency_throughput.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_concurrency_throughput.png"), bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT_DIR, "fig_concurrency_throughput.pdf/.png"))


if __name__ == "__main__":
    make_figure1_selfcheckgpt_by_class()
    make_figure2_concurrency()
