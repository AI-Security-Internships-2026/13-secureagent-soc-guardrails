"""
experiments/evaluation/visualize_concurrency_comparison.py

Week 7: side-by-side comparison of threading vs multiprocessing, across
both the guardrail-only (CPU-bound) and full-pipeline (I/O-bound)
workloads. Reads both result JSONs already produced by
threading_benchmark.py and multiprocessing_benchmark.py — does not re-run
either benchmark.

Produces a 2x2 grid of grouped bar charts:
  [guardrail-only throughput]   [full pipeline throughput]
  [guardrail-only avg CPU%]     [full pipeline avg CPU%]

Each panel groups threading vs multiprocessing side by side per worker
count (1/2/4), so the divergence is directly visible rather than requiring
two separate charts to be mentally overlaid.

Usage:
    python -m experiments.evaluation.visualize_concurrency_comparison
"""

import argparse
import json
import os

import matplotlib.pyplot as plt
import numpy as np


def load_results(path: str):
    with open(path) as f:
        return json.load(f)


def make_comparison_chart(threading_results: dict, mp_results: dict, output_path: str):
    worker_counts = [r["num_threads"] for r in threading_results["guardrail_only"]]
    x = np.arange(len(worker_counts))
    width = 0.35

    thread_color = "#4C72B0"
    process_color = "#C44E52"

    repeats = threading_results["guardrail_only"][0].get("repeats", 1)

    fig, axes = plt.subplots(2, 2, figsize=(13, 9))
    fig.suptitle(f"SecureAgent-SOC — Threading vs Multiprocessing (mean ± stdev, n={repeats} repeats)",
                 fontsize=13, fontweight="bold")

    def grouped_bar(ax, thread_vals, process_vals, ylabel, title, thread_err=None, process_err=None,
                     log_scale=False, as_percent=False):
        b1 = ax.bar(x - width / 2, thread_vals, width, yerr=thread_err, capsize=3,
                     label="Threading", color=thread_color)
        b2 = ax.bar(x + width / 2, process_vals, width, yerr=process_err, capsize=3,
                     label="Multiprocessing", color=process_color)
        if log_scale:
            ax.set_yscale("log")
        ax.set_title(title)
        ax.set_xlabel("Worker count")
        ax.set_ylabel(ylabel)
        ax.set_xticks(x)
        ax.set_xticklabels([str(w) for w in worker_counts])
        ax.legend(fontsize=8)
        fmt = (lambda v: f"{v:.1f}%") if as_percent else (lambda v: f"{v:,.0f}" if v >= 100 else f"{v:.2f}")
        for bars in (b1, b2):
            for bar in bars:
                h = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2, h, fmt(h), ha="center", va="bottom", fontsize=7)

    # Each result is now an aggregate over N repeats rather than a
    # single-shot number — stdev is plotted as an error bar so the spread
    # (and whether threading vs multiprocessing differ by more than noise)
    # stays visible instead of being collapsed to one point estimate.
    g_thread_throughput = [r["throughput_per_sec"]["mean"] for r in threading_results["guardrail_only"]]
    g_thread_throughput_err = [r["throughput_per_sec"]["stdev"] for r in threading_results["guardrail_only"]]
    g_process_throughput = [r["throughput_per_sec"]["mean"] for r in mp_results["guardrail_only"]]
    g_process_throughput_err = [r["throughput_per_sec"]["stdev"] for r in mp_results["guardrail_only"]]
    grouped_bar(axes[0][0], g_thread_throughput, g_process_throughput,
                "Alerts/sec (log scale)", "Guardrail-only throughput",
                thread_err=g_thread_throughput_err, process_err=g_process_throughput_err, log_scale=True)

    p_thread_throughput = [r["throughput_per_sec"]["mean"] for r in threading_results["full_pipeline"]]
    p_thread_throughput_err = [r["throughput_per_sec"]["stdev"] for r in threading_results["full_pipeline"]]
    p_process_throughput = [r["throughput_per_sec"]["mean"] for r in mp_results["full_pipeline"]]
    p_process_throughput_err = [r["throughput_per_sec"]["stdev"] for r in mp_results["full_pipeline"]]
    grouped_bar(axes[0][1], p_thread_throughput, p_process_throughput,
                "Alerts/sec", "Full pipeline throughput",
                thread_err=p_thread_throughput_err, process_err=p_process_throughput_err)

    g_thread_cpu = [r["avg_cpu_percent"]["mean"] for r in threading_results["guardrail_only"]]
    g_thread_cpu_err = [r["avg_cpu_percent"]["stdev"] for r in threading_results["guardrail_only"]]
    g_process_cpu = [r["avg_cpu_percent"]["mean"] for r in mp_results["guardrail_only"]]
    g_process_cpu_err = [r["avg_cpu_percent"]["stdev"] for r in mp_results["guardrail_only"]]
    grouped_bar(axes[1][0], g_thread_cpu, g_process_cpu,
                "Avg CPU %", "Guardrail-only avg CPU usage",
                thread_err=g_thread_cpu_err, process_err=g_process_cpu_err, as_percent=True)
    axes[1][0].set_ylim(0, 100)

    p_thread_cpu = [r["avg_cpu_percent"]["mean"] for r in threading_results["full_pipeline"]]
    p_thread_cpu_err = [r["avg_cpu_percent"]["stdev"] for r in threading_results["full_pipeline"]]
    p_process_cpu = [r["avg_cpu_percent"]["mean"] for r in mp_results["full_pipeline"]]
    p_process_cpu_err = [r["avg_cpu_percent"]["stdev"] for r in mp_results["full_pipeline"]]
    grouped_bar(axes[1][1], p_thread_cpu, p_process_cpu,
                "Avg CPU %", "Full pipeline avg CPU usage",
                thread_err=p_thread_cpu_err, process_err=p_process_cpu_err, as_percent=True)
    axes[1][1].set_ylim(0, 100)

    plt.tight_layout(rect=[0, 0, 1, 0.96])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=150)
    print(f"Saved chart to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threading-input", default="experiments/results/threading_benchmark_results.json")
    parser.add_argument("--mp-input", default="experiments/results/multiprocessing_benchmark_results.json")
    parser.add_argument("--output", default="experiments/results/visualizations/concurrency_comparison_charts.png")
    args = parser.parse_args()

    threading_results = load_results(args.threading_input)
    mp_results = load_results(args.mp_input)
    make_comparison_chart(threading_results, mp_results, args.output)