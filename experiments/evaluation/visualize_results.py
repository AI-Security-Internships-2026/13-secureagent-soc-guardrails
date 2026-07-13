

import argparse
import json
import os

import matplotlib.pyplot as plt


def load_results(path: str):
    with open(path) as f:
        return json.load(f)


def make_charts(results: dict, output_path: str):
    guardrail = results["guardrail_only"]
    pipeline = results["full_pipeline"]

    g_threads = [r["num_threads"] for r in guardrail]
    g_throughput = [r["throughput_per_sec"] for r in guardrail]
    g_cpu = [r["avg_cpu_percent"] for r in guardrail]

    p_threads = [r["num_threads"] for r in pipeline]
    p_throughput = [r["throughput_per_sec"] for r in pipeline]
    p_cpu = [r["avg_cpu_percent"] for r in pipeline]

    labels = [str(t) for t in g_threads]
    colors = ["#4C72B0", "#DD8452", "#55A868"][: len(labels)]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle("SecureAgent-SOC — Multi-Threading Benchmark", fontsize=14, fontweight="bold")

    ax = axes[0][0]
    ax.bar(labels, g_throughput, color=colors)
    ax.set_yscale("log")
    ax.set_title("Guardrail-only throughput (CPU-bound, GIL-limited)")
    ax.set_xlabel("Threads")
    ax.set_ylabel("Alerts / sec (log scale)")
    for i, v in enumerate(g_throughput):
        ax.text(i, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=9)

    ax = axes[0][1]
    ax.bar(labels, p_throughput, color=colors)
    ax.set_title("Full pipeline throughput (I/O-bound: Groq API)")
    ax.set_xlabel("Threads")
    ax.set_ylabel("Alerts / sec")
    for i, v in enumerate(p_throughput):
        ax.text(i, v, f"{v:.2f}", ha="center", va="bottom", fontsize=9)

    ax = axes[1][0]
    ax.bar(labels, g_cpu, color=colors)
    ax.set_title("Guardrail-only avg CPU usage")
    ax.set_xlabel("Threads")
    ax.set_ylabel("Avg CPU %")
    ax.set_ylim(0, 100)
    for i, v in enumerate(g_cpu):
        ax.text(i, v, f"{v:.1f}%", ha="center", va="bottom", fontsize=9)

    ax = axes[1][1]
    ax.bar(labels, p_cpu, color=colors)
    ax.set_title("Full pipeline avg CPU usage")
    ax.set_xlabel("Threads")
    ax.set_ylabel("Avg CPU %")
    ax.set_ylim(0, 100)
    for i, v in enumerate(p_cpu):
        ax.text(i, v, f"{v:.1f}%", ha="center", va="bottom", fontsize=9)

    plt.tight_layout(rect=[0, 0, 1, 0.96])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=150)
    print(f"Saved chart to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="experiments/results/threading_benchmark_results.json")
    parser.add_argument("--output", default="experiments/results/visualizations/threading_benchmark_charts.png")
    args = parser.parse_args()

    results = load_results(args.input)
    make_charts(results, args.output)