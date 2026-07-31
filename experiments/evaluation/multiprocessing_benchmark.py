"""

    python -m experiments.evaluation.multiprocessing_benchmark
    python -m experiments.evaluation.multiprocessing_benchmark --guardrail-n 2000 --pipeline-n 6 --processes 1 2 4
"""

import argparse
import itertools
import json
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor

import psutil

from src.agent.alert_schema import SAMPLE_ALERTS
from src.agent.soc_agent import format_alert
from src.guardrails.input_guardrail import check_injection
from experiments.evaluation.threading_benchmark import analyse_alert_with_retry


class CpuMonitor:
    """
    Samples system-wide CPU% in a background thread while a benchmark runs.
    System-wide (not per-process) is deliberate: with multiprocessing,
    "how busy is the machine" is the meaningful comparison against the
    threading results, which were also measured system-wide.
    """

    def __init__(self, interval: float = 0.1):
        self.interval = interval
        self._samples = []
        self._stop = threading.Event()
        self._thread = None

    def _loop(self):
        while not self._stop.is_set():
            self._samples.append(psutil.cpu_percent(interval=self.interval))

    def __enter__(self):
        self._samples = []
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()

    @property
    def avg_cpu(self):
        return sum(self._samples) / len(self._samples) if self._samples else 0.0

    @property
    def max_cpu(self):
        return max(self._samples) if self._samples else 0.0


def build_workload(n: int):
    return list(itertools.islice(itertools.cycle(SAMPLE_ALERTS), n))


# Module-level worker functions — required for ProcessPoolExecutor/pickle,
# especially on Windows (spawn start method).

def _guardrail_worker(alert_text: str) -> bool:
    return check_injection(alert_text)


def _pipeline_worker(alert):
    return analyse_alert_with_retry(alert)


def run_guardrail_only(alerts, num_processes: int):
    texts = [format_alert(a) for a in alerts]

    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_processes == 1:
            results = [_guardrail_worker(t) for t in texts]
        else:
            with ProcessPoolExecutor(max_workers=num_processes) as pool:
                results = list(pool.map(_guardrail_worker, texts))
        elapsed = time.perf_counter() - start

    throughput = len(alerts) / elapsed if elapsed > 0 else float("inf")
    return {
        "num_processes": num_processes,
        "n": len(alerts),
        "elapsed_sec": elapsed,
        "throughput_per_sec": throughput,
        "avg_cpu_percent": monitor.avg_cpu,
        "max_cpu_percent": monitor.max_cpu,
    }


def run_full_pipeline(alerts, num_processes: int):
    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_processes == 1:
            results = [_pipeline_worker(a) for a in alerts]
        else:
            with ProcessPoolExecutor(max_workers=num_processes) as pool:
                results = list(pool.map(_pipeline_worker, alerts))
        elapsed = time.perf_counter() - start

    rate_limited = sum(1 for r in results if r.get("rate_limited"))
    throughput = len(alerts) / elapsed if elapsed > 0 else float("inf")
    return {
        "num_processes": num_processes,
        "n": len(alerts),
        "elapsed_sec": elapsed,
        "throughput_per_sec": throughput,
        "avg_cpu_percent": monitor.avg_cpu,
        "max_cpu_percent": monitor.max_cpu,
        "rate_limited_count": rate_limited,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardrail-n", type=int, default=2000,
                         help="Number of alerts for the guardrail-only benchmark")
    parser.add_argument("--pipeline-n", type=int, default=6,
                         help="Number of alerts for the full-pipeline benchmark (costs real Groq API calls)")
    parser.add_argument("--processes", type=int, nargs="+", default=[1, 2, 4],
                         help="Process counts to test")
    parser.add_argument("--cooldown", type=float, default=15.0,
                         help="Seconds between thread-count runs in the pipeline benchmark, to let Groq TPM budget recover")
    args = parser.parse_args()

    results = {"guardrail_only": [], "full_pipeline": []}

    print("=== Guardrail-only benchmark: multiprocessing (CPU-bound, no GIL across processes) ===")
    guardrail_alerts = build_workload(args.guardrail_n)
    for p in args.processes:
        r = run_guardrail_only(guardrail_alerts, p)
        results["guardrail_only"].append(r)
        print(f"  processes={p:>2} | {r['throughput_per_sec']:>12,.0f} alerts/sec | "
              f"avg_cpu={r['avg_cpu_percent']:.1f}% | max_cpu={r['max_cpu_percent']:.1f}%")

    print("\n=== Full pipeline benchmark: multiprocessing (I/O-bound: Groq API) ===")
    print(f"  (using n={args.pipeline_n} per process-count — this makes real API calls, keep n modest)")
    pipeline_alerts = build_workload(args.pipeline_n)
    for i, p in enumerate(args.processes):
        if i > 0:
            print(f"  [cooling down {args.cooldown:.0f}s to let Groq TPM budget recover]")
            time.sleep(args.cooldown)
        r = run_full_pipeline(pipeline_alerts, p)
        results["full_pipeline"].append(r)
        rl_note = f" | rate_limited={r['rate_limited_count']}" if r["rate_limited_count"] else ""
        print(f"  processes={p:>2} | {r['throughput_per_sec']:>8.2f} alerts/sec | "
              f"avg_cpu={r['avg_cpu_percent']:.1f}% | max_cpu={r['max_cpu_percent']:.1f}%{rl_note}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/multiprocessing_benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    main()