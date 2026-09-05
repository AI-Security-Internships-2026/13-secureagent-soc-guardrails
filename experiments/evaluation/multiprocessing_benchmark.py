"""
experiments/evaluation/multiprocessing_benchmark.py

Week 7 task: compare separate Python processes (multiprocessing) against
the existing threading results, for both the guardrail-only (CPU-bound)
and full-pipeline (I/O-bound) workloads.

Why this matters given what threading_benchmark.py already found:
  - Guardrail-only got SLOWER with more threads — GIL contention on a
    microsecond-scale task dominates over any parallel benefit.
  - Full pipeline got FASTER with more threads — the GIL releases during
    the Groq network wait, so threads overlap I/O.

Multiprocessing sidesteps the GIL entirely: each process has its own
interpreter, its own GIL, no shared lock to contend over. Predictions to
test against actual numbers:
  - Guardrail-only: SHOULD benefit from true parallelism this time, since
    there's no GIL contention across processes — but each process has much
    heavier startup cost than a thread (new interpreter, re-importing
    everything), so for a task this fast, startup overhead may still
    dominate. Not assumed — measured.
  - Full pipeline: expected to perform similarly to (not necessarily
    better than) threading, since the bottleneck there was never CPU
    contention — it was network wait time, which multiprocessing doesn't
    speed up any further than threading already did.

Uses the same retry-with-backoff Groq call wrapper as threading_benchmark.py
(imported from there rather than duplicated) so rate-limit handling stays
consistent across both benchmark scripts.

IMPORTANT (Windows): multiprocessing on Windows uses the "spawn" start
method, which re-imports this module in each child process. This is why
all worker functions are defined at module level (picklable) and the
whole benchmark is wrapped in `if __name__ == "__main__":` — required for
ProcessPoolExecutor to work correctly on Windows at all.

Usage:
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
from experiments.evaluation.threading_benchmark import (
    DEFAULT_MOCK_DELAY_SEC,
    aggregate_runs,
    analyse_alert_mocked,
    analyse_alert_with_retry,
)


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


def _pipeline_worker_mock(alert_and_delay):
    # ProcessPoolExecutor.map only passes one positional arg per call, so
    # the (alert, mock_delay) pair travels together through pickling.
    alert, mock_delay = alert_and_delay
    return analyse_alert_mocked(alert, mock_delay)


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
    # At num_processes==1 there is no ProcessPoolExecutor -- this is plain
    # serial execution in the same single process, architecturally
    # identical to threading_benchmark.py's num_threads==1 case. Warming
    # pytector here too (excluded from timing) keeps that baseline
    # comparable to threading's; at num_processes>1, a real
    # ProcessPoolExecutor spawns separate processes and each pays its own
    # cold-start, which is left unwarmed deliberately -- that per-process
    # cost is a genuine, disclosed part of what multiprocessing costs here.
    if num_processes == 1:
        from experiments.evaluation.threading_benchmark import _warmup_pytector
        _warmup_pytector()

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


def run_full_pipeline_mock(alerts, num_processes: int, mock_delay: float = DEFAULT_MOCK_DELAY_SEC):
    # At num_processes==1, warm up the same way run_full_pipeline (real)
    # and threading_benchmark.py's num_threads==1 case do -- no pool exists
    # yet, so this is plain serial execution in one process. At
    # num_processes>1, a real ProcessPoolExecutor spawns separate processes
    # with their own memory space, so a parent-process warmup wouldn't
    # reach them anyway; each worker pays its own ~10-15s pytector
    # cold-start on its first assigned task there -- a real, disclosed cost
    # specific to multiprocessing's per-process isolation, not a bug, and
    # consistent with this benchmark's existing "process-creation/setup
    # overhead dominates" finding.
    if num_processes == 1:
        from experiments.evaluation.threading_benchmark import _warmup_pytector
        _warmup_pytector()

    pairs = [(a, mock_delay) for a in alerts]
    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_processes == 1:
            results = [_pipeline_worker_mock(p) for p in pairs]
        else:
            with ProcessPoolExecutor(max_workers=num_processes) as pool:
                results = list(pool.map(_pipeline_worker_mock, pairs))
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
    parser.add_argument("--repeats", type=int, default=3,
                         help="How many times to repeat each process-count configuration, "
                              "reporting mean/stdev instead of a single-shot number")
    parser.add_argument("--single-run", action="store_true",
                         help="Run exactly one (mode, process-count) measurement and print its "
                              "JSON result to stdout, then exit. Used by "
                              "fresh_process_benchmark.py to get true fresh-process isolation "
                              "between repeats instead of looping in one long-running process.")
    parser.add_argument("--mode", choices=["guardrail", "pipeline", "pipeline-mock"],
                         help="Which measurement to run in --single-run mode")
    parser.add_argument("--workers", type=int, help="Process count for --single-run mode")
    parser.add_argument("--n", type=int, help="Alert count for --single-run mode")
    parser.add_argument("--mock-delay", type=float, default=DEFAULT_MOCK_DELAY_SEC,
                         help="Fixed delay (seconds) standing in for the real Groq call in "
                              "pipeline-mock mode")
    args = parser.parse_args()

    if args.single_run:
        alerts = build_workload(args.n)
        if args.mode == "guardrail":
            result = run_guardrail_only(alerts, args.workers)
        elif args.mode == "pipeline":
            result = run_full_pipeline(alerts, args.workers)
        else:
            result = run_full_pipeline_mock(alerts, args.workers, args.mock_delay)
        print(json.dumps(result))
        return

    results = {"guardrail_only": [], "full_pipeline": []}

    print(f"=== Guardrail-only benchmark: multiprocessing ({args.repeats} repeats per process-count) ===")
    guardrail_alerts = build_workload(args.guardrail_n)
    for p in args.processes:
        runs = [run_guardrail_only(guardrail_alerts, p) for _ in range(args.repeats)]
        r = aggregate_runs(runs)
        results["guardrail_only"].append(r)
        tp, cpu = r["throughput_per_sec"], r["avg_cpu_percent"]
        print(f"  processes={p:>2} | {tp['mean']:>12,.0f} ± {tp['stdev']:>8,.0f} alerts/sec | "
              f"avg_cpu={cpu['mean']:.1f}%")

    print(f"\n=== Full pipeline benchmark: multiprocessing ({args.repeats} repeats per process-count) ===")
    print(f"  (using n={args.pipeline_n} per run — this makes real API calls, keep n modest)")
    pipeline_alerts = build_workload(args.pipeline_n)
    first_call = True
    for p in args.processes:
        runs = []
        for _ in range(args.repeats):
            if not first_call:
                print(f"  [cooling down {args.cooldown:.0f}s to let Groq TPM budget recover]")
                time.sleep(args.cooldown)
            first_call = False
            runs.append(run_full_pipeline(pipeline_alerts, p))
        r = aggregate_runs(runs)
        results["full_pipeline"].append(r)
        tp, cpu = r["throughput_per_sec"], r["avg_cpu_percent"]
        rl_note = f" | rate_limited={r['rate_limited_count']}" if r.get("rate_limited_count") else ""
        print(f"  processes={p:>2} | {tp['mean']:>8.2f} ± {tp['stdev']:>6.2f} alerts/sec | "
              f"avg_cpu={cpu['mean']:.1f}%{rl_note}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/multiprocessing_benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    main()