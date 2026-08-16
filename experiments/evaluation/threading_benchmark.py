
import argparse
import itertools
import json
import os
import statistics
import threading
import time

import psutil
from groq import RateLimitError

from src.agent.alert_schema import SAMPLE_ALERTS
from src.agent.soc_agent import analyse_alert, format_alert
from src.guardrails.input_guardrail import check_injection


def analyse_alert_with_retry(alert, max_retries: int = 4, base_delay: float = 5.0):
    """
    Wraps analyse_alert with exponential backoff on Groq rate limits, so one
    429 doesn't crash the whole multi-threaded benchmark run. Free-tier Groq
    caps llama-3.1-8b-instant at 6000 tokens/minute — concurrent threads can
    easily burst past that even when the total workload is modest.
    """
    for attempt in range(max_retries):
        try:
            return analyse_alert(alert)
        except RateLimitError:
            if attempt == max_retries - 1:
                return {
                    "alert_id": alert.alert_id,
                    "severity_assessment": "ERROR",
                    "threat_summary": "Rate limited after retries",
                    "threat_type": "ERROR",
                    "recommended_action": "N/A",
                    "confidence_score": 0.0,
                    "reasoning": "groq.RateLimitError persisted after retries",
                    "guardrail_blocked": False,
                    "rate_limited": True,
                }
            wait = base_delay * (2 ** attempt)
            print(f"    [rate limited on {alert.alert_id}, retrying in {wait:.0f}s]")
            time.sleep(wait)


class CpuMonitor:
    """Samples system-wide CPU% in a background thread while a benchmark runs."""

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
    cycled = itertools.islice(itertools.cycle(SAMPLE_ALERTS), n)
    return list(cycled)


# Measurements that vary run-to-run and are worth summarizing across repeats.
# num_threads/n/rate_limited_count are config/outcome fields, not per-run
# noise, so they're kept as-is rather than averaged.
_NUMERIC_FIELDS = ["elapsed_sec", "throughput_per_sec", "avg_cpu_percent", "max_cpu_percent"]


def aggregate_runs(runs: list) -> dict:
    """
    Collapse N repeated runs of the same configuration into summary
    statistics (mean/median/stdev/min/max) per measurement, plus the raw
    per-run results for full reproducibility.

    A single-shot benchmark run is vulnerable to one slow or fast run (OS
    scheduling noise, a slow Groq response) skewing the whole result with no
    way to tell signal from noise afterward. Repeating and reporting spread
    (stdev, min/max) makes that visible instead of hidden behind one point
    estimate.
    """
    agg = {k: v for k, v in runs[0].items() if k not in _NUMERIC_FIELDS and k != "rate_limited_count"}
    agg["repeats"] = len(runs)
    for field in _NUMERIC_FIELDS:
        values = [r[field] for r in runs]
        agg[field] = {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }
    if "rate_limited_count" in runs[0]:
        agg["rate_limited_count"] = sum(r["rate_limited_count"] for r in runs)
    agg["raw_runs"] = runs
    return agg


def run_guardrail_only(alerts, num_threads: int):
    texts = [format_alert(a) for a in alerts]

    def worker(text):
        return check_injection(text)

    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_threads == 1:
            results = [worker(t) for t in texts]
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=num_threads) as pool:
                results = list(pool.map(worker, texts))
        elapsed = time.perf_counter() - start

    throughput = len(alerts) / elapsed if elapsed > 0 else float("inf")
    return {
        "num_threads": num_threads,
        "n": len(alerts),
        "elapsed_sec": elapsed,
        "throughput_per_sec": throughput,
        "avg_cpu_percent": monitor.avg_cpu,
        "max_cpu_percent": monitor.max_cpu,
    }


def run_full_pipeline(alerts, num_threads: int):
    def worker(alert):
        return analyse_alert_with_retry(alert)

    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_threads == 1:
            results = [worker(a) for a in alerts]
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=num_threads) as pool:
                results = list(pool.map(worker, alerts))
        elapsed = time.perf_counter() - start

    rate_limited = sum(1 for r in results if r.get("rate_limited"))
    throughput = len(alerts) / elapsed if elapsed > 0 else float("inf")
    return {
        "num_threads": num_threads,
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
                         help="Number of alerts for the guardrail-only benchmark (cheap, CPU-bound)")
    parser.add_argument("--pipeline-n", type=int, default=6,
                         help="Number of alerts for the full-pipeline benchmark (costs real Groq API calls)")
    parser.add_argument("--cooldown", type=float, default=15.0,
                         help="Seconds to wait between thread-count runs in the pipeline benchmark, to let the Groq TPM budget recover")
    parser.add_argument("--threads", type=int, nargs="+", default=[1, 2, 4],
                         help="Thread counts to test")
    parser.add_argument("--repeats", type=int, default=3,
                         help="How many times to repeat each thread-count configuration, "
                              "reporting mean/stdev instead of a single-shot number")
    args = parser.parse_args()

    results = {"guardrail_only": [], "full_pipeline": []}

    print(f"Guardrail-only benchmark ({args.repeats} repeats per thread-count)")
    guardrail_alerts = build_workload(args.guardrail_n)
    for t in args.threads:
        runs = [run_guardrail_only(guardrail_alerts, t) for _ in range(args.repeats)]
        r = aggregate_runs(runs)
        results["guardrail_only"].append(r)
        tp, cpu = r["throughput_per_sec"], r["avg_cpu_percent"]
        print(f"  threads={t:>2} | {tp['mean']:>12,.0f} ± {tp['stdev']:>8,.0f} alerts/sec | "
              f"avg_cpu={cpu['mean']:.1f}%")

    print(f"\nFull pipeline benchmark ({args.repeats} repeats per thread-count)")
    print(f"  (using n={args.pipeline_n} per run — this makes real API calls, keep n modest)")
    pipeline_alerts = build_workload(args.pipeline_n)
    first_call = True
    for t in args.threads:
        runs = []
        for _ in range(args.repeats):
            if not first_call:
                print(f"  [cooling down {args.cooldown:.0f}s to let Groq TPM budget recover]")
                time.sleep(args.cooldown)
            first_call = False
            runs.append(run_full_pipeline(pipeline_alerts, t))
        r = aggregate_runs(runs)
        results["full_pipeline"].append(r)
        tp, cpu = r["throughput_per_sec"], r["avg_cpu_percent"]
        rl_note = f" | rate_limited={r['rate_limited_count']}" if r.get("rate_limited_count") else ""
        print(f"  threads={t:>2} | {tp['mean']:>8.2f} ± {tp['stdev']:>6.2f} alerts/sec | "
              f"avg_cpu={cpu['mean']:.1f}%{rl_note}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/threading_benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    main()