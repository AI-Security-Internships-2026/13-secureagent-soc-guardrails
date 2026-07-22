
import argparse
import itertools
import json
import os
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
    args = parser.parse_args()

    results = {"guardrail_only": [], "full_pipeline": []}

    print("Guardrail-only benchmark")
    guardrail_alerts = build_workload(args.guardrail_n)
    for t in args.threads:
        r = run_guardrail_only(guardrail_alerts, t)
        results["guardrail_only"].append(r)
        print(f"  threads={t:>2} | {r['throughput_per_sec']:>12,.0f} alerts/sec | "
              f"avg_cpu={r['avg_cpu_percent']:.1f}% | max_cpu={r['max_cpu_percent']:.1f}%")

    print("\nFull pipeline benchmark")
    print(f"  (using n={args.pipeline_n} per thread-count — this makes real API calls, keep n modest)")
    pipeline_alerts = build_workload(args.pipeline_n)
    for i, t in enumerate(args.threads):
        if i > 0:
            print(f"  [cooling down {args.cooldown:.0f}s to let Groq TPM budget recover]")
            time.sleep(args.cooldown)
        r = run_full_pipeline(pipeline_alerts, t)
        results["full_pipeline"].append(r)
        rl_note = f" | rate_limited={r['rate_limited_count']}" if r["rate_limited_count"] else ""
        print(f"  threads={t:>2} | {r['throughput_per_sec']:>8.2f} alerts/sec | "
              f"avg_cpu={r['avg_cpu_percent']:.1f}% | max_cpu={r['max_cpu_percent']:.1f}%{rl_note}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/threading_benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    main()