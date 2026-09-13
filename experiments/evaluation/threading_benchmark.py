
import argparse
import itertools
import json
import os
import statistics
import threading
import time
from unittest.mock import patch

import psutil
from groq import RateLimitError

import src.agent.soc_agent as soc_agent_module
from src.agent.alert_schema import SAMPLE_ALERTS
from src.agent.soc_agent import analyse_alert, format_alert
from src.guardrails.input_guardrail import check_injection

# Approximate per-call mean observed in the real n=6 threading benchmark
# (Sect. 4.7, Table 6, 1-thread run: 1.90s / 6 calls) -- used as the default
# mocked-LLM delay so the mocked variant's absolute numbers stay in the same
# ballpark as the real one, while letting the benchmark isolate guardrail/
# scheduling overhead from live Groq network variance (docs/ROADMAP_PLAN.md
# sec.5, "Redo threading vs. multiprocessing benchmark").
DEFAULT_MOCK_DELAY_SEC = 0.3

_MOCK_REPORT_CONTENT = json.dumps({
    "severity_assessment": "MEDIUM",
    "threat_summary": "Synthetic report generated for concurrency-benchmark timing isolation (mocked LLM call).",
    "threat_type": "BENIGN_TEST",
    "recommended_action": "No action needed -- this is a mocked benchmark response.",
    "confidence_score": 0.5,
    "reasoning": "LLM call replaced with a fixed-delay mock so this benchmark measures guardrail/scheduling overhead independent of live Groq network variance.",
})


class _MockLLMResponse:
    def __init__(self, content):
        self.content = content


class _MockLLM:
    """Stands in for the real ChatGroq client -- soc_agent.llm is a pydantic
    model, whose __setattr__ rejects patching an undeclared 'invoke'
    attribute directly, so the module-level `llm` name itself is swapped
    for this instead (see analyse_alert_mocked)."""

    def __init__(self, mock_delay: float):
        self.mock_delay = mock_delay

    def invoke(self, messages):
        time.sleep(self.mock_delay)
        return _MockLLMResponse(_MOCK_REPORT_CONTENT)


def analyse_alert_mocked(alert, mock_delay: float = DEFAULT_MOCK_DELAY_SEC):
    """
    Runs the real pipeline (input guardrail, CVE/ATT&CK grounding, PII
    redaction) but replaces only the actual Groq network call with a
    fixed-delay sleep. The mocked report cites no CVE/ATT&CK identifiers,
    so grounding checks find nothing to verify and no NVD network call
    happens either -- this is a genuinely local, deterministic-latency run
    apart from the deliberate sleep. Patches the module-level `llm` name
    (not the pydantic instance's attributes, which pydantic won't allow),
    so this works correctly inside a ProcessPoolExecutor worker under
    Windows' spawn start method, where each worker re-imports this module
    fresh.
    """
    with patch.object(soc_agent_module, "llm", _MockLLM(mock_delay)):
        return soc_agent_module.analyse_alert(alert)


def analyse_alert_with_retry(alert, max_retries: int = 4, base_delay: float = 5.0):
    """
    Wraps analyse_alert with exponential backoff on Groq rate limits, so one
    429 doesn't crash the whole multi-threaded benchmark run. Free-tier Groq
    per-model token/minute caps are low enough that concurrent threads can
    easily burst past them even when the total workload is modest (measured
    against llama-3.1-8b-instant's 6000 tokens/minute cap; re-verify against
    openai/gpt-oss-20b's limit, since it was not re-measured after the
    Aug 2026 migration, see docs/all_results.md #22).
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


def _warmup_pytector():
    """
    Loads the lazy-singleton DeBERTa/pytector model once, synchronously,
    before the timed section starts. In a fresh process, the model has
    never been loaded, so the first call to check_injection_hybrid pays a
    ~10-15s cold-start cost that would otherwise swamp the actual
    guardrail/scheduling signal this benchmark measures -- the original
    (non-fresh-process) benchmark accidentally avoided this by always
    testing thread-count=1 first in the same long-running process, warming
    the singleton before any concurrent access. Same warmup convention
    already used in guardrail_comparison/run_comparison.py.
    """
    from src.guardrails.input_guardrail import check_injection_hybrid
    check_injection_hybrid("warmup")


def run_full_pipeline(alerts, num_threads: int):
    _warmup_pytector()

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


def run_full_pipeline_mock(alerts, num_threads: int, mock_delay: float = DEFAULT_MOCK_DELAY_SEC):
    _warmup_pytector()

    def worker(alert):
        return analyse_alert_mocked(alert, mock_delay)

    with CpuMonitor() as monitor:
        start = time.perf_counter()
        if num_threads == 1:
            results = [worker(a) for a in alerts]
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=num_threads) as pool:
                results = list(pool.map(worker, alerts))
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
    parser.add_argument("--single-run", action="store_true",
                         help="Run exactly one (mode, thread-count) measurement and print its "
                              "JSON result to stdout, then exit. Used by "
                              "fresh_process_benchmark.py to get true fresh-process isolation "
                              "between repeats instead of looping in one long-running process.")
    parser.add_argument("--mode", choices=["guardrail", "pipeline", "pipeline-mock"],
                         help="Which measurement to run in --single-run mode")
    parser.add_argument("--workers", type=int, help="Thread count for --single-run mode")
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