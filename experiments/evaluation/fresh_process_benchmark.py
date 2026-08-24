"""
experiments/evaluation/fresh_process_benchmark.py

Redo of the threading-vs-multiprocessing concurrency benchmark
(docs/ROADMAP_PLAN.md sec.5, "Redo threading vs. multiprocessing
benchmark") addressing the two gaps flagged as not yet resolved:

  1. Repeats previously looped inside one long-running process, so OS
     scheduler state, memory allocator warm-up, etc. could carry over
     between repeats. This script spawns each repeat as a genuinely
     independent `python -m ...` subprocess via threading_benchmark.py's
     and multiprocessing_benchmark.py's `--single-run` mode, added
     alongside this script specifically for that purpose.

  2. No mocked-latency variant existed to separate our own guardrail/
     scheduling overhead from live Groq network variance. `--single-run
     --mode pipeline-mock` (also new) replaces the real Groq call with a
     fixed-delay stand-in, letting this run at a much larger n than the
     real-API variant (no cost, no rate limits) while still exercising
     the real input guardrail, CVE/ATT&CK grounding, and PII redaction
     code paths.

Fresh-process isolation surfaced a real bug in the process: a race in
src/guardrails/input_guardrail.py's lazy pytector-singleton
initialization, invisible in the original benchmark because thread-count=1
always ran first in the same process and accidentally warmed the
singleton safely. Fixed there (docs/all_results.md, this entry) before
this script was trusted to produce numbers.

Usage:
    python -m experiments.evaluation.fresh_process_benchmark
    python -m experiments.evaluation.fresh_process_benchmark --repeats 5 --skip-real
"""

import argparse
import json
import os
import subprocess
import sys
import time

from experiments.evaluation.threading_benchmark import DEFAULT_MOCK_DELAY_SEC, aggregate_runs

OUTPUT_PATH = "experiments/results/fresh_process_benchmark_results.json"


def run_single(module: str, mode: str, workers: int, n: int, mock_delay: float = None) -> dict:
    cmd = [sys.executable, "-m", module, "--single-run", "--mode", mode,
           "--workers", str(workers), "--n", str(n)]
    if mock_delay is not None:
        cmd += ["--mock-delay", str(mock_delay)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{module} --single-run --mode {mode} --workers {workers} --n {n} "
            f"failed (exit {proc.returncode}):\n{proc.stderr[-4000:]}"
        )
    line = proc.stdout.strip().splitlines()[-1]
    return json.loads(line)


def bench_config(module: str, mode: str, worker_counts: list, n: int, repeats: int,
                  mock_delay: float = None, cooldown: float = 0.0) -> list:
    rows = []
    first = True
    for w in worker_counts:
        runs = []
        for i in range(repeats):
            if not first and cooldown > 0:
                print(f"    [cooling down {cooldown:.0f}s]")
                time.sleep(cooldown)
            first = False
            print(f"  {module.split('.')[-1]} | mode={mode} | workers={w} | repeat {i+1}/{repeats}")
            runs.append(run_single(module, mode, w, n, mock_delay))
        rows.append(aggregate_runs(runs))
    return rows


def print_summary(label: str, rows: list):
    print(f"\n{label}")
    for r in rows:
        key = "num_threads" if "num_threads" in r else "num_processes"
        tp, cpu = r["throughput_per_sec"], r["avg_cpu_percent"]
        print(f"  {key}={r[key]:>2} | {tp['mean']:>10.3f} ± {tp['stdev']:>8.3f} alerts/sec | "
              f"avg_cpu={cpu['mean']:.1f}% | repeats={r['repeats']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4],
                         help="Thread/process counts to test")
    parser.add_argument("--repeats", type=int, default=5,
                         help="Fresh-process repeats per configuration")
    parser.add_argument("--guardrail-n", type=int, default=2000,
                         help="Alert count for the guardrail-only benchmark")
    parser.add_argument("--mock-n", type=int, default=60,
                         help="Alert count for the mocked-LLM full-pipeline benchmark "
                              "(no API cost, so this can be much larger than the real-API n)")
    parser.add_argument("--mock-delay", type=float, default=DEFAULT_MOCK_DELAY_SEC,
                         help="Fixed delay standing in for the real Groq call")
    parser.add_argument("--real-n", type=int, default=6,
                         help="Alert count for the real-API full-pipeline benchmark (costs "
                              "real Groq calls -- kept modest deliberately)")
    parser.add_argument("--cooldown", type=float, default=15.0,
                         help="Seconds between real-API repeats, to let Groq TPM budget recover")
    parser.add_argument("--skip-real", action="store_true",
                         help="Skip the real-API full-pipeline benchmark entirely (guardrail-only "
                              "and mocked-pipeline results still require no API calls)")
    args = parser.parse_args()

    results = {}

    for module in ["experiments.evaluation.threading_benchmark",
                    "experiments.evaluation.multiprocessing_benchmark"]:
        short = module.split(".")[-1]
        print(f"\n=== {short}: guardrail-only ({args.repeats} fresh-process repeats) ===")
        results[f"{short}_guardrail_only"] = bench_config(
            module, "guardrail", args.workers, args.guardrail_n, args.repeats
        )
        print_summary(f"{short} guardrail-only", results[f"{short}_guardrail_only"])

        print(f"\n=== {short}: full pipeline, mocked LLM ({args.repeats} fresh-process repeats, "
              f"n={args.mock_n}, delay={args.mock_delay}s) ===")
        results[f"{short}_pipeline_mock"] = bench_config(
            module, "pipeline-mock", args.workers, args.mock_n, args.repeats, args.mock_delay
        )
        print_summary(f"{short} full pipeline (mocked)", results[f"{short}_pipeline_mock"])

        if not args.skip_real:
            print(f"\n=== {short}: full pipeline, real Groq ({args.repeats} fresh-process "
                  f"repeats, n={args.real_n}) ===")
            results[f"{short}_pipeline_real"] = bench_config(
                module, "pipeline", args.workers, args.real_n, args.repeats,
                cooldown=args.cooldown,
            )
            print_summary(f"{short} full pipeline (real Groq)", results[f"{short}_pipeline_real"])

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
