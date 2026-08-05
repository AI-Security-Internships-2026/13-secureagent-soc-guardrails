"""
experiments/evaluation/diagnose_thread_slowdown.py

Follow-up to the repeated-runs concurrency benchmark (threading_benchmark.py),
which found the full pipeline at 4 threads is reproducibly ~7-8x slower than
at 2 threads, with rate_limited_count=0 and *lower* avg CPU than at 2 threads
-- the threads are blocked on something, not competing for CPU or getting
explicit 429s.

This script doesn't measure throughput, it measures *where the time goes*
per request: for each alert, record the offset (relative to batch start) at
which its Groq call begins and ends. That distinguishes two different
explanations for the slowdown:

  - Queuing: requests start staggered (worker N+1 doesn't start until a
    worker frees up), but each individual call is still fast. Expected and
    boring -- ThreadPoolExecutor(max_workers=4) legitimately can't run more
    than 4 calls at once, but with only 6 tasks that shouldn't cost 8s.
  - Per-request stalling: requests start close together (near offset 0), but
    each one individually takes far longer than it would running alone --
    pointing at server-side throttling/queuing under concurrency, or a
    connection-pool bottleneck in the client, not scheduling.

Run:
    python -m experiments.evaluation.diagnose_thread_slowdown
"""

import argparse
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from experiments.evaluation.threading_benchmark import analyse_alert_with_retry, build_workload


def instrumented_worker(alert, batch_start: float) -> dict:
    thread_name = threading.current_thread().name
    start_offset = time.perf_counter() - batch_start
    result = analyse_alert_with_retry(alert)
    end_offset = time.perf_counter() - batch_start
    return {
        "alert_id": alert.alert_id,
        "thread": thread_name,
        "start_offset_sec": round(start_offset, 3),
        "end_offset_sec": round(end_offset, 3),
        "duration_sec": round(end_offset - start_offset, 3),
        "rate_limited": bool(result.get("rate_limited")),
    }


def run(num_threads: int, n: int) -> tuple:
    alerts = build_workload(n)
    batch_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures = [pool.submit(instrumented_worker, a, batch_start) for a in alerts]
        records = [f.result() for f in futures]
    total_elapsed = time.perf_counter() - batch_start
    return records, total_elapsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=6)
    parser.add_argument("--threads", type=int, nargs="+", default=[2, 4])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--cooldown", type=float, default=20.0,
                         help="Seconds between runs to let the Groq TPM budget recover")
    args = parser.parse_args()

    all_results = {}
    first = True
    for t in args.threads:
        all_results[f"threads_{t}"] = []
        for rep in range(args.repeats):
            if not first:
                print(f"\n[cooling down {args.cooldown:.0f}s]")
                time.sleep(args.cooldown)
            first = False

            print(f"\n=== threads={t} repeat={rep + 1}/{args.repeats} ===")
            records, total_elapsed = run(t, args.n)
            for r in sorted(records, key=lambda r: r["start_offset_sec"]):
                print(f"  [{r['thread']}] {r['alert_id']}: "
                      f"start={r['start_offset_sec']:>6.2f}s  end={r['end_offset_sec']:>6.2f}s  "
                      f"duration={r['duration_sec']:>6.2f}s  rate_limited={r['rate_limited']}")
            print(f"  total wall time: {total_elapsed:.2f}s")
            all_results[f"threads_{t}"].append({"records": records, "total_elapsed_sec": total_elapsed})

    os.makedirs("experiments/results", exist_ok=True)
    out_path = "experiments/results/thread_slowdown_diagnosis.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nsaved to {out_path}")


if __name__ == "__main__":
    main()
