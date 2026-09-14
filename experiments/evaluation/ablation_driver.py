"""
experiments/evaluation/ablation_driver.py

Phase 3 driver for issue #42 (R3)'s component ablation study: 6 toggle
configs x the 436-alert frozen pool (experiments/evaluation/ablation_pool.py
-- see that module's docstring for why 436, not the issue's literal 479).

Behaviour (per issue #42's Task 2 spec):
  - Loads the frozen alert pool from experiments/results/ablation_pool_436.json
    (never rebuilds it from source -- see ablation_pool.py's docstring on
    why the pool must be frozen once, not regenerated per run).
  - Loops (config x alert) in deterministic order: configs C0..C5, alerts
    in pool order.
  - Resume mode: experiments/results/ablation_full.jsonl is append-only.
    Skips any (config_id, pool_id) pair already present. Every row is
    flushed + fsynced immediately, so a crash mid-run loses at most the
    row in flight, not the whole file (this project's Groq runs have
    crashed mid-run on 429s before -- see docs/all_results.md).
  - Retries with exponential backoff on RateLimitError (429) and
    InternalServerError/APIConnectionError/APITimeoutError (5xx/transient),
    same shape as ablation_study.py's _analyse_with_retry.

Quota-saving reuse: 507 of the 2,616 (config, alert) pairs (all of C0/C1/C2
plus 57/150 of C3, restricted to the cve_bait source alerts) were already
run for real against Groq under experiments/evaluation/ablation_study.py's
identically-scoped configs (its "all-on"/"input-off"/"cve-off"/"attack-off"
map 1:1 onto this issue's C0/C1/C2/C3 -- same toggle values, same alert_ids,
since ablation_study.py's cve-bait dataset IS this pool's cve_bait source).
--seed-legacy imports those rows once (real Groq output, not fabricated;
its cve_verifications/attack_technique_verifications already carry the
per-identifier taxonomy classification F3 needs, and its requires_review/
latency_sec fields are exactly what Table T6 and F4 need) rather than
re-spending scarce quota to regenerate identical results. Seeded rows are
marked "reused_from" for transparency and only ever carry the reduced
field set that run saved (no evidence_pack/reasoning/model, since those
weren't saved by that script) -- sufficient for T6/F3/F4, not for
verbatim-quote case studies.

Usage:
    python -m experiments.evaluation.ablation_driver --seed-legacy   # once
    python -m experiments.evaluation.ablation_driver --limit 100     # do up to 100 new live calls, then stop
    python -m experiments.evaluation.ablation_driver --validate      # check completeness, no calls
"""

import argparse
import dataclasses
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from groq import RateLimitError, InternalServerError, APIConnectionError, APITimeoutError

from src.agent.alert_schema import SecurityAlert
from src.agent.soc_agent import analyse_alert
from src.guardrails.input_guardrail import check_injection_hybrid

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
POOL_PATH = os.path.join(RESULTS_DIR, "ablation_pool_436.json")
OUTPUT_PATH = os.path.join(RESULTS_DIR, "ablation_full.jsonl")
LEGACY_CVE_BAIT_PATH = os.path.join(RESULTS_DIR, "ablation_study_cve_bait.json")

# issue #42's C0-C5 naming -> analyse_alert() toggle kwargs. Values are
# identical to ablation_study.py's all-on/input-off/cve-off/attack-off/
# pii-off/all-off, named per the issue's own table instead.
CONFIGS = {
    "C0": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "C1": dict(input_guardrail_enabled=False, cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "C2": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=False, attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "C3": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=False, pii_guardrail_enabled=True),
    "C4": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=False),
    "C5": dict(input_guardrail_enabled=False, cve_guardrail_enabled=False, attack_guardrail_enabled=False, pii_guardrail_enabled=False),
}

# ablation_study.py config name -> issue C-name, for --seed-legacy.
LEGACY_CONFIG_MAP = {
    "all-on": "C0",
    "input-off": "C1",
    "cve-off": "C2",
    "attack-off": "C3",
    # pii-off/all-off never reached completion in the legacy run (0/150 each) -- nothing to seed.
}

RETRYABLE = (RateLimitError, InternalServerError, APIConnectionError, APITimeoutError)

_warmed_up = False


def _warmup_once():
    """Same rationale as ablation_study.py: Pytector's DeBERTa lazy-load
    is a several-second one-time cost that must not land inside whichever
    config happens to run first's latency numbers."""
    global _warmed_up
    if not _warmed_up:
        check_injection_hybrid("warmup")
        _warmed_up = True


def load_pool() -> list:
    if not os.path.exists(POOL_PATH):
        raise SystemExit(
            f"{POOL_PATH} not found -- run `python -m experiments.evaluation.ablation_pool` first."
        )
    with open(POOL_PATH, encoding="utf-8") as f:
        return json.load(f)["pool"]


def load_done_pairs() -> set:
    done = set()
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                done.add((row["config_id"], row["alert_id"]))
    return done


def _append_row(row: dict):
    with open(OUTPUT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())


def seed_legacy():
    """One-time import of already-real Groq results from ablation_study.py's
    cve-bait run, for the (config, alert) pairs it already completed."""
    if not os.path.exists(LEGACY_CVE_BAIT_PATH):
        print(f"No legacy file at {LEGACY_CVE_BAIT_PATH}, nothing to seed.")
        return

    done = load_done_pairs()
    with open(LEGACY_CVE_BAIT_PATH, encoding="utf-8") as f:
        legacy = json.load(f)

    seeded = 0
    for legacy_config, rows in legacy.get("by_config", {}).items():
        config_id = LEGACY_CONFIG_MAP.get(legacy_config)
        if config_id is None:
            continue
        for r in rows:
            pool_id = r["alert_id"]
            if (config_id, pool_id) in done:
                continue
            row = {
                "config_id": config_id,
                "alert_id": pool_id,
                "source": "cve_bait",
                "runtime_ms": round(r["latency_sec"] * 1000, 1),
                "reused_from": "ablation_study_cve_bait.json",
                "output_report": {
                    "guardrail_blocked": r.get("guardrail_blocked"),
                    "severity_assessment": r.get("severity_assessment"),
                    "hallucinated_cves": r.get("hallucinated_cves"),
                    "cve_verifications": r.get("cve_verifications"),
                    "hallucinated_attack_techniques": r.get("hallucinated_attack_techniques"),
                    "attack_technique_verifications": r.get("attack_technique_verifications"),
                    "pii_detections": r.get("pii_detections"),
                    "output_guardrail_flagged": r.get("output_guardrail_flagged"),
                    "requires_review": r.get("requires_review"),
                },
            }
            _append_row(row)
            done.add((config_id, pool_id))
            seeded += 1

    print(f"Seeded {seeded} rows from {LEGACY_CVE_BAIT_PATH}.")


def _analyse_with_retry(alert: SecurityAlert, max_retries: int = 5, base_delay: float = 8.0, **cfg):
    total_wait = 0.0
    for attempt in range(max_retries):
        try:
            return analyse_alert(alert, use_nvd_snapshot=True, **cfg), total_wait
        except RETRYABLE as e:
            if attempt == max_retries - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(f"    {type(e).__name__}, waiting {wait:.0f}s...", flush=True)
            time.sleep(wait)
            total_wait += wait


def run(limit=None):
    _warmup_once()
    pool = load_pool()
    done = load_done_pairs()
    total_target = len(pool) * len(CONFIGS)

    if done:
        print(f"Resuming: {len(done)}/{total_target} (config, alert) pairs already done\n")

    calls_this_invocation = 0
    for config_id, cfg in CONFIGS.items():
        for entry in pool:
            pool_id = entry["pool_id"]
            if (config_id, pool_id) in done:
                continue
            if limit is not None and calls_this_invocation >= limit:
                print(f"\nHit --limit {limit} new calls this invocation, stopping.")
                _print_progress(len(done), total_target)
                return

            alert = SecurityAlert(**entry["alert"])
            idx = len(done) + 1
            print(f"[{config_id} / {entry['source']}] ({idx}/{total_target}) {pool_id}...", flush=True)

            start = time.perf_counter()
            report, wait_sec = _analyse_with_retry(alert, **cfg)
            runtime_ms = ((time.perf_counter() - start) - wait_sec) * 1000

            row = {
                "config_id": config_id,
                "alert_id": pool_id,
                "source": entry["source"],
                "runtime_ms": round(runtime_ms, 1),
                "output_report": report,
            }
            _append_row(row)
            done.add((config_id, pool_id))
            calls_this_invocation += 1

    print(f"\nAll {total_target} (config, alert) pairs complete.")
    _print_progress(len(done), total_target)


def _print_progress(done_n, total_target):
    print(f"Progress: {done_n}/{total_target} ({done_n/total_target:.1%})")


def validate():
    pool = load_pool()
    pool_ids = [e["pool_id"] for e in pool]
    done = load_done_pairs()
    total_target = len(pool) * len(CONFIGS)

    missing = []
    for config_id in CONFIGS:
        for pool_id in pool_ids:
            if (config_id, pool_id) not in done:
                missing.append((config_id, pool_id))

    if not missing:
        print(f"{len(done)} rows, all {len(CONFIGS)} configs present for each of {len(pool)} alerts.")
    else:
        by_config = {}
        for config_id, pool_id in missing:
            by_config[config_id] = by_config.get(config_id, 0) + 1
        print(f"{len(done)}/{total_target} rows present. Missing {len(missing)}:")
        for config_id, n in by_config.items():
            print(f"  {config_id}: {n} missing")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-legacy", action="store_true", help="Import already-completed cve_bait rows from ablation_study.py's run.")
    parser.add_argument("--limit", type=int, default=None, help="Max new live Groq calls this invocation.")
    parser.add_argument("--validate", action="store_true", help="Check completeness, no calls.")
    args = parser.parse_args()

    if args.validate:
        validate()
    elif args.seed_legacy:
        seed_legacy()
    else:
        run(limit=args.limit)
