"""
experiments/evaluation/ablation_study.py

Phase 3 of the component ablation study (docs/ROADMAP_PLAN.md sec.12).
Runs each of 3 datasets -- CVE-bait (150), ATT&CK-bait (150), and
PII-bait (60, = 40 PII_ALERTS + 20 CLEAN_ALERTS, the same n=60 set
pii_bait_test.py uses) -- through analyse_alert() under 6 toggle
configurations each: all-on, input-off, cve-off, attack-off, pii-off,
all-off.

Scope note (corrected from the roadmap's original draft, see
docs/all_results.md write-up for this run): the roadmap's Phase 3 draft
assumed a 4th dataset, the input-guardrail comparison's 119-sample
eval_dataset.json. That set is `{id, label, text}` -- not a SecurityAlert,
no CVE/ATT&CK/PII ground truth attached -- built specifically to compare
guardrail *implementations* head-to-head (already covered rigorously in
Sect. 4.10.1's Table 5/6). It doesn't fit this ablation's actual
questions (per-component latency; redundant coverage between components
on the SAME alert), so it's excluded here rather than force-adapted.
Corrected total: 3 datasets x 6 configs x (150+150+60) alerts = 2,160
live Groq calls, not the original ~2,874.

Per (alert, config) result recorded: the full analyse_alert() report,
plus wall-clock latency for that call and the alert's ground truth
(expected_cve / expected_technique / expected_entities, whichever
applies), so post-hoc analysis can answer both open questions from the
roadmap's "Why" section directly:
  - per-component latency cost: mean/stdev latency by config, same
    dataset held constant
  - redundant coverage: for each alert, compare requires_review across
    configs -- does turning one component off ever leave requires_review
    unchanged (because a still-enabled component independently caught the
    same alert), or does it always flip to False when that was the only
    thing catching it

Retry-on-rate-limit: every analyse_alert() call is wrapped with the same
exponential-backoff retry llm_judge_synthetic_test.py already established
for this exact model's free-tier TPM limit (RateLimitError -> wait
8s*2^attempt, up to 5 attempts) -- added after the first real run crashed
outright on the very first 429 it hit (Groq's 8000 TPM cap on
openai/gpt-oss-20b, tripped at call ~164; see docs/all_results.md for
this run's write-up). Without this, a TPM limit -- which is a
transient, retryable, seconds-scale condition, not the same thing as the
harder daily-quota wall this project's other scripts checkpoint-and-
manually-resume around -- kills the whole process outright.

Checkpointed after every (config, alert) pair -- same resume-from-
checkpoint pattern as cve_bait_test.py/attack_bait_test.py/
pii_bait_test.py (docs/all_results.md #26/#29), scaled to this script's
two-level (config x alert) structure: on resume, any config already
fully complete is skipped entirely; a partially-complete config resumes
from its last completed alert.

Usage:
    python -m experiments.evaluation.ablation_study --dataset cve
    python -m experiments.evaluation.ablation_study --dataset attack
    python -m experiments.evaluation.ablation_study --dataset pii
    python -m experiments.evaluation.ablation_study --dataset all   (runs all 3 in sequence)
"""

import argparse
import json
import os
import time

from groq import RateLimitError

from src.agent.soc_agent import analyse_alert
from src.guardrails.input_guardrail import check_injection_hybrid

CONFIGS = {
    "all-on":     dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "input-off":  dict(input_guardrail_enabled=False, cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "cve-off":    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=False, attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "attack-off": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=False, pii_guardrail_enabled=True),
    "pii-off":    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=False),
    "all-off":    dict(input_guardrail_enabled=False, cve_guardrail_enabled=False, attack_guardrail_enabled=False, pii_guardrail_enabled=False),
}

RESULTS_DIR = "experiments/results"

_warmed_up = False


def _warmup_once():
    """Pytector (used by check_injection_hybrid) lazy-loads its DeBERTa
    model on first call, a one-time cost of several seconds (same known
    issue documented in guardrail_comparison/adapters.py's WARMUPS dict --
    confirmed there as a 6.4s first-call outlier). Without this, whichever
    config happens to run first in a given process would unfairly absorb
    that cold-start cost in its latency numbers -- caught in this script's
    own dry run (BAIT-001 under 'all-on', which ran first, measured
    13.5s vs. 0.87s for the identical alert under a later config). Called
    once per process, before any timed alert, so every config's latency
    numbers are comparable."""
    global _warmed_up
    if not _warmed_up:
        check_injection_hybrid("warmup")
        _warmed_up = True


def _analyse_with_retry(alert, max_retries: int = 5, base_delay: float = 8.0, **cfg):
    """Same exponential-backoff shape as llm_judge_synthetic_test.py's
    _judge_with_retry -- see this module's docstring for why.

    Returns (report, retry_wait_sec, retries) rather than just the
    report: this study measures per-call latency as one of its two
    central questions, so backoff sleep time (seconds, not the
    sub-second real work being measured) must be tracked separately and
    excluded by the caller, not silently baked into latency_sec -- the
    same class of measurement contamination as the Pytector cold-start
    issue this script's dry run already caught once. retries is recorded
    on every result (0 if none needed) for transparency, not just
    subtracted away silently."""
    total_wait = 0.0
    retries = 0
    for attempt in range(max_retries):
        try:
            return analyse_alert(alert, **cfg), total_wait, retries
        except RateLimitError:
            if attempt == max_retries - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(f"    rate limited, waiting {wait:.0f}s...", flush=True)
            time.sleep(wait)
            total_wait += wait
            retries += 1


def _load_checkpoint(output_path: str) -> dict:
    if os.path.exists(output_path):
        with open(output_path) as f:
            data = json.load(f)
        if isinstance(data.get("by_config"), dict):
            return data["by_config"]
    return {name: [] for name in CONFIGS}


def _write_checkpoint(output_path: str, by_config: dict, dataset_name: str, total_alerts: int):
    total_done = sum(len(v) for v in by_config.values())
    total_target = total_alerts * len(CONFIGS)
    output = {
        "dataset": dataset_name,
        "total_alerts_in_dataset": total_alerts,
        "configs": list(CONFIGS.keys()),
        "total_target": total_target,
        "total_done": total_done,
        "run_complete": total_done == total_target,
        "by_config": by_config,
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)


def run_dataset(dataset_name: str, alerts: list, ground_truth_fn, output_filename: str):
    """
    alerts: list of SecurityAlert objects
    ground_truth_fn: alert -> dict of ground-truth fields to attach to
                      each result (e.g. {"expected_cve": "..."})
    """
    _warmup_once()
    output_path = os.path.join(RESULTS_DIR, output_filename)
    by_config = _load_checkpoint(output_path)

    total_alerts = len(alerts)
    total_target = total_alerts * len(CONFIGS)
    total_done_at_start = sum(len(v) for v in by_config.values())
    if total_done_at_start:
        print(f"Resuming '{dataset_name}': {total_done_at_start}/{total_target} (config, alert) pairs already done\n")

    for config_name, cfg in CONFIGS.items():
        done_ids = {r["alert_id"] for r in by_config[config_name]}
        remaining = [a for a in alerts if a.alert_id not in done_ids]
        if not remaining:
            print(f"[{dataset_name} / {config_name}] already complete ({total_alerts}/{total_alerts}), skipping")
            continue

        for alert in remaining:
            idx = len(by_config[config_name]) + 1
            print(f"[{dataset_name} / {config_name}] ({idx}/{total_alerts}) {alert.alert_id}...", flush=True)

            start = time.perf_counter()
            report, retry_wait_sec, retries = _analyse_with_retry(alert, **cfg)
            latency_sec = (time.perf_counter() - start) - retry_wait_sec

            record = {
                "alert_id": alert.alert_id,
                "config": config_name,
                "latency_sec": latency_sec,
                "rate_limit_retries": retries,
                "guardrail_blocked": report.get("guardrail_blocked"),
                "severity_assessment": report.get("severity_assessment"),
                "hallucinated_cves": report.get("hallucinated_cves"),
                "cve_verifications": report.get("cve_verifications"),
                "hallucinated_attack_techniques": report.get("hallucinated_attack_techniques"),
                "attack_technique_verifications": report.get("attack_technique_verifications"),
                "pii_detections": report.get("pii_detections"),
                "output_guardrail_flagged": report.get("output_guardrail_flagged"),
                "requires_review": report.get("requires_review"),
            }
            record.update(ground_truth_fn(alert))

            by_config[config_name].append(record)
            _write_checkpoint(output_path, by_config, dataset_name, total_alerts)

        print(f"[{dataset_name} / {config_name}] complete ({total_alerts}/{total_alerts})\n")

    total_done = sum(len(v) for v in by_config.values())
    print(f"'{dataset_name}' dataset: {total_done}/{total_target} (config, alert) pairs complete.")
    print(f"Results at {output_path}\n")


def run_cve_bait():
    from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS, EXPECTED_CVE
    run_dataset(
        "cve-bait",
        CVE_BAIT_ALERTS,
        lambda a: {"expected_cve": EXPECTED_CVE.get(a.alert_id)},
        "ablation_study_cve_bait.json",
    )


def run_attack_bait():
    from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS, EXPECTED_TECHNIQUE
    run_dataset(
        "attack-bait",
        ATTACK_BAIT_ALERTS,
        lambda a: {"expected_technique": EXPECTED_TECHNIQUE.get(a.alert_id)},
        "ablation_study_attack_bait.json",
    )


def run_pii_bait():
    from experiments.evaluation.pii_bait_alerts import PII_ALERTS, CLEAN_ALERTS

    pii_alerts = [item["alert"] for item in PII_ALERTS]
    pii_expected = {item["alert"].alert_id: sorted(item["expected_entities"]) for item in PII_ALERTS}
    all_alerts = pii_alerts + CLEAN_ALERTS

    def ground_truth(a):
        return {
            "is_clean_alert": a.alert_id not in pii_expected,
            "expected_entities": pii_expected.get(a.alert_id, []),
        }

    run_dataset("pii-bait", all_alerts, ground_truth, "ablation_study_pii_bait.json")


DATASET_RUNNERS = {
    "cve": run_cve_bait,
    "attack": run_attack_bait,
    "pii": run_pii_bait,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["cve", "attack", "pii", "all"], required=True)
    args = parser.parse_args()

    if args.dataset == "all":
        for name, fn in DATASET_RUNNERS.items():
            fn()
    else:
        DATASET_RUNNERS[args.dataset]()


if __name__ == "__main__":
    main()
