"""
experiments/evaluation/llm_judge_synthetic_test.py

The LLM-judge baseline (llm_judge_baseline_test.py, docs/all_results.md
#23) got 100% agreement with the deterministic grounding checker, but on
only 4 positive (ungrounded) cases out of 106 samples -- too few to cite a
real precision/recall number, for the same reason the original CVE-bait
set wasn't citable until it grew to n=100 (#21). Unlike #21, growing this
one by writing more bait alerts wouldn't reliably fix it: the underlying
model almost never spontaneously hallucinates a citation (~0% per #21), so
waiting for more organic positives is slow, expensive, and its count can't
be chosen in advance.

This script sidesteps that by testing the JUDGE directly on a class-
balanced, purpose-built set instead of waiting for the agent to hallucinate
on its own -- a controlled calibration set, not a replacement for #23's
real-pipeline check (kept as the "does it also hold on real model output"
corroborating evidence).

Method: reuse the 106 existing (alert evidence, generated report) pairs
already saved from the CVE-bait and ATT&CK-bait runs
(experiments/results/cve_bait_results.json, attack_bait_results.json). For
each one:
  1. Strip any CVE/ATT&CK identifier already present in the report text
     (regex, reusing the same CVE_PATTERN/ATTACK_ID_PATTERN the
     deterministic checkers use) -- guarantees a genuinely clean base,
     regardless of whether the original report happened to cite anything.
  2. That clean version is the GROUNDED sample (label False).
  3. A twin copy has one sentence appended to its reasoning field, citing a
     real CVE (for CVE-bait bases) or real MITRE ATT&CK technique (for
     ATT&CK-bait bases) that this alert's own evidence never mentions --
     the UNGROUNDED sample (label True). The injected identifier is drawn
     from a fixed-offset shuffle of this project's own already-verified
     real identifiers (EXPECTED_CVE in cve_bait_alerts.py; the local MITRE
     snapshot for technique IDs) rather than invented, so it's realistic
     rather than a trivially-detectable nonsense string.

Result: 212 samples (106 GROUNDED / 106 UNGROUNDED), a clean 50/50 split,
built with zero new agent-pipeline calls -- only new judge calls.

Wilson 95% CI implemented directly (same no-new-dependency convention as
significance_test.py, which uses scipy rather than adding statsmodels for
one test) rather than a normal-approximation interval, since that's the
project's established convention for small-ish n (see #21).

Usage:
    python -m experiments.evaluation.llm_judge_synthetic_test
"""

import json
import os
import re
import time

from dotenv import load_dotenv
from groq import RateLimitError
from langchain_groq import ChatGroq
from scipy.stats import norm

from src.agent.soc_agent import MODEL_NAME
from src.guardrails.attack_grounding import ATTACK_ID_PATTERN, DEFAULT_SNAPSHOT_PATH
from src.guardrails.grounding_utils import REPORT_TEXT_FIELDS
from src.guardrails.llm_judge import judge_grounding
from src.guardrails.output_guardrail import CVE_PATTERN
from experiments.evaluation.cve_bait_alerts import EXPECTED_CVE

load_dotenv()

llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=MODEL_NAME, temperature=0.1)

SOURCE_DATASETS = {
    "cve_bait": {
        "results_path": "experiments/results/cve_bait_results.json",
        "id_pattern": CVE_PATTERN,
        "distractor_kind": "cve",
    },
    "attack_bait": {
        "results_path": "experiments/results/attack_bait_results.json",
        "id_pattern": ATTACK_ID_PATTERN,
        "distractor_kind": "attack",
    },
}

OUTPUT_PATH = "experiments/results/llm_judge_synthetic_results.json"

# Shift offsets so an alert never gets assigned its own expected/adjacent
# identifier as a distractor -- doesn't need to be cryptographically clean,
# just non-zero and not a divisor of the pool size.
CVE_SHIFT = 13
ATTACK_SHIFT = 97


def _load_attack_distractor_pool() -> list:
    with open(DEFAULT_SNAPSHOT_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)
    techniques = snapshot.get("techniques", {})
    return sorted(tid for tid, rec in techniques.items() if not rec.get("revoked") and rec.get("description"))


def _strip_identifiers(text: str, id_pattern: re.Pattern, replacement: str) -> str:
    return id_pattern.sub(replacement, text or "")


def build_synthetic_samples() -> list:
    cve_distractor_pool = [EXPECTED_CVE[k] for k in sorted(EXPECTED_CVE)]
    attack_distractor_pool = _load_attack_distractor_pool()

    samples = []
    for dataset_name, cfg in SOURCE_DATASETS.items():
        with open(cfg["results_path"]) as f:
            data = json.load(f)

        pool = cve_distractor_pool if cfg["distractor_kind"] == "cve" else attack_distractor_pool
        shift = CVE_SHIFT if cfg["distractor_kind"] == "cve" else ATTACK_SHIFT
        replacement = "a known vulnerability" if cfg["distractor_kind"] == "cve" else "a known technique"

        for i, report in enumerate(data["results"]):
            alert_text = report["evidence_pack"]["text"]

            clean_fields = {
                field: _strip_identifiers(str(report.get(field, "")), cfg["id_pattern"], replacement)
                for field in REPORT_TEXT_FIELDS
            }
            distractor = pool[(i + shift) % len(pool)]
            assert distractor.upper() not in alert_text.upper(), (
                f"distractor {distractor} unexpectedly present in {report['alert_id']}'s evidence"
            )

            if cfg["distractor_kind"] == "cve":
                injected_sentence = f" This is consistent with exploitation of {distractor}."
            else:
                injected_sentence = f" This corresponds to MITRE ATT&CK technique {distractor}."

            injected_fields = dict(clean_fields)
            injected_fields["reasoning"] = clean_fields["reasoning"] + injected_sentence

            base_id = f"{dataset_name}-{report['alert_id']}"
            samples.append({
                "id": f"{base_id}-grounded",
                "source_dataset": dataset_name,
                "alert_text": alert_text,
                "report_fields": clean_fields,
                "ground_truth": False,
            })
            samples.append({
                "id": f"{base_id}-ungrounded",
                "source_dataset": dataset_name,
                "alert_text": alert_text,
                "report_fields": injected_fields,
                "injected_id": distractor,
                "ground_truth": True,
            })

    return samples


def _judge_with_retry(llm, alert_text: str, report: dict, max_retries: int = 5, base_delay: float = 8.0) -> dict:
    """Same exponential-backoff shape as llm_judge_baseline_test.py -- see that
    file's docstring for why gpt-oss-20b's free-tier TPM limit needs this."""
    for attempt in range(max_retries):
        try:
            return judge_grounding(llm, alert_text, report)
        except RateLimitError:
            if attempt == max_retries - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(f"    rate limited, waiting {wait:.0f}s...")
            time.sleep(wait)


def wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def run():
    samples = build_synthetic_samples()
    print(f"Built {len(samples)} synthetic samples "
          f"({sum(s['ground_truth'] for s in samples)} ungrounded / "
          f"{sum(not s['ground_truth'] for s in samples)} grounded)\n")

    results = []
    for i, sample in enumerate(samples):
        verdict = _judge_with_retry(llm, sample["alert_text"], sample["report_fields"])
        results.append({**sample, "judge_verdict": verdict["verdict"], "judge_flagged": verdict["flagged"],
                         "judge_reasoning": verdict["reasoning"]})
        agree = "agree" if sample["ground_truth"] == verdict["flagged"] else "DISAGREE"
        print(f"[{i+1}/{len(samples)}] {sample['id']}: "
              f"truth={sample['ground_truth']} judge={verdict['verdict']} ({agree})")

    scored = [r for r in results if r["judge_verdict"] != "PARSE_ERROR"]
    parse_errors = [r for r in results if r["judge_verdict"] == "PARSE_ERROR"]

    tp = sum(1 for r in scored if r["ground_truth"] and r["judge_flagged"])
    fp = sum(1 for r in scored if not r["ground_truth"] and r["judge_flagged"])
    tn = sum(1 for r in scored if not r["ground_truth"] and not r["judge_flagged"])
    fn = sum(1 for r in scored if r["ground_truth"] and not r["judge_flagged"])
    n = len(scored)
    correct = tp + tn

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    accuracy = correct / n if n else None

    acc_ci = wilson_ci(correct, n)
    recall_ci = wilson_ci(tp, tp + fn) if (tp + fn) else (None, None)
    precision_ci = wilson_ci(tp, tp + fp) if (tp + fp) else (None, None)

    print(f"\n=== Synthetic calibration summary (n={n}, {len(parse_errors)} parse errors) ===")
    print(f"Accuracy:  {accuracy:.1%}  95% Wilson CI [{acc_ci[0]:.1%}, {acc_ci[1]:.1%}]")
    print(f"Precision: {precision:.1%}  95% Wilson CI [{precision_ci[0]:.1%}, {precision_ci[1]:.1%}]")
    print(f"Recall:    {recall:.1%}  95% Wilson CI [{recall_ci[0]:.1%}, {recall_ci[1]:.1%}]")
    print(f"F1: {f1:.3f}")
    print(f"Confusion matrix: TP={tp} FP={fp} TN={tn} FN={fn}")
    if parse_errors:
        print(f"WARNING: {len(parse_errors)} judge responses failed to parse: "
              f"{[r['id'] for r in parse_errors]}")

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({
            "task": "LLM-judge synthetic calibration -- balanced grounded/ungrounded set",
            "model": MODEL_NAME,
            "n_samples": len(samples),
            "n_scored": n,
            "n_parse_errors": len(parse_errors),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "accuracy": round(accuracy, 4) if accuracy is not None else None,
            "accuracy_wilson_ci_95": acc_ci,
            "precision": round(precision, 4) if precision is not None else None,
            "precision_wilson_ci_95": precision_ci,
            "recall": round(recall, 4) if recall is not None else None,
            "recall_wilson_ci_95": recall_ci,
            "f1": round(f1, 4) if f1 is not None else None,
            "results": results,
        }, f, indent=2)

    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
