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

Hard tier (added after PR #25 review, engranaabubakar): the original
GROUNDED sample has zero identifiers of any kind (step 1 strips them all),
so the original 212-sample set can be solved by "does any ID-shaped token
appear in the report" without the judge ever having to actually check
whether an identifier is present in the evidence -- a real construct-
validity gap, not just a hypothetical one. To test the capability the
judge is actually supposed to have, a third class is added per base
report: GROUNDED-CITED. It reuses the exact same distractor identifier as
that report's UNGROUNDED twin, but injects it into the ALERT EVIDENCE too
(via a synthetic "scanner cross-reference" sentence appended to
`alert_text`), not just the report. Same surface form (an ID-shaped token
in the reasoning field) as the UNGROUNDED case; the only difference is
whether that ID also appears in the evidence -- which is exactly the
distinction the judge's system prompt claims to make. `run()` reports
accuracy for this tier separately (GROUNDED-CITED vs. UNGROUNDED, "hard"
pair) alongside the original (GROUNDED-EMPTY vs. UNGROUNDED, "easy" pair)
so a construct-validity regression would show up as a lower hard-tier
number, not be hidden inside one blended accuracy figure.

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
                evidence_sentence = f" Vulnerability scanner cross-reference: {distractor} confirmed present on this host."
            else:
                injected_sentence = f" This corresponds to MITRE ATT&CK technique {distractor}."
                evidence_sentence = f" Detection engine cross-reference: matches MITRE ATT&CK technique {distractor}."

            injected_fields = dict(clean_fields)
            injected_fields["reasoning"] = clean_fields["reasoning"] + injected_sentence

            base_id = f"{dataset_name}-{report['alert_id']}"

            # Tier: GROUNDED-EMPTY -- no identifiers anywhere (the original,
            # "easy" grounded case: solvable by "is there any ID token").
            samples.append({
                "id": f"{base_id}-grounded-empty",
                "tier": "grounded_empty",
                "source_dataset": dataset_name,
                "alert_text": alert_text,
                "report_fields": clean_fields,
                "ground_truth": False,
            })
            # Tier: GROUNDED-CITED (hard, added after PR #25 review) -- same
            # distractor as the UNGROUNDED twin below, but also injected
            # into the evidence, so the ID is genuinely present-and-grounded.
            samples.append({
                "id": f"{base_id}-grounded-cited",
                "tier": "grounded_cited",
                "source_dataset": dataset_name,
                "alert_text": alert_text + evidence_sentence,
                "report_fields": injected_fields,
                "cited_id": distractor,
                "ground_truth": False,
            })
            # Tier: UNGROUNDED -- identifier present in the report only.
            samples.append({
                "id": f"{base_id}-ungrounded",
                "tier": "ungrounded",
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


def _confusion_matrix(rows: list) -> dict:
    scored = [r for r in rows if r["judge_verdict"] != "PARSE_ERROR"]
    parse_errors = [r for r in rows if r["judge_verdict"] == "PARSE_ERROR"]

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

    return {
        "n_scored": n,
        "n_parse_errors": len(parse_errors),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "accuracy_wilson_ci_95": wilson_ci(correct, n),
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_ci_95": wilson_ci(tp, tp + fp) if (tp + fp) else (None, None),
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_ci_95": wilson_ci(tp, tp + fn) if (tp + fn) else (None, None),
        "f1": round(f1, 4) if f1 is not None else None,
    }


def _print_summary(label: str, m: dict) -> None:
    print(f"\n=== {label} (n={m['n_scored']}, {m['n_parse_errors']} parse errors) ===")
    print(f"Accuracy:  {m['accuracy']:.1%}  95% Wilson CI "
          f"[{m['accuracy_wilson_ci_95'][0]:.1%}, {m['accuracy_wilson_ci_95'][1]:.1%}]")
    if m["precision"] is not None:
        print(f"Precision: {m['precision']:.1%}  95% Wilson CI "
              f"[{m['precision_wilson_ci_95'][0]:.1%}, {m['precision_wilson_ci_95'][1]:.1%}]")
    if m["recall"] is not None:
        print(f"Recall:    {m['recall']:.1%}  95% Wilson CI "
              f"[{m['recall_wilson_ci_95'][0]:.1%}, {m['recall_wilson_ci_95'][1]:.1%}]")
    print(f"Confusion matrix: {m['confusion_matrix']}")


def _write_output(n_samples: int, results: list, complete: bool) -> dict:
    easy_rows = [r for r in results if r["tier"] in ("grounded_empty", "ungrounded")]
    hard_rows = [r for r in results if r["tier"] in ("grounded_cited", "ungrounded")]

    overall = _confusion_matrix(results)
    easy = _confusion_matrix(easy_rows)  # original #24 pair: grounded-empty vs. ungrounded
    hard = _confusion_matrix(hard_rows)  # new pair: grounded-cited vs. ungrounded

    output = {
        "task": "LLM-judge synthetic calibration -- grounded-empty / grounded-cited / ungrounded tiers",
        "model": MODEL_NAME,
        "n_samples": n_samples,
        "n_completed": len(results),
        "run_complete": complete,
        "overall": overall,
        "easy_pair_grounded_empty_vs_ungrounded": easy,
        "hard_pair_grounded_cited_vs_ungrounded": hard,
        "results": results,
    }

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    return output


def run():
    samples = build_synthetic_samples()
    n_ungrounded = sum(s["ground_truth"] for s in samples)
    n_grounded_empty = sum(s["tier"] == "grounded_empty" for s in samples)
    n_grounded_cited = sum(s["tier"] == "grounded_cited" for s in samples)
    print(f"Built {len(samples)} synthetic samples "
          f"({n_ungrounded} ungrounded / {n_grounded_empty} grounded-empty / "
          f"{n_grounded_cited} grounded-cited)\n")

    # Resume from a prior checkpoint if one exists -- the daily token quota
    # on the free Groq tier is smaller than a full 318-call run needs, so
    # this test structurally requires spanning more than one day. Skip any
    # sample id already present in a previous (possibly incomplete) run.
    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if "n_completed" in prior and isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} samples already completed\n")
    done_ids = {r["id"] for r in results}
    remaining = [s for s in samples if s["id"] not in done_ids]

    for sample in remaining:
        verdict = _judge_with_retry(llm, sample["alert_text"], sample["report_fields"])
        results.append({**sample, "judge_verdict": verdict["verdict"], "judge_flagged": verdict["flagged"],
                         "judge_reasoning": verdict["reasoning"]})
        agree = "agree" if sample["ground_truth"] == verdict["flagged"] else "DISAGREE"
        print(f"[{len(results)}/{len(samples)}] {sample['id']}: "
              f"truth={sample['ground_truth']} judge={verdict['verdict']} ({agree})")

        # Checkpoint after every sample -- a 318-call run against a
        # quota-pressured free tier previously crashed at ~97% completion
        # with nothing recoverable (no incremental writes), losing the
        # entire run. Same pattern as selfcheckgpt_test.py's _write_output.
        _write_output(len(samples), results, complete=False)

    output = _write_output(len(samples), results, complete=True)

    _print_summary("Overall (all 3 tiers, imbalanced 2 grounded : 1 ungrounded)", output["overall"])
    _print_summary("Easy pair (grounded-empty vs. ungrounded -- original #24 test)",
                    output["easy_pair_grounded_empty_vs_ungrounded"])
    _print_summary("Hard pair (grounded-cited vs. ungrounded -- construct-validity tier)",
                    output["hard_pair_grounded_cited_vs_ungrounded"])

    parse_errors = [r for r in results if r["judge_verdict"] == "PARSE_ERROR"]
    if parse_errors:
        print(f"\nWARNING: {len(parse_errors)} judge responses failed to parse: "
              f"{[r['id'] for r in parse_errors]}")

    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
