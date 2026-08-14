"""
experiments/evaluation/llm_judge_baseline_test.py

Runs the LLM-judge baseline (src/guardrails/llm_judge.py) against the
already-saved CVE-bait and ATT&CK-bait results
(experiments/results/cve_bait_results.json,
experiments/results/attack_bait_results.json) and compares its
grounded/ungrounded verdicts against the deterministic output-guardrail's
own verdicts on the same reports. No new alert generation or agent
pipeline runs needed -- only new judge calls -- since both result files
already contain the generated report plus the deterministic checker's
verdict for every sample.

Ground truth for this comparison is the deterministic checker's own
grounding verdict (hallucinated_cves / hallucinated_attack_techniques
non-empty), NOT a hand-labeled external truth. "Is this exact identifier
string present in the alert text" is an objective, mechanically-checkable
fact, not a judgment call -- so the deterministic extract-and-diff result
IS the correct answer for this narrow question by construction. What's
actually being tested is whether the LLM-judge can reproduce that same
objective answer without the deterministic scaffolding (issue #20,
docs/ROADMAP_PLAN.md sec.3 item 5).

Why this is scored as a confusion matrix, not McNemar's test: McNemar
(experiments/evaluation/guardrail_comparison/significance_test.py) is for
comparing two FALLIBLE implementations that are both scored against a
third, external ground truth -- that's the input-guardrail case (hybrid vs.
Pytector vs. LLM Guard, all scored against hand-labeled injection/benign
samples). Here there is no third external label: the deterministic checker
IS the ground truth for "is this ID present in the text," so pairing it
against itself in a McNemar test would be degenerate by construction
(it can never be wrong). A precision/recall/confusion-matrix read of the
judge against that ground truth is the correct method for this baseline,
not a paired significance test.

Honest small-n caveat, both datasets: CVE-bait ground truth is heavily
imbalanced (2 ungrounded / 100, see docs/all_results.md #21) and
ATT&CK-bait is small outright (2 ungrounded / 6 total, see
docs/all_results.md #13/#16 and attack_bait_results.json). Precision/recall
on that few positives should be read as a first directional estimate, not
a citable rate -- same caveat already on record for CVE-bait McNemar
testing in docs/ROADMAP_PLAN.md sec.10 item 5.

Usage:
    python -m experiments.evaluation.llm_judge_baseline_test
"""

import json
import os
import time

from dotenv import load_dotenv
from groq import RateLimitError
from langchain_groq import ChatGroq

from src.agent.soc_agent import MODEL_NAME
from src.guardrails.llm_judge import judge_grounding

load_dotenv()

llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=MODEL_NAME, temperature=0.1)


def _judge_with_retry(llm, alert_text: str, report: dict, max_retries: int = 5, base_delay: float = 8.0) -> dict:
    """
    gpt-oss-20b's free-tier Groq limit is 8000 tokens/minute -- hit live
    while building this harness (see docs/all_results.md #23), since each
    judge call sends the full alert evidence text plus the full report text
    plus the judge system prompt, and a 100-sample sequential run adds that
    up fast even without concurrency. Same exponential-backoff shape as
    experiments/evaluation/threading_benchmark.py's analyse_alert_with_retry.
    """
    for attempt in range(max_retries):
        try:
            return judge_grounding(llm, alert_text, report)
        except RateLimitError:
            if attempt == max_retries - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(f"    rate limited, waiting {wait:.0f}s...")
            time.sleep(wait)

DATASETS = {
    "cve_bait": {
        "results_path": "experiments/results/cve_bait_results.json",
        "ground_truth_field": "hallucinated_cves",
    },
    "attack_bait": {
        "results_path": "experiments/results/attack_bait_results.json",
        "ground_truth_field": "hallucinated_attack_techniques",
    },
}

OUTPUT_PATH = "experiments/results/llm_judge_baseline_results.json"


def confusion_matrix(samples: list) -> dict:
    """
    samples: [{"id", "ground_truth": bool, "judge_flagged": bool, "judge_verdict": str}, ...]
    PARSE_ERROR samples are excluded from TP/FP/TN/FN (counted separately)
    since they're neither a correct nor an incorrect grounding judgment --
    they're the judge failing to answer at all.
    """
    scored = [s for s in samples if s["judge_verdict"] != "PARSE_ERROR"]
    parse_errors = [s for s in samples if s["judge_verdict"] == "PARSE_ERROR"]

    tp = sum(1 for s in scored if s["ground_truth"] and s["judge_flagged"])
    fp = sum(1 for s in scored if not s["ground_truth"] and s["judge_flagged"])
    tn = sum(1 for s in scored if not s["ground_truth"] and not s["judge_flagged"])
    fn = sum(1 for s in scored if s["ground_truth"] and not s["judge_flagged"])

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    accuracy = (tp + tn) / len(scored) if scored else None

    return {
        "n_scored": len(scored),
        "n_parse_errors": len(parse_errors),
        "parse_error_ids": [s["id"] for s in parse_errors],
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "accuracy": round(accuracy, 3) if accuracy is not None else None,
    }


def run_dataset(name: str, results_path: str, ground_truth_field: str) -> dict:
    with open(results_path) as f:
        data = json.load(f)

    samples = []
    print(f"\n=== {name} ({results_path}) ===")

    for report in data["results"]:
        sample_id = report["alert_id"]
        alert_text = report["evidence_pack"]["text"]
        ground_truth = bool(report.get(ground_truth_field))

        verdict = _judge_with_retry(llm, alert_text, report)

        samples.append({
            "id": sample_id,
            "ground_truth": ground_truth,
            "judge_verdict": verdict["verdict"],
            "judge_flagged": verdict["flagged"],
            "judge_ungrounded_ids": verdict["ungrounded_ids"],
            "judge_reasoning": verdict["reasoning"],
            "deterministic_ungrounded_ids": report.get(ground_truth_field, []),
        })

        agree = "agree" if ground_truth == verdict["flagged"] else "DISAGREE"
        print(f"  {sample_id}: deterministic={ground_truth} judge={verdict['verdict']} ({agree})")

    metrics = confusion_matrix(samples)
    agreement = sum(1 for s in samples if s["ground_truth"] == s["judge_flagged"]) / len(samples)

    print(f"\n{name} summary: n={len(samples)} agreement_rate={agreement:.1%}")
    print(f"  precision={metrics['precision']} recall={metrics['recall']} "
          f"f1={metrics['f1']} accuracy={metrics['accuracy']}")
    if metrics["n_parse_errors"]:
        print(f"  WARNING: {metrics['n_parse_errors']} judge response(s) failed to parse: "
              f"{metrics['parse_error_ids']}")

    return {
        "dataset": name,
        "n_samples": len(samples),
        "agreement_rate": round(agreement, 3),
        "confusion_matrix": metrics,
        "samples": samples,
    }


def run():
    results = {name: run_dataset(name, cfg["results_path"], cfg["ground_truth_field"])
               for name, cfg in DATASETS.items()}

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({
            "task": "LLM-judge baseline vs. deterministic output-guardrail grounding checks",
            "model": MODEL_NAME,
            "note": "Ground truth is the deterministic checker's own verdict, not an "
                     "external hand-labeled truth -- see module docstring for why.",
            "datasets": results,
        }, f, indent=2)

    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
