"""
experiments/evaluation/selfcheckgpt_test_attack.py

The ATT&CK-side counterpart of selfcheckgpt_test.py (issue #40/R1) --
closes the paper's disclosed CVE-only gap in its central SelfCheckGPT-
vs-deterministic comparison. Same harness, same scoring convention, same
checkpoint-resume behavior; the only real differences are the alert set
(selfcheckgpt_alerts_attack.py instead of selfcheckgpt_alerts.py) and the
extractor (extract_attack_ids instead of extract_cves). See
selfcheckgpt_test.py's own docstring for the full methodology rationale
(N_SAMPLES=3 cost tradeoff, "don't score what wasn't claimed" convention,
etc.) -- it applies unchanged here.

Ground truth per alert is the class it was built from
(selfcheckgpt_alerts_attack.py): STATED = grounded (technique ID given
directly, expect stable echoing -- including the 3 items where that given
ID is itself a REVOKED legacy one, since grounding only asks whether the
ID matches the evidence, not whether it's still current), PROMPTED =
ungrounded (technique ID withheld, any citation is ungrounded regardless
of factual correctness).

Usage:
    python -m experiments.evaluation.selfcheckgpt_test_attack

    Same GENERATOR_MODEL override as selfcheckgpt_test.py:

        GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_test_attack

    Writes to its own results file (selfcheckgpt_results_attack[_<model>].json).
"""

import json
import os
import re

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from scipy.stats import norm

from src.agent.soc_agent import MODEL_NAME
from src.guardrails.attack_grounding import extract_attack_ids
from src.guardrails.selfcheckgpt import sample_citations, consistency_score, SAMPLING_TEMPERATURE
from experiments.evaluation.selfcheckgpt_alerts_attack import STATED_ALERTS_ATTACK, PROMPTED_ALERTS_ATTACK

load_dotenv()

GENERATOR_MODEL_NAME = os.getenv("GENERATOR_MODEL", MODEL_NAME)

# qwen/qwen3.6-27b's current Groq free-tier organization limit caps output
# tokens per minute (OTPM) at 1000 -- below LangChain's default max_tokens
# (2048), which the API rejects outright regardless of retry/backoff
# ("reduce max_tokens and try again"). This wasn't a problem for the
# original qwen SelfCheckGPT run (#50/#51 in docs/all_results.md), so it
# reflects a live quota change on Groq's side since then, not a bug in
# that earlier run. Only qwen is capped here; gpt-oss-20b keeps its
# already-proven default.
_MAX_TOKENS = 900 if "qwen" in GENERATOR_MODEL_NAME.lower() else None
llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=GENERATOR_MODEL_NAME, temperature=SAMPLING_TEMPERATURE,
                max_tokens=_MAX_TOKENS)

N_SAMPLES = 3


def _slug(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", model).strip("_").lower()


def _output_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_results_attack.json"
    return f"experiments/results/selfcheckgpt_results_attack_{_slug(generator_model)}.json"


OUTPUT_PATH = _output_path_for(GENERATOR_MODEL_NAME)


def wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def _write_output(all_alerts: list, results: list, complete: bool) -> dict:
    scored = [r for r in results if r["citation_occurred"]]
    declined = [r for r in results if not r["citation_occurred"]]

    tp = sum(1 for r in scored if r["expected_ungrounded"] and r["flagged_unstable"])
    fp = sum(1 for r in scored if not r["expected_ungrounded"] and r["flagged_unstable"])
    tn = sum(1 for r in scored if not r["expected_ungrounded"] and not r["flagged_unstable"])
    fn = sum(1 for r in scored if r["expected_ungrounded"] and not r["flagged_unstable"])
    n = len(scored)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    accuracy = (tp + tn) / n if n else None
    stable_but_wrong = [r for r in scored if r["expected_ungrounded"] and not r["flagged_unstable"]]

    output = {
        "task": "SelfCheckGPT-style resampling-consistency baseline vs. deterministic ATT&CK grounding check",
        "model": GENERATOR_MODEL_NAME,
        "sampling_temperature": SAMPLING_TEMPERATURE,
        "n_samples_per_alert": N_SAMPLES,
        "n_alerts_total": len(all_alerts),
        "n_alerts_completed": len(results),
        "run_complete": complete,
        "n_scored": n,
        "n_declined_every_sample": len(declined),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "accuracy_wilson_ci_95": wilson_ci(tp + tn, n),
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_ci_95": wilson_ci(tp, tp + fp) if (tp + fp) else (None, None),
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_ci_95": wilson_ci(tp, tp + fn) if (tp + fn) else (None, None),
        "stable_but_wrong_alert_ids": [r["alert_id"] for r in stable_but_wrong],
        "results": results,
    }

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    return output


def run():
    print(f"Generator model: {GENERATOR_MODEL_NAME}")
    print(f"Output: {OUTPUT_PATH}\n")

    all_alerts = [{"class": "stated", **item} for item in STATED_ALERTS_ATTACK] + \
                 [{"class": "prompted", **item} for item in PROMPTED_ALERTS_ATTACK]

    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [item for item in all_alerts if item["alert"].alert_id not in done_ids]

    for item in remaining:
        alert = item["alert"]
        print(f"[{len(results)+1}/{len(all_alerts)}] {alert.alert_id} ({item['class']})...")
        samples = sample_citations(llm, alert, extract_attack_ids, n_samples=N_SAMPLES)
        score = consistency_score(samples)
        citation_occurred = score["majority_id"] is not None

        results.append({
            "alert_id": alert.alert_id,
            "class": item["class"],
            "expected_ungrounded": item["expected_ungrounded"],
            "ground_truth_technique": item["ground_truth_technique"],
            "is_revoked_id": item["is_revoked_id"],
            "samples": [sorted(s) for s in samples],
            "any_citation_rate": score["any_citation_rate"],
            "majority_id": score["majority_id"],
            "agreement_rate": score["agreement_rate"],
            "flagged_unstable": score["flagged_unstable"],
            "citation_occurred": citation_occurred,
        })
        status = "declined every sample" if not citation_occurred else \
            f"majority={score['majority_id']} agreement={score['agreement_rate']:.0%} " \
            f"{'UNSTABLE' if score['flagged_unstable'] else 'stable'}"
        print(f"    {status}")

        _write_output(all_alerts, results, complete=False)

    output = _write_output(all_alerts, results, complete=True)

    print(f"\n=== SelfCheckGPT (ATT&CK) summary (n_scored={output['n_scored']}, "
          f"{output['n_declined_every_sample']} declined every sample) ===")
    print(f"Accuracy={output['accuracy']}  Precision={output['precision']}  Recall={output['recall']}")
    print(f"Confusion matrix: {output['confusion_matrix']}")
    if output["stable_but_wrong_alert_ids"]:
        print(f"Stable-but-wrong: {output['stable_but_wrong_alert_ids']}")
    else:
        print("No stable-but-wrong cases observed in this run.")


if __name__ == "__main__":
    run()
