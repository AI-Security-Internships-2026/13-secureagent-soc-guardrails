"""
experiments/evaluation/selfcheckgpt_test.py

Runs the SelfCheckGPT-style baseline (src/guardrails/selfcheckgpt.py)
against the 60-alert stated/prompted set (selfcheckgpt_alerts.py) --
issue #20 sec.3 item 8 (docs/ROADMAP_PLAN.md), required alongside the
LLM-judge baseline (#23/#24) as a second hallucination-detection
comparison for the paper.

Scoring: for each alert, generate N_SAMPLES resamples at temperature=0.7 and
extract the cited CVE from each (src.guardrails.output_guardrail.extract_cves).
N_SAMPLES=3 rather than a literature-typical 5-20 -- a deliberate cost/time
tradeoff given this project's Groq free-tier quota was already under
pressure from the same day's #23/#24 runs (observed ~20s/call during a
smoke test, vs. ~5s/call earlier the same day). 3 samples still supports a
majority vote (2/3 or 3/3 = stable, no-majority/1-1-1 = unstable) -- coarser
than 5 would give, but real and honestly reported as a scale tradeoff
rather than silently presented as equivalent to the literature's typical N.
Results are checkpointed to disk after every alert so a late-run failure
(rate-limit exhaustion, network error) doesn't lose already-computed data.
An alert only enters the confusion matrix if at least one of its 5 samples
actually cited something -- an alert where the model stayed silent every
time has no claim to judge for stability, same "don't score what wasn't
claimed" convention used throughout this project's other bait tests (see
#21's 0/97 spontaneous-citation alerts). Those "declined every time" cases
are still counted and reported separately (not silently dropped).

Ground truth per alert is the class it was built from
(selfcheckgpt_alerts.py): STATED = grounded (CVE given directly, expect
stable echoing), PROMPTED = ungrounded (CVE withheld, any citation is
ungrounded by the same rule the deterministic checker already applies,
regardless of factual correctness).

Usage:
    python -m experiments.evaluation.selfcheckgpt_test

    Report-generation model defaults to MODEL_NAME (src/agent/soc_agent.py,
    openai/gpt-oss-20b) -- the paper's central SelfCheckGPT-vs-deterministic
    result was only ever run against this one model/provider, a disclosed
    generalization gap (docs/paper/paper_draft.md §5). To test whether that
    result is a pipeline property or a gpt-oss-20b-specific artifact, set
    GENERATOR_MODEL to a genuinely different, currently-active Groq model
    (confirmed live via the groq SDK's client.models.list() on 2026-08-29 --
    e.g. "qwen/qwen3.6-27b", a different lab/training lineage):

        GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_test

    Writes to its own results file (selfcheckgpt_results_<model>.json)
    rather than overwriting the completed gpt-oss-20b baseline.
"""

import json
import os
import re

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from scipy.stats import norm

from src.agent.soc_agent import MODEL_NAME
from src.guardrails.attack_grounding import extract_attack_ids  # noqa: F401  (kept for parity/future ATT&CK extension)
from src.guardrails.output_guardrail import extract_cves
from src.guardrails.selfcheckgpt import sample_citations, consistency_score, SAMPLING_TEMPERATURE
from experiments.evaluation.selfcheckgpt_alerts import STATED_ALERTS, PROMPTED_ALERTS

load_dotenv()

# Report-generation model is independently selectable from the project
# default (MODEL_NAME) via GENERATOR_MODEL. Defaults to MODEL_NAME so
# existing behavior/output (the completed 60/60 gpt-oss-20b baseline) is
# untouched when the env var isn't set. Same pattern as
# llm_judge_synthetic_test.py's LLM_JUDGE_MODEL/JUDGE_MODEL_NAME.
GENERATOR_MODEL_NAME = os.getenv("GENERATOR_MODEL", MODEL_NAME)

llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=GENERATOR_MODEL_NAME, temperature=SAMPLING_TEMPERATURE)

N_SAMPLES = 3


def _output_path_for(generator_model: str) -> str:
    # Default model keeps the original path so the completed 60/60
    # gpt-oss-20b baseline and its checkpoint-resume history are never
    # touched. A different generator model writes to its own file instead
    # of overwriting or being conflated with the baseline result.
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_results.json"
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", generator_model).strip("_").lower()
    return f"experiments/results/selfcheckgpt_results_{slug}.json"


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
        "task": "SelfCheckGPT-style resampling-consistency baseline vs. deterministic/LLM-judge grounding checks",
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

    all_alerts = [{"class": "stated", **item} for item in STATED_ALERTS] + \
                 [{"class": "prompted", **item} for item in PROMPTED_ALERTS]

    # Resume from a prior checkpoint if one exists -- same free-tier daily
    # quota constraint as llm_judge_synthetic_test.py means this run can
    # also span more than one day. Skip any alert id already present in a
    # previous (possibly incomplete) run.
    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [item for item in all_alerts if item["alert"].alert_id not in done_ids]

    for i, item in enumerate(remaining):
        alert = item["alert"]
        print(f"[{len(results)+1}/{len(all_alerts)}] {alert.alert_id} ({item['class']})...")
        samples = sample_citations(llm, alert, extract_cves, n_samples=N_SAMPLES)
        score = consistency_score(samples)
        citation_occurred = score["majority_id"] is not None

        results.append({
            "alert_id": alert.alert_id,
            "class": item["class"],
            "expected_ungrounded": item["expected_ungrounded"],
            "ground_truth_cve": item["ground_truth_cve"],
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

        # Checkpoint after every alert -- a 60-alert x N-sample run against a
        # quota-pressured free tier can run long enough that a late failure
        # (rate-limit exhaustion, network blip) is a real risk; this way a
        # partial run still leaves usable, honestly-labeled (run_complete:
        # false) data on disk instead of losing everything.
        _write_output(all_alerts, results, complete=False)

    output = _write_output(all_alerts, results, complete=True)

    print(f"\n=== SelfCheckGPT summary (n_scored={output['n_scored']}, "
          f"{output['n_declined_every_sample']} declined every sample) ===")
    print(f"Accuracy={output['accuracy']}  Precision={output['precision']}  Recall={output['recall']}")
    print(f"Confusion matrix: {output['confusion_matrix']}")
    if output["stable_but_wrong_alert_ids"]:
        print(f"Stable-but-wrong (SelfCheckGPT's structural blind spot, see module docstring): "
              f"{output['stable_but_wrong_alert_ids']}")
    else:
        print("No stable-but-wrong cases observed in this run.")


if __name__ == "__main__":
    run()
