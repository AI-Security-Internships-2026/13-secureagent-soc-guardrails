"""
experiments/evaluation/selfcheckgpt_significance_test_attack.py

The ATT&CK-side counterpart of selfcheckgpt_significance_test.py (issue
#40/R1, Tasks 2-4). Same reasoning and harness as the CVE-side script:
generates ONE report per alert at SelfCheckGPT's sampling temperature
(not a re-run of SelfCheckGPT itself), runs the deterministic ATT&CK
grounding check (Stage 1 only -- verify_with_attack_data=False, since the
paired McNemar test only needs the grounding "flagged" decision, not the
Stage-2 authoritative-source verification) against the exact same 60-item
ATT&CK pool, and pairs the result against the matching
selfcheckgpt_results_attack[_<model>].json run for a McNemar test.

Adds two new statistics beyond the CVE-side script's original output
(issue #40 Task 4) -- Cohen's g and an odds-ratio point estimate + 95% CI
-- computed only for this new ATT&CK comparison. The CVE-side McNemar
files are intentionally left untouched here; backfilling them with the
same two columns is issue R6a's job, not this one's.

Usage:
    python -m experiments.evaluation.selfcheckgpt_significance_test_attack

    GENERATOR_MODEL override must match whatever selfcheckgpt_test_attack.py
    was run with, same convention as the CVE-side pair of scripts:

        GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_significance_test_attack
"""

import json
import os
import re

from dotenv import load_dotenv
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq
from scipy.stats import binomtest, chi2, norm

from src.agent.soc_agent import MODEL_NAME, SYSTEM_PROMPT, format_alert
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.attack_grounding import check_hallucinated_attack_techniques_verified
from src.guardrails.selfcheckgpt import SAMPLING_TEMPERATURE
from experiments.evaluation.selfcheckgpt_alerts_attack import STATED_ALERTS_ATTACK, PROMPTED_ALERTS_ATTACK

load_dotenv()

GENERATOR_MODEL_NAME = os.getenv("GENERATOR_MODEL", MODEL_NAME)


def _slug(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", model).strip("_").lower()


def _output_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_significance_results_attack.json"
    return f"experiments/results/selfcheckgpt_significance_results_attack_{_slug(generator_model)}.json"


def _selfcheckgpt_results_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_results_attack.json"
    return f"experiments/results/selfcheckgpt_results_attack_{_slug(generator_model)}.json"


def _mcnemar_output_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_vs_deterministic_mcnemar_ATTACK_gpt-oss-20b.json"
    return f"experiments/results/selfcheckgpt_vs_deterministic_mcnemar_ATTACK_{_slug(generator_model)}.json"


OUTPUT_PATH = _output_path_for(GENERATOR_MODEL_NAME)
SELFCHECKGPT_RESULTS_PATH = _selfcheckgpt_results_path_for(GENERATOR_MODEL_NAME)
MCNEMAR_OUTPUT_PATH = _mcnemar_output_path_for(GENERATOR_MODEL_NAME)

EXACT_THRESHOLD = 25

# See selfcheckgpt_test_attack.py's matching comment: qwen/qwen3.6-27b's
# current Groq OTPM cap (1000) is below LangChain's default max_tokens
# (2048), so it needs an explicit lower cap here too, to pair correctly
# against that script's run.
_MAX_TOKENS = 900 if "qwen" in GENERATOR_MODEL_NAME.lower() else None
llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=GENERATOR_MODEL_NAME, temperature=SAMPLING_TEMPERATURE,
                max_tokens=_MAX_TOKENS)


def _generate_report(alert) -> tuple:
    alert_text = format_alert(alert)
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Analyse this security alert and produce a threat report:\n{alert_text}"),
    ]
    response = llm.invoke(messages)
    raw_text = response.content
    try:
        report = json.loads(raw_text)
    except json.JSONDecodeError:
        report = {
            "threat_summary": raw_text,
            "recommended_action": "",
            "reasoning": "Agent failed to produce structured output",
        }
    return report, raw_text


def _write_output(results: list, complete: bool) -> dict:
    output = {
        "task": "Deterministic ATT&CK checker run at SelfCheckGPT's sampling temperature, for a paired McNemar test",
        "model": GENERATOR_MODEL_NAME,
        "sampling_temperature": SAMPLING_TEMPERATURE,
        "n_total": len(STATED_ALERTS_ATTACK) + len(PROMPTED_ALERTS_ATTACK),
        "n_completed": len(results),
        "run_complete": complete,
        "results": results,
    }
    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    return output


def run():
    print(f"Generator model: {GENERATOR_MODEL_NAME}")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Pairing against: {SELFCHECKGPT_RESULTS_PATH}\n")

    all_items = STATED_ALERTS_ATTACK + PROMPTED_ALERTS_ATTACK
    n_total = len(all_items)

    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [item for item in all_items if item["alert"].alert_id not in done_ids]

    print(f"Running {len(remaining)}/{n_total} remaining alerts at temperature={SAMPLING_TEMPERATURE}\n")

    for item in remaining:
        alert = item["alert"]
        print(f"[{len(results)+1}/{n_total}] {alert.alert_id}...")
        evidence_pack = build_evidence_pack(alert)
        report, raw_text = _generate_report(alert)

        attack_check = check_hallucinated_attack_techniques_verified(
            report, evidence_pack["text"], verify_with_attack_data=False,
        )

        results.append({
            "alert_id": alert.alert_id,
            "class": "stated" if item in STATED_ALERTS_ATTACK else "prompted",
            "expected_ungrounded": item["expected_ungrounded"],
            "ground_truth_technique": item["ground_truth_technique"],
            "is_revoked_id": item["is_revoked_id"],
            "deterministic_flagged_ungrounded": attack_check["flagged"],
            "ungrounded_attack_techniques": attack_check["ungrounded_attack_techniques"],
            "raw_report_text": raw_text,
        })
        correct = attack_check["flagged"] == item["expected_ungrounded"]
        print(f"    expected_ungrounded={item['expected_ungrounded']} | "
              f"deterministic_flagged={attack_check['flagged']} | {'agree' if correct else 'DISAGREE'}")

        _write_output(results, complete=False)

    output = _write_output(results, complete=(len(results) == n_total))
    print(f"\nresults saved to {OUTPUT_PATH}")

    if output["run_complete"]:
        _run_mcnemar(results)


def _wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (max(0.0, center - margin), min(1.0, center + margin))


def _run_mcnemar(det_results: list):
    if not os.path.exists(SELFCHECKGPT_RESULTS_PATH):
        print(f"\n{SELFCHECKGPT_RESULTS_PATH} not found -- cannot pair for McNemar.")
        return
    with open(SELFCHECKGPT_RESULTS_PATH) as f:
        scgpt = json.load(f)
    scgpt_by_id = {r["alert_id"]: r for r in scgpt["results"]}

    common_ids = sorted(set(r["alert_id"] for r in det_results) & set(scgpt_by_id))
    det_by_id = {r["alert_id"]: r for r in det_results}

    both_correct = det_only_correct = scgpt_only_correct = both_incorrect = 0
    skipped_declined = 0
    for aid in common_ids:
        d = det_by_id[aid]
        s = scgpt_by_id[aid]
        if not s["samples"] or all(not sample for sample in s["samples"]):
            skipped_declined += 1
            continue
        det_correct = d["deterministic_flagged_ungrounded"] == d["expected_ungrounded"]
        scgpt_correct = s["flagged_unstable"] == s["expected_ungrounded"]
        if det_correct and scgpt_correct:
            both_correct += 1
        elif det_correct and not scgpt_correct:
            det_only_correct += 1
        elif not det_correct and scgpt_correct:
            scgpt_only_correct += 1
        else:
            both_incorrect += 1

    n = both_correct + det_only_correct + scgpt_only_correct + both_incorrect
    b, c = det_only_correct, scgpt_only_correct
    discordant = b + c

    if discordant == 0:
        method, statistic, p_value = "degenerate", 0.0, 1.0
    elif discordant < EXACT_THRESHOLD:
        method = "exact_binomial"
        result = binomtest(b, discordant, 0.5, alternative="two-sided")
        statistic, p_value = None, result.pvalue
    else:
        method = "chi_square_continuity_corrected"
        statistic = (abs(b - c) - 1) ** 2 / discordant
        p_value = 1 - chi2.cdf(statistic, df=1)

    # Task 4: Cohen's g and an odds-ratio point estimate + 95% CI, derived
    # by taking the Wilson-score CI on the proportion b/(b+c) and
    # transforming its endpoints through the odds transform p/(1-p) --
    # the conditional-MLE odds ratio for McNemar's test is b/c itself,
    # so this keeps the point estimate and CI internally consistent.
    if discordant == 0:
        cohens_g = 0.0
        odds_ratio_point = None
        odds_ratio_95ci_low = odds_ratio_95ci_high = None
    else:
        cohens_g = (b - c) / discordant
        lo, hi = _wilson_ci(b, discordant)
        odds_ratio_point = (b / c) if c > 0 else float("inf")
        odds_ratio_95ci_low = (lo / (1 - lo)) if lo < 0.999999 else float("inf")
        # A zero discordant cell (b or c == 0) makes the true odds ratio
        # mathematically infinite/undefined -- report it as such rather
        # than a huge-but-finite float artifact from Wilson's upper bound
        # rounding to just under 1.0 (1/(1-hi) blows up near that edge).
        odds_ratio_95ci_high = (hi / (1 - hi)) if (hi < 0.999999 and c > 0) else float("inf")

    output = {
        "task": "McNemar's test: deterministic checker vs. SelfCheckGPT, paired on the same ATT&CK alerts",
        "citation_family": "ATT&CK",
        "model": GENERATOR_MODEL_NAME,
        "n_samples": n,
        "n_excluded_declined_every_sample": skipped_declined,
        "contingency": {
            "both_correct": both_correct,
            "deterministic_only_correct": det_only_correct,
            "selfcheckgpt_only_correct": scgpt_only_correct,
            "both_incorrect": both_incorrect,
        },
        "discordant_pairs": discordant,
        "method": method,
        "statistic": float(statistic) if statistic is not None else None,
        "p_value": float(p_value),
        "significant_at_0.05": bool(p_value < 0.05),
        "cohens_g": round(cohens_g, 4),
        "odds_ratio_point": (round(odds_ratio_point, 4) if odds_ratio_point not in (None, float("inf")) else odds_ratio_point),
        "odds_ratio_95ci_low": (round(odds_ratio_95ci_low, 4) if odds_ratio_95ci_low not in (None, float("inf")) else odds_ratio_95ci_low),
        "odds_ratio_95ci_high": (round(odds_ratio_95ci_high, 4) if odds_ratio_95ci_high not in (None, float("inf")) else odds_ratio_95ci_high),
    }

    with open(MCNEMAR_OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n=== McNemar (ATT&CK): deterministic vs. SelfCheckGPT (n={n}) ===")
    print(f"both correct={both_correct}  deterministic-only={det_only_correct}  "
          f"selfcheckgpt-only={scgpt_only_correct}  both wrong={both_incorrect}")
    print(f"method={method}  p={p_value:.6f}  ({'SIGNIFICANT' if p_value < 0.05 else 'not significant'} at alpha=0.05)")
    print(f"Cohen's g={output['cohens_g']}  odds ratio={output['odds_ratio_point']} "
          f"[{output['odds_ratio_95ci_low']}, {output['odds_ratio_95ci_high']}]")
    print(f"\nresults saved to {MCNEMAR_OUTPUT_PATH}")


if __name__ == "__main__":
    run()
