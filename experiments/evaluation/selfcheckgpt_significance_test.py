"""
experiments/evaluation/selfcheckgpt_significance_test.py

Closes out Sect. 4.10's deterministic-vs-SelfCheckGPT paired significance
test (docs/ROADMAP_PLAN.md, docs/all_results.md #34/#37) -- the one piece
that was blocked because selfcheckgpt_test.py's sample_citations() only
ever persisted extracted citation IDs, never the raw generated report
text, so the deterministic checker had nothing to run on retroactively.

This is a SEPARATE, cheaper run, not a re-run of SelfCheckGPT itself:
SelfCheckGPT needs 3 resamples per alert to measure self-consistency (that
result, in experiments/results/selfcheckgpt_results.json, is complete and
untouched by this script). The deterministic checker doesn't need
resampling at all -- it just needs ONE generated report per alert to check
grounding against. So this generates 1 sample per alert (60 calls, not
180) at the SAME temperature=0.7 SelfCheckGPT used (selfcheckgpt.py's
SAMPLING_TEMPERATURE), over the exact same 60-alert set
(selfcheckgpt_alerts.py's STATED_ALERTS + PROMPTED_ALERTS), and this time
saves the raw report text alongside the verdict -- so this gap can't
recur if the comparison ever needs re-checking.

verify_with_nvd=False: check_hallucinated_cves_verified()'s "flagged"
field (which this script actually needs) is a pure Stage-1 grounding
decision -- is the cited CVE present in the alert's own evidence text --
computed before and independent of the Stage-2 NVD lookup. Skipping NVD
entirely avoids a second rate-limited API dependency for a value ("flagged")
that doesn't depend on it, not a correctness shortcut.

McNemar pairs, for each of the 60 (or however many are scored) alerts:
  - deterministic checker correct?  cve_check["flagged"] == expected_ungrounded
  - SelfCheckGPT correct?           flagged_unstable == expected_ungrounded
                                     (pulled from the already-complete
                                     selfcheckgpt_results.json, not re-run)
against the SAME ground truth (expected_ungrounded), reusing the exact
mcnemar()/holm_bonferroni() implementation already built and used in
experiments/evaluation/guardrail_comparison/significance_test.py.

Usage:
    python -m experiments.evaluation.selfcheckgpt_significance_test

    Report-generation model defaults to MODEL_NAME (src/agent/soc_agent.py,
    openai/gpt-oss-20b), same as selfcheckgpt_test.py. Set GENERATOR_MODEL
    to the same alternate model used for that script's run (e.g.
    "qwen/qwen3.6-27b") to generate the matching deterministic-checker data
    and pair it against that model's SelfCheckGPT results instead of the
    gpt-oss-20b baseline:

        GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_significance_test

    Writes to its own results/McNemar files (*_<model>.json) rather than
    overwriting the completed gpt-oss-20b baseline.
"""

import json
import os
import re

from dotenv import load_dotenv
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq
from scipy.stats import binomtest, chi2

from src.agent.soc_agent import MODEL_NAME, SYSTEM_PROMPT, format_alert
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.output_guardrail import check_hallucinated_cves_verified
from src.guardrails.selfcheckgpt import SAMPLING_TEMPERATURE
from experiments.evaluation.selfcheckgpt_alerts import STATED_ALERTS, PROMPTED_ALERTS

load_dotenv()

# Report-generation model is independently selectable from the project
# default (MODEL_NAME) via GENERATOR_MODEL -- must match whatever
# selfcheckgpt_test.py was run with, so the two get paired correctly below.
GENERATOR_MODEL_NAME = os.getenv("GENERATOR_MODEL", MODEL_NAME)


def _slug(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", model).strip("_").lower()


def _output_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_significance_results.json"
    return f"experiments/results/selfcheckgpt_significance_results_{_slug(generator_model)}.json"


def _selfcheckgpt_results_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_results.json"
    return f"experiments/results/selfcheckgpt_results_{_slug(generator_model)}.json"


def _mcnemar_output_path_for(generator_model: str) -> str:
    if generator_model == MODEL_NAME:
        return "experiments/results/selfcheckgpt_vs_deterministic_mcnemar.json"
    return f"experiments/results/selfcheckgpt_vs_deterministic_mcnemar_{_slug(generator_model)}.json"


OUTPUT_PATH = _output_path_for(GENERATOR_MODEL_NAME)
SELFCHECKGPT_RESULTS_PATH = _selfcheckgpt_results_path_for(GENERATOR_MODEL_NAME)
MCNEMAR_OUTPUT_PATH = _mcnemar_output_path_for(GENERATOR_MODEL_NAME)

EXACT_THRESHOLD = 25  # same convention as guardrail_comparison/significance_test.py

llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=GENERATOR_MODEL_NAME, temperature=SAMPLING_TEMPERATURE)


def _generate_report(alert) -> tuple:
    """Returns (report_dict, raw_text). Same parse-with-fallback pattern as soc_agent.analyse_alert()."""
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
        "task": "Deterministic checker run at SelfCheckGPT's sampling temperature, for a paired McNemar test",
        "model": GENERATOR_MODEL_NAME,
        "sampling_temperature": SAMPLING_TEMPERATURE,
        "n_total": len(STATED_ALERTS) + len(PROMPTED_ALERTS),
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

    all_items = STATED_ALERTS + PROMPTED_ALERTS
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

        cve_check = check_hallucinated_cves_verified(report, evidence_pack["text"], verify_with_nvd=False)

        results.append({
            "alert_id": alert.alert_id,
            "class": "stated" if item in STATED_ALERTS else "prompted",
            "expected_ungrounded": item["expected_ungrounded"],
            "ground_truth_cve": item["ground_truth_cve"],
            "deterministic_flagged_ungrounded": cve_check["flagged"],
            "ungrounded_cves": cve_check["ungrounded_cves"],
            "raw_report_text": raw_text,
        })
        correct = cve_check["flagged"] == item["expected_ungrounded"]
        print(f"    expected_ungrounded={item['expected_ungrounded']} | "
              f"deterministic_flagged={cve_check['flagged']} | {'agree' if correct else 'DISAGREE'}")

        _write_output(results, complete=False)

    output = _write_output(results, complete=(len(results) == n_total))
    print(f"\nresults saved to {OUTPUT_PATH}")

    if output["run_complete"]:
        _run_mcnemar(results)


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
        # SelfCheckGPT's own scoring excludes alerts where every resample
        # declined to cite anything -- match that exclusion here so both
        # sides are scored on the exact same alert set.
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
    discordant = det_only_correct + scgpt_only_correct

    if discordant == 0:
        method, statistic, p_value = "degenerate", 0.0, 1.0
    elif discordant < EXACT_THRESHOLD:
        method = "exact_binomial"
        result = binomtest(det_only_correct, discordant, 0.5, alternative="two-sided")
        statistic, p_value = None, result.pvalue
    else:
        method = "chi_square_continuity_corrected"
        statistic = (abs(det_only_correct - scgpt_only_correct) - 1) ** 2 / discordant
        p_value = 1 - chi2.cdf(statistic, df=1)

    output = {
        "task": "McNemar's test: deterministic checker vs. SelfCheckGPT, paired on the same alerts",
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
    }

    with open(MCNEMAR_OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n=== McNemar: deterministic vs. SelfCheckGPT (n={n}) ===")
    print(f"both correct={both_correct}  deterministic-only={det_only_correct}  "
          f"selfcheckgpt-only={scgpt_only_correct}  both wrong={both_incorrect}")
    print(f"method={method}  p={p_value:.6f}  ({'SIGNIFICANT' if p_value < 0.05 else 'not significant'} at alpha=0.05)")
    print(f"\nresults saved to {MCNEMAR_OUTPUT_PATH}")


if __name__ == "__main__":
    run()
