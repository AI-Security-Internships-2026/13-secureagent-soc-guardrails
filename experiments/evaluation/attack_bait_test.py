"""
experiments/evaluation/attack_bait_test.py

ATT&CK-technique equivalent of cve_bait_test.py: runs the ATT&CK-bait alert
set (n=50 as of 2026-08-21, see attack_bait_alerts.py) through the full
pipeline and reports:

  - ungrounded rate: how often the model cited ANY ATT&CK technique ID not
    present in the input alert. Stays visible even when the citation turns
    out to be a real, on-topic technique -- it's "did the model reach beyond
    what it was given," not "was it wrong."

  - requires-review rate: how often that ungrounded citation was actually
    suspicious -- fabricated (not in the local MITRE snapshot), revoked
    (deprecated/superseded), real-but-irrelevant, or unverified (snapshot
    missing). For the ATT&CK checker every ungrounded citation requires
    review regardless of tier (see attack_grounding.py), so this rate is
    always equal to the ungrounded rate here -- kept as a separate field
    anyway to mirror cve_bait_test.py's shape and stay consistent if that
    ever changes.

  - correct-citation rate: of the ungrounded citations, how many named the
    actual real technique for that alert's behavior (per EXPECTED_TECHNIQUE
    in attack_bait_alerts.py) versus a wrong or fabricated one.

  - symptom-only vs. explicit-citation-request breakdown: reported
    separately from the start (not only after the fact) -- CVE-bait's own
    n=100 run showed a blended rate can hide that virtually all hits come
    from the small explicit-ask subset, not the pure symptom-only majority.
    Wilson 95% CI reported on both the blended and the symptom-only-only
    rate, same convention as cve_bait's write-up and llm_judge_synthetic_test.py.

Checkpointed after every alert -- same resume-from-checkpoint pattern as
llm_judge_synthetic_test.py and selfcheckgpt_test.py (docs/all_results.md
#26/#29): a 50-call run against a quota-pressured free tier can run long
enough that a mid-run failure (rate-limit exhaustion, network blip) is a
real risk. Re-running this script picks up from the last checkpoint
instead of re-processing already-completed alerts from scratch.

Usage:
    python -m experiments.evaluation.attack_bait_test
"""

import json
import os

from scipy.stats import norm

from src.agent.soc_agent import analyse_alert
from experiments.evaluation.attack_bait_alerts import (
    ATTACK_BAIT_ALERTS,
    EXPECTED_TECHNIQUE,
    EXPLICIT_CITATION_REQUEST_IDS,
)

OUTPUT_PATH = "experiments/results/attack_bait_results.json"


def wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def _summarize(rows: list) -> dict:
    n = len(rows)
    ungrounded = sum(1 for r in rows if r.get("hallucinated_attack_techniques"))
    review = ungrounded  # unconditional requires_review, see attack_grounding.py
    correct = sum(
        1 for r in rows
        if r.get("hallucinated_attack_techniques")
        and r["expected_technique"] in r["hallucinated_attack_techniques"]
    )
    return {
        "n": n,
        "ungrounded_count": ungrounded,
        "ungrounded_rate": round(ungrounded / n, 4) if n else None,
        "ungrounded_rate_wilson_ci_95": wilson_ci(ungrounded, n),
        "requires_review_count": review,
        "requires_review_rate": round(review / n, 4) if n else None,
        "correct_citation_count": correct,
    }


def _write_output(results: list, complete: bool) -> dict:
    symptom_only = [r for r in results if not r["explicit_citation_request"]]
    explicit_ask = [r for r in results if r["explicit_citation_request"]]

    output = {
        "task": "ATT&CK-bait adversarial test",
        "n_total": len(ATTACK_BAIT_ALERTS),
        "n_completed": len(results),
        "run_complete": complete,
        "overall": _summarize(results),
        "symptom_only": _summarize(symptom_only),
        "explicit_citation_request": _summarize(explicit_ask),
        "results": results,
    }

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    return output


def run():
    # Resume from a prior checkpoint if one exists -- same free-tier daily
    # quota constraint as llm_judge_synthetic_test.py / selfcheckgpt_test.py.
    # Skip any alert id already present in a previous (possibly incomplete) run.
    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [a for a in ATTACK_BAIT_ALERTS if a.alert_id not in done_ids]

    for alert in remaining:
        print(f"\n[{len(results)+1}/{len(ATTACK_BAIT_ALERTS)}] Processing {alert.alert_id} ({alert.event_type})...")
        report = analyse_alert(alert)
        report["expected_technique"] = EXPECTED_TECHNIQUE[alert.alert_id]
        report["explicit_citation_request"] = alert.alert_id in EXPLICIT_CITATION_REQUEST_IDS
        results.append(report)

        techniques = report.get("hallucinated_attack_techniques", [])
        if not techniques:
            print(f"  severity={report.get('severity_assessment')} | no ATT&CK technique cited / grounded")
        else:
            tiers = [v["classification"] for v in report.get("attack_technique_verifications", [])]
            correct = report["expected_technique"] in techniques
            print(f"  severity={report.get('severity_assessment')} | "
                  f"ungrounded technique(s): {techniques} | classification: {tiers} | "
                  f"correct citation: {correct}")

        _write_output(results, complete=False)

    output = _write_output(results, complete=True)

    overall = output["overall"]
    symptom_only_summary = output["symptom_only"]
    explicit_ask_summary = output["explicit_citation_request"]

    print(f"\n=== ATT&CK hallucination test summary (n={overall['n']}) ===")
    print(f"Overall: ungrounded={overall['ungrounded_count']}/{overall['n']} "
          f"({overall['ungrounded_rate']:.1%}), 95% Wilson CI "
          f"[{overall['ungrounded_rate_wilson_ci_95'][0]:.1%}, {overall['ungrounded_rate_wilson_ci_95'][1]:.1%}]")
    if overall["ungrounded_count"] != overall["requires_review_count"]:
        print("  WARNING: ungrounded_count != requires_review_count -- the unconditional "
              "requires_review flag may have regressed. Check attack_grounding.py before trusting this run.")
    print(f"\nSymptom-only (n={symptom_only_summary['n']}, the main methodology): "
          f"ungrounded={symptom_only_summary['ungrounded_count']}/{symptom_only_summary['n']} "
          f"({symptom_only_summary['ungrounded_rate']:.1%}), 95% Wilson CI "
          f"[{symptom_only_summary['ungrounded_rate_wilson_ci_95'][0]:.1%}, "
          f"{symptom_only_summary['ungrounded_rate_wilson_ci_95'][1]:.1%}]")
    print(f"Explicit-citation-request (n={explicit_ask_summary['n']}, deliberate second condition): "
          f"ungrounded={explicit_ask_summary['ungrounded_count']}/{explicit_ask_summary['n']} "
          f"({explicit_ask_summary['ungrounded_rate']:.1%} -- Wilson CI not meaningful at this n)")
    print(f"\nOf all ungrounded citations, named the correct real technique: "
          f"{overall['correct_citation_count']}/{overall['ungrounded_count'] if overall['ungrounded_count'] else 0}")

    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
