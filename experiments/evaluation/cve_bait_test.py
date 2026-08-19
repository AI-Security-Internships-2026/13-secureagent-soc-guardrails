"""
experiments/evaluation/cve_bait_test.py

Runs the (now 25-alert, see cve_bait_alerts.py) CVE-bait set through the
full pipeline and reports:

  - ungrounded rate: how often the model cited ANY CVE not present in the
    input alert (output_guardrail_flagged). This stays visible even when
    the citation turns out to be correct -- it's "did the model reach
    beyond what it was given," not "was it wrong."

  - requires-review rate: how often that citation was flagged for review.
    As of the requires_review unconditional-flag fix (see
    src/guardrails/output_guardrail.py, docs/ROADMAP_PLAN.md sec.3 item 1),
    this is now IDENTICAL to the ungrounded rate by construction --
    every ungrounded citation requires review regardless of classification,
    including REAL_AND_PLAUSIBLE. Both rates are still reported separately
    so a divergence between them (which would indicate the unconditional
    flag logic regressed) is immediately visible rather than silently
    passing.

  - correct-citation rate: of the ungrounded citations, how many named the
    actual real CVE for that alert's behavior (per EXPECTED_CVE in
    cve_bait_alerts.py) versus a wrong or fabricated one. Mirrors the
    bait/stated distinction already used in
    experiments/evaluation/soc_integration/cve_pool.py.

Usage:
    python -m experiments.evaluation.cve_bait_test
"""

import json
import os

from src.agent.soc_agent import analyse_alert
from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS, EXPECTED_CVE


def run():
    results = []

    for alert in CVE_BAIT_ALERTS:
        print(f"\nProcessing {alert.alert_id} ({alert.event_type})...")
        report = analyse_alert(alert)
        report["expected_cve"] = EXPECTED_CVE[alert.alert_id]
        results.append(report)

        cves = report.get("hallucinated_cves", [])
        if not cves:
            print(f"  severity={report.get('severity_assessment')} | no CVE cited / grounded")
        else:
            tiers = [v["classification"] for v in report.get("cve_verifications", [])]
            correct = EXPECTED_CVE[alert.alert_id] in cves
            print(f"  severity={report.get('severity_assessment')} | "
                  f"ungrounded CVE(s): {cves} | classification: {tiers} | "
                  f"correct citation: {correct}")

    ungrounded_count = sum(1 for r in results if r.get("output_guardrail_flagged"))
    review_count = sum(1 for r in results if r.get("requires_review"))
    correct_count = sum(
        1 for r in results
        if r.get("output_guardrail_flagged") and r["expected_cve"] in r.get("hallucinated_cves", [])
    )
    total = len(results)

    print(f"\nCVE hallucination test summary")
    print(f"Total bait alerts tested: {total}")
    print(f"Ungrounded CVE citations (any CVE not in input): {ungrounded_count} ({ungrounded_count/total:.1%})")
    print(f"Requires review: {review_count} ({review_count/total:.1%})")
    if ungrounded_count != review_count:
        print(f"  WARNING: ungrounded_count != review_count -- the unconditional "
              f"requires_review flag (every ungrounded citation should require review) "
              f"may have regressed. Check output_guardrail.py before trusting this run.")
    print(f"Of the ungrounded citations, named the correct real CVE: "
          f"{correct_count}/{ungrounded_count if ungrounded_count else 0}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/cve_bait_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "total_tested": total,
            "ungrounded_count": ungrounded_count,
            "ungrounded_rate": ungrounded_count / total,
            "requires_review_count": review_count,
            "requires_review_rate": review_count / total,
            "correct_citation_count": correct_count,
            "results": results,
        }, f, indent=2)

    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    run()