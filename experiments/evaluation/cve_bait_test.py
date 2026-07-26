"""
experiments/evaluation/cve_bait_test.py

Runs the CVE-bait alert set through the full pipeline and reports two
distinct rates rather than one collapsed number:

  - ungrounded rate: how often the model cited ANY CVE not present in the
    input alert (output_guardrail_flagged). This stays visible even when
    the citation turns out to be correct — it's "did the model reach
    beyond what it was given," not "was it wrong."

  - requires-review rate: how often that ungrounded citation was actually
    suspicious — fabricated (doesn't exist in NVD), real-but-irrelevant
    (real CVE, wrong context), or unverified (NVD lookup failed). A
    REAL_AND_PLAUSIBLE-only result leaves this at 0 even though the
    ungrounded rate is nonzero — that's the intended distinction, not a bug.

Usage:
    python -m experiments.evaluation.cve_bait_test
"""

import json
import os

from src.agent.soc_agent import analyse_alert
from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS


def run():
    results = []

    for alert in CVE_BAIT_ALERTS:
        print(f"\nProcessing {alert.alert_id} ({alert.event_type})...")
        report = analyse_alert(alert)
        results.append(report)

        cves = report.get("hallucinated_cves", [])
        if not cves:
            print(f"  severity={report.get('severity_assessment')} | no CVE cited / grounded")
        else:
            tiers = [v["classification"] for v in report.get("cve_verifications", [])]
            print(f"  severity={report.get('severity_assessment')} | "
                  f"ungrounded CVE(s): {cves} | classification: {tiers}")

    ungrounded_count = sum(1 for r in results if r.get("output_guardrail_flagged"))
    review_count = sum(1 for r in results if r.get("requires_review"))
    total = len(results)

    print(f"\nCVE hallucination test summary")
    print(f"Total bait alerts tested: {total}")
    print(f"Ungrounded CVE citations (any CVE not in input): {ungrounded_count} ({ungrounded_count/total:.1%})")
    print(f"Requires review (fabricated / wrong / unverified): {review_count} ({review_count/total:.1%})")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/cve_bait_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "total_tested": total,
            "ungrounded_count": ungrounded_count,
            "ungrounded_rate": ungrounded_count / total,
            "requires_review_count": review_count,
            "requires_review_rate": review_count / total,
            "results": results,
        }, f, indent=2)

    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    run()