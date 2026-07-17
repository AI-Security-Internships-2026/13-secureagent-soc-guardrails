"""
experiments/evaluation/cve_bait_test.py

Runs the CVE-bait alert set through the full pipeline and reports how often
the output guardrail flags a hallucinated CVE. None of the bait alerts
contain a real CVE ID in their input, so any CVE-YYYY-NNNNN the model cites
in its report is by definition hallucinated (well-known vulns like Log4Shell
DO have real CVE numbers — CVE-2021-44228 — but the model was never given
that number, so producing it anyway demonstrates it's pulling from training
data/prior knowledge rather than grounding in the alert, which is exactly
the behaviour this guardrail exists to catch).

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

        flagged = report.get("output_guardrail_flagged")
        cves = report.get("hallucinated_cves", [])
        status = f"HALLUCINATED CVE(s): {cves}" if flagged else "no CVE cited / grounded"
        print(f"  severity={report.get('severity_assessment')} | {status}")

    flagged_count = sum(1 for r in results if r.get("output_guardrail_flagged"))
    total = len(results)

    print(f"\nCVE hallucination test summary")
    print(f"Total bait alerts tested: {total}")
    print(f"Flagged (hallucinated CVE cited): {flagged_count}")
    print(f"Hallucination rate: {flagged_count / total:.1%}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/cve_bait_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "total_tested": total,
            "flagged_count": flagged_count,
            "hallucination_rate": flagged_count / total,
            "results": results,
        }, f, indent=2)

    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    run()
