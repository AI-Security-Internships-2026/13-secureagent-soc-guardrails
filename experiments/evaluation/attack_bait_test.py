"""
experiments/evaluation/attack_bait_test.py

ATT&CK-technique equivalent of cve_bait_test.py: runs the ATT&CK-bait alert
set through the full pipeline and reports the same two distinct rates.

  - ungrounded rate: how often the model cited ANY ATT&CK technique ID not
    present in the input alert. Stays visible even when the citation turns
    out to be a real, on-topic technique — it's "did the model reach beyond
    what it was given," not "was it wrong."

  - requires-review rate: how often that ungrounded citation was actually
    suspicious — fabricated (not in the local MITRE snapshot), revoked
    (deprecated/superseded), real-but-irrelevant, or unverified (snapshot
    missing). For the ATT&CK checker every ungrounded citation requires
    review regardless of tier (see attack_grounding.py), so this rate is
    always equal to the ungrounded rate here — kept as a separate field
    anyway to mirror cve_bait_test.py's shape and stay consistent if that
    ever changes.

Deliberately computed from hallucinated_attack_techniques /
attack_technique_verifications specifically rather than the report's
combined output_guardrail_flagged/requires_review fields, so a bait alert
that happens to also trigger the CVE checker doesn't contaminate these
ATT&CK-specific rates.

Usage:
    python -m experiments.evaluation.attack_bait_test
"""

import json
import os

from src.agent.soc_agent import analyse_alert
from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS


def run():
    results = []

    for alert in ATTACK_BAIT_ALERTS:
        print(f"\nProcessing {alert.alert_id} ({alert.event_type})...")
        report = analyse_alert(alert)
        results.append(report)

        techniques = report.get("hallucinated_attack_techniques", [])
        if not techniques:
            print(f"  severity={report.get('severity_assessment')} | no ATT&CK technique cited / grounded")
        else:
            tiers = [v["classification"] for v in report.get("attack_technique_verifications", [])]
            print(f"  severity={report.get('severity_assessment')} | "
                  f"ungrounded technique(s): {techniques} | classification: {tiers}")

    # Mirrors attack_grounding.py's own rule: every ungrounded citation
    # requires review regardless of classification tier (REAL_AND_PLAUSIBLE
    # included — it's the most convincing-looking case, so it's exactly the
    # one an analyst is least likely to double-check unprompted). So this
    # is always equal to ungrounded_count here, kept as its own field only
    # to mirror cve_bait_test.py's output shape.
    ungrounded_count = sum(1 for r in results if r.get("hallucinated_attack_techniques"))
    review_count = ungrounded_count
    total = len(results)

    print(f"\nATT&CK hallucination test summary")
    print(f"Total bait alerts tested: {total}")
    print(f"Ungrounded technique citations (any ID not in input): {ungrounded_count} ({ungrounded_count/total:.1%})")
    print(f"Requires review (fabricated / revoked / irrelevant / unverified): {review_count} ({review_count/total:.1%})")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/attack_bait_results.json"
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
