"""
experiments/evaluation/soc_integration_cve_pool_test.py

Companion to soc_integration_test.py. That script's incidents come from
Secure_SOC_AI's rule engine, which has no CVE awareness at all (its 7 rules
are behavioral, not exploit-specific) — so it can only exercise MITRE ATT&CK
grounding, never CVE grounding. This script runs the separate CVE pool
(soc_integration/cve_pool.py: 15 real, NVD-verifiable CVEs x bait/stated
style x 2 victim variants = 60 alerts) through the same guardrailed pipeline
so CVE grounding gets tested at realistic scale instead of trivially passing
on empty input.

Distinct from cve_bait_test.py (n=6, deliberately adversarial, untouched) —
this is the larger, non-adversarial-scale companion, split "bait" (CVE
number withheld, tests spontaneous citation) vs "stated" (CVE number given
directly, tests whether grounding handles an already-correct citation).

Usage:
    python -m experiments.evaluation.soc_integration_cve_pool_test
"""

import json
import os

from experiments.evaluation.soc_integration.cve_pool import CVE_POOL_ALERTS
from src.agent.soc_agent import analyse_alert


def run():
    results = []
    for i, entry in enumerate(CVE_POOL_ALERTS, 1):
        alert = entry["alert"]
        print(f"[{i}/{len(CVE_POOL_ALERTS)}] {alert.alert_id} "
              f"({entry['ground_truth_cve']}, {entry['style']})...")
        report = analyse_alert(alert)
        results.append({
            "alert_id": alert.alert_id,
            "ground_truth_cve": entry["ground_truth_cve"],
            "cve_name": entry["cve_name"],
            "style": entry["style"],
            "report": report,
        })
        cves = report.get("hallucinated_cves", [])
        print(f"    severity={report.get('severity_assessment')} | ungrounded CVE: {cves or 'none'}")

    total = len(results)

    def rate(pred, subset=results):
        n = len(subset)
        return sum(1 for r in subset if pred(r)) / n if n else 0.0

    bait_results = [r for r in results if r["style"] == "bait"]
    stated_results = [r for r in results if r["style"] == "stated"]

    def cited_correct_cve(r):
        text = json.dumps(r["report"]).lower()
        return r["ground_truth_cve"].lower() in text

    summary = {
        "total_tested": total,
        "cve_ungrounded_rate_overall": rate(lambda r: r["report"].get("hallucinated_cves")),
        "requires_review_rate_overall": rate(lambda r: r["report"].get("requires_review")),
        "bait": {
            "n": len(bait_results),
            "cve_ungrounded_rate": rate(lambda r: r["report"].get("hallucinated_cves"), bait_results),
            "cited_ground_truth_cve_rate": rate(cited_correct_cve, bait_results),
        },
        "stated": {
            "n": len(stated_results),
            "cve_ungrounded_rate": rate(lambda r: r["report"].get("hallucinated_cves"), stated_results),
            "cited_ground_truth_cve_rate": rate(cited_correct_cve, stated_results),
        },
    }

    print("\nCVE pool test summary")
    print(f"Total alerts tested: {total}")
    print(f"Bait style   (n={summary['bait']['n']:2d}): ungrounded rate="
          f"{summary['bait']['cve_ungrounded_rate']:.1%} | cited ground-truth CVE="
          f"{summary['bait']['cited_ground_truth_cve_rate']:.1%}")
    print(f"Stated style (n={summary['stated']['n']:2d}): ungrounded rate="
          f"{summary['stated']['cve_ungrounded_rate']:.1%} | cited ground-truth CVE="
          f"{summary['stated']['cited_ground_truth_cve_rate']:.1%}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/soc_integration_cve_pool_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "source": "hand-authored, modeled on 15 real NVD-listed CVEs "
                       "(soc_integration/cve_pool.py); not from Secure_SOC_AI",
            "summary": summary,
            "results": results,
        }, f, indent=2, default=str)

    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    run()
