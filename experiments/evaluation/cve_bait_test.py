"""
experiments/evaluation/cve_bait_test.py

Runs the (now 25-alert, see cve_bait_alerts.py) CVE-bait set through the
full pipeline and reports:

  - ungrounded rate: how often the model cited ANY CVE not present in the
    input alert -- based on `hallucinated_cves` directly, not on
    `output_guardrail_flagged`. This stays visible even when the citation
    turns out to be correct -- it's "did the model reach beyond what it
    was given," not "was it wrong."

  - requires-review rate: how often the *report* was flagged for review
    for any reason -- CVE grounding OR the PII redaction guardrail
    (they're OR'd together in soc_agent.py by design, see
    docs/ROADMAP_PLAN.md sec.5's PII redaction row). This is a genuinely
    different, broader signal than the ungrounded rate above, and the two
    are reported separately with the gap between them broken out
    explicitly (`pii_only_review_count`) rather than assumed equal --
    at n=150 (2026-08-25 expansion), 3 of the 5 review-flagged reports
    were PII-only (single-word product names like "Zimbra"/"Ray"/"Joomla"
    misread as PERSON by the small spaCy NER model, the same known false-
    positive class as docs/all_results.md #35/#39/#42), not a CVE
    hallucination at all. An earlier version of this script conflated the
    two by computing "ungrounded" from output_guardrail_flagged, which
    happened to equal the CVE-only count at n=100 by coincidence (no
    product name in the original 100 alerts tripped the PII false
    positive) but silently stopped being true once the PII guardrail's
    OR-wiring interacted with a larger, more varied product-name pool --
    exactly the kind of blended-metric bug that's easy to miss without
    checking individual detections first.

  - correct-citation rate: of the ungrounded citations, how many named the
    actual real CVE for that alert's behavior (per EXPECTED_CVE in
    cve_bait_alerts.py) versus a wrong or fabricated one. Mirrors the
    bait/stated distinction already used in
    experiments/evaluation/soc_integration/cve_pool.py.

Checkpointed after every alert -- same resume-from-checkpoint pattern as
attack_bait_test.py / llm_judge_synthetic_test.py / selfcheckgpt_test.py
(docs/all_results.md #26/#29): a 150-call run against a quota-pressured
free tier can run long enough that a mid-run failure (rate-limit
exhaustion, network blip) is a real risk. Re-running this script picks up
from the last checkpoint instead of re-processing already-completed
alerts from scratch (added 2026-08-25 alongside the 100 -> 150 expansion).

Usage:
    python -m experiments.evaluation.cve_bait_test
"""

import json
import os

from src.agent.soc_agent import analyse_alert
from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS, EXPECTED_CVE

OUTPUT_PATH = "experiments/results/cve_bait_results.json"


def _write_output(results: list, total_target: int) -> dict:
    ungrounded_count = sum(1 for r in results if r.get("hallucinated_cves"))
    review_count = sum(1 for r in results if r.get("requires_review"))
    pii_only_review_count = sum(
        1 for r in results
        if r.get("requires_review") and not r.get("hallucinated_cves")
    )
    correct_count = sum(
        1 for r in results
        if r.get("hallucinated_cves") and r["expected_cve"] in r["hallucinated_cves"]
    )
    total = len(results)

    output = {
        "total_tested": total,
        "run_complete": total == total_target,
        "ungrounded_count": ungrounded_count,
        "ungrounded_rate": ungrounded_count / total if total else None,
        "requires_review_count": review_count,
        "requires_review_rate": review_count / total if total else None,
        "pii_only_review_count": pii_only_review_count,
        "correct_citation_count": correct_count,
        "results": results,
    }

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    return output


def run():
    # Resume from a prior checkpoint if one exists.
    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [a for a in CVE_BAIT_ALERTS if a.alert_id not in done_ids]

    for alert in remaining:
        print(f"\n[{len(results)+1}/{len(CVE_BAIT_ALERTS)}] Processing {alert.alert_id} ({alert.event_type})...")
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

        _write_output(results, len(CVE_BAIT_ALERTS))

    output = _write_output(results, len(CVE_BAIT_ALERTS))
    total = output["total_tested"]
    ungrounded_count = output["ungrounded_count"]
    review_count = output["requires_review_count"]
    pii_only_review_count = output["pii_only_review_count"]
    correct_count = output["correct_citation_count"]

    print(f"\nCVE hallucination test summary")
    print(f"Total bait alerts tested: {total}")
    print(f"Ungrounded CVE citations (any CVE not in input): {ungrounded_count} ({ungrounded_count/total:.1%})")
    print(f"Requires review (CVE grounding OR PII): {review_count} ({review_count/total:.1%})")
    if pii_only_review_count:
        print(f"  of which {pii_only_review_count} flagged for PII only, no CVE hallucination "
              f"-- not counted in the ungrounded rate above")
    if review_count < ungrounded_count:
        print(f"  WARNING: requires_review_count < ungrounded_count -- the unconditional "
              f"requires_review flag (every ungrounded citation should require review) "
              f"may have regressed. Check output_guardrail.py before trusting this run.")
    print(f"Of the ungrounded citations, named the correct real CVE: "
          f"{correct_count}/{ungrounded_count if ungrounded_count else 0}")

    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()