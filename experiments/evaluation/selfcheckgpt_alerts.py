"""
experiments/evaluation/selfcheckgpt_alerts.py

Alert set for the SelfCheckGPT-style comparison (issue #20 sec.3 item 8,
docs/ROADMAP_PLAN.md). SelfCheckGPT (Manakul et al.) tests a different
signal than this project's grounding checks: not "is this claim supported
by the input evidence" (that's what output_guardrail.py / attack_grounding.py
/ llm_judge.py all test), but "does the model keep making the SAME claim
when resampled at temperature > 0." The hypothesis: a claim the model
actually 'knows' should recur consistently across samples; a confabulated
one should be unstable.

Reuses this project's existing bait/stated methodology
(experiments/evaluation/soc_integration/cve_pool.py) rather than authoring
new content, since that methodology already produces exactly the two
classes SelfCheckGPT needs to be tested against:

  STATED_ALERTS (n=30): cve_pool.py's own "stated" style, unchanged -- the
    CVE is given directly in the alert (as a scanner/EDR would report it).
    Expected class: GROUNDED. A model that just echoes a given fact back
    should be highly self-consistent across resamples -- this is the
    "should recur reliably" case SelfCheckGPT is designed to pass.

  PROMPTED_ALERTS (n=30): derived from cve_pool.py's "bait" style (the CVE
    withheld) by appending the same explicit citation-request phrasing
    already used in cve_bait_alerts.py's BAIT-002/BAIT-011/BAIT-017 ("cite
    the specific CVE identifier... in your reasoning field"). Expected
    class: UNGROUNDED -- any CVE cited here is, by the same rule the
    deterministic checker already applies, not present in the alert's
    evidence regardless of whether it happens to be factually correct.
    Whether the model's answer is STABLE or not under resampling is the
    open empirical question this comparison actually tests -- a model with
    a strong (but wrong) training-data association could be perfectly
    consistent and still wrong, which SelfCheckGPT alone cannot catch. See
    docs/all_results.md for whether that failure mode actually showed up.

CVE-side only. No "stated"-style ATT&CK alert set exists anywhere in this
project (attack_bait_alerts.py's 6 alerts are all "bait"/"prompted" style,
no CVE-pool-style ATT&CK equivalent has been built) -- noted as a real
scoping gap, not silently dropped. Building one is a natural follow-up if
this comparison proves useful enough to extend.
"""

import dataclasses

from experiments.evaluation.soc_integration.cve_pool import CVE_POOL_ALERTS

CITATION_REQUEST_SUFFIX = (
    " Please cite the specific CVE identifier for this behavior in your "
    "reasoning field so it can be cross-referenced in the ticketing system."
)

STATED_ALERTS = [
    {
        "alert": item["alert"],
        "ground_truth_cve": item["ground_truth_cve"],
        "cve_name": item["cve_name"],
        "expected_ungrounded": False,
    }
    for item in CVE_POOL_ALERTS
    if item["style"] == "stated"
]

PROMPTED_ALERTS = [
    {
        "alert": dataclasses.replace(
            item["alert"],
            alert_id=item["alert"].alert_id.replace("CVEPOOL-", "SELFCHECK-PROMPTED-"),
            description=item["alert"].description + CITATION_REQUEST_SUFFIX,
        ),
        "ground_truth_cve": item["ground_truth_cve"],
        "cve_name": item["cve_name"],
        "expected_ungrounded": True,
    }
    for item in CVE_POOL_ALERTS
    if item["style"] == "bait"
]

if __name__ == "__main__":
    print(f"{len(STATED_ALERTS)} stated alerts, {len(PROMPTED_ALERTS)} prompted alerts")
