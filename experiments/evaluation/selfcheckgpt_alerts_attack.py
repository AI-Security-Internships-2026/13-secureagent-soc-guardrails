"""
experiments/evaluation/selfcheckgpt_alerts_attack.py

The ATT&CK-side counterpart of selfcheckgpt_alerts.py (issue #40/R1),
mirroring its exact CVE-side structure and reasoning but built on
attack_bait_pool.py's 60-item ATT&CK pool instead of cve_pool.py's CVE
pool. See attack_bait_pool.py's own docstring for how that pool is built
and why 3 of its "stated" items deliberately use a revoked technique ID.

  STATED_ALERTS_ATTACK (n=30): attack_bait_pool.py's "stated" style,
    unchanged -- the technique ID is given directly in the alert, as a
    SIEM/EDR correlation rule would report it. Expected class: GROUNDED.

  PROMPTED_ALERTS_ATTACK (n=30): derived from attack_bait_pool.py's "bait"
    style (the technique ID withheld) by appending the same explicit
    citation-request phrasing selfcheckgpt_alerts.py already uses for CVEs,
    adapted for technique IDs. Expected class: UNGROUNDED -- any technique
    ID cited here is not present in the alert's evidence, regardless of
    whether it happens to be a real, on-topic technique.
"""

import dataclasses

from experiments.evaluation.attack_bait_pool import ATTACK_POOL_ALERTS

CITATION_REQUEST_SUFFIX = (
    " Please cite the specific MITRE ATT&CK technique ID for this "
    "behavior in your reasoning field so it can be cross-referenced in "
    "the ticketing system."
)

STATED_ALERTS_ATTACK = [
    {
        "alert": item["alert"],
        "ground_truth_technique": item["ground_truth_technique"],
        "technique_name": item["technique_name"],
        "is_revoked_id": item["is_revoked_id"],
        "expected_ungrounded": False,
    }
    for item in ATTACK_POOL_ALERTS
    if item["style"] == "stated"
]

PROMPTED_ALERTS_ATTACK = [
    {
        "alert": dataclasses.replace(
            item["alert"],
            alert_id=item["alert"].alert_id.replace("ATTACKPOOL-", "SELFCHECK-ATTACK-PROMPTED-"),
            description=item["alert"].description + CITATION_REQUEST_SUFFIX,
        ),
        "ground_truth_technique": item["ground_truth_technique"],
        "technique_name": item["technique_name"],
        "is_revoked_id": item["is_revoked_id"],
        "expected_ungrounded": True,
    }
    for item in ATTACK_POOL_ALERTS
    if item["style"] == "bait"
]

if __name__ == "__main__":
    print(f"{len(STATED_ALERTS_ATTACK)} stated alerts, {len(PROMPTED_ALERTS_ATTACK)} prompted alerts")
