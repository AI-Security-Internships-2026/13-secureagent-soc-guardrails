"""
experiments/evaluation/ablation_pool.py

Builds the frozen alert pool for issue #42 (R3)'s component ablation study.

Issue #42 asks for the ablation to run on "the 479-alert pool ... identical
to the one that produced Sect. 4.9 numbers." That number is wrong -- the
real pooled cross-source set behind Sect. 4.9 is 575 alerts
(grounding_benchmark_summary.py), not 479 (same class of wrong specific as
issue #50/E5's guessed "479-alert pool" and "~290 CVEs", both corrected
against real values at the time).

Of those 575, 139 (the live Wazuh SIEM alerts) cannot be reproduced here:
wazuh_integration_results.json only persisted wazuh_alert_id/rule_id/
rule_level per alert, not the per-event fields (source_ip, destination_ip,
payload_snippet, file_hash, hostname, timestamp) wazuh_integration_test.py's
wazuh_alert_to_security_alert() actually built each alert's content from --
none of that was cached anywhere, and the live Docker stack that produced it
is not currently running. Re-collecting a fresh set of Wazuh alerts would
not be "identical to the one that produced Sect. 4.9 numbers" as the issue
requires, so it's excluded here rather than substituted silently. This is a
disclosed scope reduction, decided with the supervisor, not a silent
shortfall -- see docs/all_results.md and docs/ROADMAP_PLAN.md #42.

The remaining 436 are fully reconstructable from static code/data with no
live dependency:
  - CVE-bait          150  (cve_bait_alerts.CVE_BAIT_ALERTS)
  - ATT&CK-bait        150  (attack_bait_alerts.ATTACK_BAIT_ALERTS)
  - Secure_SOC_AI CVE pool  60  (soc_integration.cve_pool.CVE_POOL_ALERTS)
  - Secure_SOC_AI rule engine  76  (soc_integration_test.py's rule engine +
    correlator over the static synthetic_events.jsonl)

The rule-engine leg needs one extra step the other three don't:
secure_soc_ai's Incident.id is a random uuid4 (models.py), regenerated
differently every time the rule engine + correlator are re-run, even
though the incidents' actual *content* (from the same static events file,
pure local Python, no randomness anywhere else) is stable. Re-deriving the
pool from source on every driver invocation would therefore silently
reassign different alert_ids to the same underlying alerts run over run --
poison for resume-mode, which keys "already done" purely by alert_id. So
this module builds the pool ONCE and freezes it to
experiments/results/ablation_pool_436.json (deterministic pool_ids of our
own choosing, e.g. SOCRULE-001..076 assigned by sorted incident creation
time, not secure_soc_ai's own random incident.id); ablation_driver.py
always loads alerts from that frozen file, never rebuilds the pool itself.

Usage:
    python -m experiments.evaluation.ablation_pool
"""

import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS, EXPECTED_CVE
from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS, EXPECTED_TECHNIQUE
from experiments.evaluation.soc_integration.cve_pool import CVE_POOL_ALERTS
from experiments.evaluation.soc_integration_test import (
    RULES_DIR, EVENTS_PATH, incident_to_security_alert,
)
from secure_soc_ai.correlate import Correlator
from secure_soc_ai.detect.rule_engine import RuleEngine
from secure_soc_ai.ingest.jsonl_source import JsonlFileSource

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
OUTPUT_PATH = os.path.join(RESULTS_DIR, "ablation_pool_436.json")


def _cve_bait_entries() -> list:
    return [
        {
            "pool_id": alert.alert_id,
            "source": "cve_bait",
            "alert": dataclasses.asdict(alert),
            "ground_truth": {"expected_cve": EXPECTED_CVE.get(alert.alert_id)},
        }
        for alert in CVE_BAIT_ALERTS
    ]


def _attack_bait_entries() -> list:
    return [
        {
            "pool_id": alert.alert_id,
            "source": "attack_bait",
            "alert": dataclasses.asdict(alert),
            "ground_truth": {"expected_technique": EXPECTED_TECHNIQUE.get(alert.alert_id)},
        }
        for alert in ATTACK_BAIT_ALERTS
    ]


def _cve_pool_entries() -> list:
    return [
        {
            "pool_id": item["alert"].alert_id,
            "source": "cve_pool",
            "alert": dataclasses.asdict(item["alert"]),
            "ground_truth": {
                "expected_cve": item["ground_truth_cve"],
                "cve_name": item["cve_name"],
                "style": item["style"],
            },
        }
        for item in CVE_POOL_ALERTS
    ]


def _soc_rule_engine_entries() -> list:
    """Re-derives the same 76 incidents soc_integration_test.py produces
    (static events file, pure local rule engine/correlator, no
    randomness anywhere except Incident.id itself -- see module
    docstring), then assigns our own deterministic pool_id rather than
    keeping secure_soc_ai's random incident.id."""
    rules = RuleEngine.from_directory(RULES_DIR)
    correlator = Correlator()

    incidents_by_id = {}
    for event in JsonlFileSource(EVENTS_PATH).read():
        for alert in rules.evaluate(event):
            incident, _ = correlator.process(alert)
            if incident is not None:
                incidents_by_id[incident.id] = incident
    for incident in correlator.flush_stale():
        incidents_by_id[incident.id] = incident

    incidents = sorted(incidents_by_id.values(), key=lambda i: i.created_at)

    entries = []
    for i, incident in enumerate(incidents, start=1):
        pool_id = f"SOCRULE-{i:03d}"
        alert = incident_to_security_alert(incident)
        alert_dict = dataclasses.asdict(alert)
        alert_dict["alert_id"] = pool_id  # replace secure_soc_ai's random incident.id
        ground_truth_mitre = sorted({m for a in incident.alerts for m in a.mitre})
        entries.append({
            "pool_id": pool_id,
            "source": "soc_rule_engine",
            "alert": alert_dict,
            "ground_truth": {
                "entity": incident.entity,
                "rule_ids": sorted({a.rule_id for a in incident.alerts}),
                "ground_truth_mitre": ground_truth_mitre,
            },
        })
    return entries


def build_pool() -> list:
    pool = (
        _cve_bait_entries()
        + _attack_bait_entries()
        + _cve_pool_entries()
        + _soc_rule_engine_entries()
    )
    ids = [e["pool_id"] for e in pool]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate pool_id(s) across sources: {dupes}")
    return pool


def main():
    pool = build_pool()
    by_source = {}
    for e in pool:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "total": len(pool),
            "by_source": by_source,
            "excluded_wazuh_note": (
                "139 live Wazuh SIEM alerts from the real Sect. 4.9 pool "
                "(575 total) are excluded -- not reproducible without the "
                "original live capture; see module docstring."
            ),
            "pool": pool,
        }, f, indent=2)

    print(f"Built pool: {len(pool)} alerts")
    for src, n in by_source.items():
        print(f"  {src}: {n}")
    print(f"Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
