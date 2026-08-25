"""
experiments/evaluation/relevance_classifier_validation/build_pairs.py

Builds the (alert, candidate CVE) pair list for manually validating the
output guardrail's relevance classifier -- the deterministic, stemmed
bag-of-words topical-overlap score (src/guardrails/grounding_utils.py's
_topical_overlap()) that decides REAL_AND_PLAUSIBLE vs. REAL_BUT_IRRELEVANT
for any citation that isn't grounded in the alert's own evidence
(src/guardrails/output_guardrail.py's verify_cve(), overlap_threshold=0.15).
That heuristic has never been checked against what a human would actually
judge -- this is issue #20 / docs/ROADMAP_PLAN.md sec.11 Tier-1 item 6.

Method: reuses the 100 CVE-bait alerts (experiments/evaluation/cve_bait_alerts.py)
as anchors. For each anchor alert, builds two pairs:
  - a POSITIVE pair: the alert's own evidence text + its real, correct CVE's
    real NVD description (by construction, should read as relevant).
  - a NEGATIVE pair: the same alert's evidence text + a different real CVE's
    real NVD description, chosen by a fixed index shift into the same
    100-CVE pool (same "shift a distractor into the pool" technique already
    used in llm_judge_synthetic_test.py, for consistency) -- by construction,
    should usually read as irrelevant, though some will land on a harder,
    more plausible-sounding near-miss purely by chance, which is fine and
    even useful (a completely predictable pattern would make for a weaker
    benchmark).

40 anchors x 2 pairs = 80 total, inside the 50-100 target range from
docs/ROADMAP_PLAN.md sec.11 item 6.

The pair-construction intent (which CVE was meant as positive/negative) is
recorded separately in construction_key.json, NOT in the CSV the human
labels -- the human's judgment should be made blind to how the pair was
built, otherwise the "validation" just checks whether the human agrees
with this script's own assumptions instead of independently judging
relevance. Row order in the CSV is shuffled for the same reason (an
alternating positive/negative pattern would be an obvious tell).

Real NVD descriptions are fetched live (same _query_nvd() the actual
guardrail uses, reused directly rather than duplicated) -- so the text a
human labels is exactly what the real pipeline would have seen, not a
paraphrase.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_pairs
"""

import csv
import json
import os
import random

from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS, EXPECTED_CVE
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.output_guardrail import _query_nvd

N_ANCHORS = 40
DISTRACTOR_SHIFT = 37  # arbitrary, non-zero mod 100 -- never lands on the same CVE as the anchor
RANDOM_SEED = 20260821  # date this was built, for reproducibility -- not a secret

OUTPUT_DIR = os.path.dirname(__file__)
PAIRS_CSV_PATH = os.path.join(OUTPUT_DIR, "pairs_to_label.csv")
CONSTRUCTION_KEY_PATH = os.path.join(OUTPUT_DIR, "construction_key.json")


def build():
    alerts_by_id = {a.alert_id: a for a in CVE_BAIT_ALERTS}
    ordered_ids = sorted(EXPECTED_CVE)  # BAIT-001 .. BAIT-100, stable order
    assert len(ordered_ids) == 100, len(ordered_ids)

    anchor_ids = ordered_ids[::2][:N_ANCHORS]  # every other alert, first 40
    assert len(anchor_ids) == N_ANCHORS, len(anchor_ids)

    # Collect every CVE ID we'll actually need a description for, so each
    # is only fetched once even if it's used as both someone's correct CVE
    # and someone else's distractor.
    needed_cve_ids = set()
    pair_specs = []  # (pair_kind, anchor_id, candidate_cve_id)
    for anchor_id in anchor_ids:
        anchor_index = ordered_ids.index(anchor_id)
        positive_cve = EXPECTED_CVE[anchor_id]
        distractor_id = ordered_ids[(anchor_index + DISTRACTOR_SHIFT) % 100]
        negative_cve = EXPECTED_CVE[distractor_id]
        assert negative_cve != positive_cve, (anchor_id, positive_cve, negative_cve)

        needed_cve_ids.add(positive_cve)
        needed_cve_ids.add(negative_cve)
        pair_specs.append(("positive", anchor_id, positive_cve))
        pair_specs.append(("negative", anchor_id, negative_cve))

    print(f"Fetching real NVD descriptions for {len(needed_cve_ids)} unique CVEs "
          f"(~{len(needed_cve_ids)}s at NVD's public rate limit)...")
    descriptions = {}
    for i, cve_id in enumerate(sorted(needed_cve_ids), 1):
        result = _query_nvd(cve_id)
        if result.get("description"):
            descriptions[cve_id] = result["description"]
        else:
            print(f"  WARNING: no description for {cve_id} ({result})")
        if i % 10 == 0:
            print(f"  {i}/{len(needed_cve_ids)} fetched")

    missing = needed_cve_ids - set(descriptions)
    if missing:
        print(f"Dropping {len(missing)} pairs with no fetchable NVD description: {sorted(missing)}")

    rows = []
    construction_key = {}
    for pair_kind, anchor_id, candidate_cve in pair_specs:
        if candidate_cve not in descriptions:
            continue
        alert = alerts_by_id[anchor_id]
        evidence_text = build_evidence_pack(alert)["text"]
        pair_id = f"{anchor_id}__{candidate_cve}"
        rows.append({
            "pair_id": pair_id,
            "alert_id": anchor_id,
            "alert_text": evidence_text,
            "candidate_cve_id": candidate_cve,
            "candidate_cve_description": descriptions[candidate_cve],
            "human_label": "",  # fill in: "relevant" or "not_relevant"
        })
        construction_key[pair_id] = {
            "intended": pair_kind,
            "expected_cve_for_this_alert": EXPECTED_CVE[anchor_id],
        }

    random.Random(RANDOM_SEED).shuffle(rows)

    with open(PAIRS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "pair_id", "alert_id", "alert_text", "candidate_cve_id",
            "candidate_cve_description", "human_label",
        ])
        writer.writeheader()
        writer.writerows(rows)

    with open(CONSTRUCTION_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(construction_key, f, indent=2)

    print(f"\n{len(rows)} pairs written to {PAIRS_CSV_PATH}")
    print(f"Construction key (not for the labeler) written to {CONSTRUCTION_KEY_PATH}")


if __name__ == "__main__":
    build()
