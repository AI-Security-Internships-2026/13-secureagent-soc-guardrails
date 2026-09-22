"""
experiments/evaluation/relevance_classifier_validation/build_attack_pairs.py

Issue #43 (R4) Part B, Task B.1 — ATT&CK counterpart of build_pairs.py.

The same deterministic, stemmed bag-of-words topical-overlap classifier
(src/guardrails/grounding_utils.py's _topical_overlap(), threshold=0.15)
that build_pairs.py validated against human judgment for CVE/NVD text is
also used, unmodified, for MITRE ATT&CK technique descriptions
(src/guardrails/attack_grounding.py's verify_attack_technique()). ATT&CK
technique text is structurally different from NVD prose -- shorter, more
terse, more code-name-rich ("Golden Ticket", "Pass the Ticket") -- so the
same 0.15 threshold calibrated on CVE pairs has never been separately
checked against human judgment on this side. Zero pairs exist for this
yet; this script builds them. Annotation itself (human_label) is a
separate, later step -- not run here.

Method, mirroring build_pairs.py exactly where the underlying question is
the same:

  Base set (80 pairs, required minimum): 40 anchor alerts from the
  150-alert ATTACK_BAIT_ALERTS pool (experiments/evaluation/attack_bait_alerts.py),
  each producing:
    - a POSITIVE pair: the alert's own evidence text + its real, correct
      technique's real snapshot description (by construction, should read
      as relevant).
    - a NEGATIVE pair: the same evidence text + a different real
      technique's description, chosen by a fixed far index-shift into the
      150-alert pool (by construction, should usually read as irrelevant,
      though some will land on a harder, more plausible-sounding near-miss
      purely by chance -- same intentional design as build_pairs.py).

  Near-miss negative set (+20 pairs, the "20 edge-case borderline pairs"
  the issue asks for if budget allows): a second negative pair for 20 of
  the 40 anchors, this time using a SMALL index shift instead of the far
  one -- deliberately harder negatives than the base set's far-shift
  distractor, without hand-authoring each one.

  Named edge cases (+3 pairs, the specific examples the issue's Task B.1
  spells out by name): hand-picked, reusing real alert text already
  committed in attack_bait_alerts.py rather than inventing new prose,
  same principle as the rest of this file.
    - EDGE-KERBEROS: ATTACK-BAIT-027's evidence ("Kerberos service ticket
      requested... TGS-REQ") vs. T1558.001 Golden Ticket, whose own
      description literally says "ticket-granting tickets (TGT)" -- heavy
      lexical overlap on "Kerberos"/"ticket", but ATTACK-BAIT-027 is
      really about a large/legacy-encryption *service* ticket
      (Kerberoasting-shaped), not TGT forgery. A genuine near-miss, not a
      constructed one.
    - EDGE-MALDOC: ATTACK-BAIT-003's evidence (macro-enabled Office
      document opened from a phishing email, spawns a child process) vs.
      T1204.002 Malicious File. Real lexical/conceptual overlap
      ("malicious file"/document execution) -- arguably even a
      *defensibly relevant* pairing, since T1204.002 (user opens the
      file) is a real component of the phishing-attachment chain, even
      though this alert's own EXPECTED_TECHNIQUE is T1566 (Phishing,
      the delivery stage). Included un-labeled on purpose: this is
      exactly the kind of case that should split annotators.
    - EDGE-REVOKED: a revoked technique's real description (T1156,
      "Malicious Shell Modification") paired with an unrelated real
      alert (ATTACK-BAIT-026, plaintext credential exposure). Tests that
      the relevance classifier -- which runs BEFORE the REVOKED check in
      verify_attack_technique() -- correctly reads this as topically
      irrelevant on its own terms, independent of revocation status.

  103 pairs total (80 + 20 + 3), inside the issue's 80-120 target range.

The pair-construction intent is recorded separately in
attack_construction_key.json, NOT in the CSV the human labels -- same
blind-construction rationale as build_pairs.py. Row order in the CSV is
shuffled for the same reason.

Descriptions come from the local MITRE ATT&CK snapshot already used by
the real guardrail (src/guardrails/attack_grounding.py's
_load_attack_techniques(), DEFAULT_SNAPSHOT_PATH) -- no live network
call, no live LLM call, this whole script is deterministic.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_attack_pairs
"""

import csv
import json
import os
import random

from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS, EXPECTED_TECHNIQUE
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.attack_grounding import _load_attack_techniques

N_ANCHORS = 40
N_NEAR_MISS = 20  # additional near-shift negative pairs, drawn from the first 20 anchors
FAR_SHIFT = 67    # arbitrary, non-zero mod 150 -- a "far" distractor, same role as build_pairs.py's DISTRACTOR_SHIFT
NEAR_SHIFT = 2    # a "close" distractor -- the technique from a nearby anchor in file order
RANDOM_SEED = 20260922  # date this was built, for reproducibility -- not a secret

OUTPUT_DIR = os.path.dirname(__file__)
PAIRS_CSV_PATH = os.path.join(OUTPUT_DIR, "attack_pairs_to_label.csv")
CONSTRUCTION_KEY_PATH = os.path.join(OUTPUT_DIR, "attack_construction_key.json")

FIELDNAMES = [
    "pair_id", "alert_id", "alert_text", "candidate_technique_id",
    "candidate_technique_description", "human_label",
]


def _alert_evidence_text(alert):
    return build_evidence_pack(alert)["text"]


def build():
    alerts_by_id = {a.alert_id: a for a in ATTACK_BAIT_ALERTS}
    ordered_ids = sorted(EXPECTED_TECHNIQUE, key=lambda aid: int(aid.rsplit("-", 1)[1]))
    assert len(ordered_ids) == 150, len(ordered_ids)

    techniques = _load_attack_techniques()

    anchor_ids = ordered_ids[::2][:N_ANCHORS]  # every other alert, first 40 -- mirrors build_pairs.py
    assert len(anchor_ids) == N_ANCHORS, len(anchor_ids)
    near_miss_anchor_ids = anchor_ids[:N_NEAR_MISS]

    def technique_desc(tid):
        record = techniques.get(tid, {})
        return record.get("description"), record.get("name")

    rows = []
    construction_key = {}

    def add_pair(pair_id, alert_id, technique_id, intended, note=None):
        desc, name = technique_desc(technique_id)
        assert desc, f"missing description for {technique_id}"
        rows.append({
            "pair_id": pair_id,
            "alert_id": alert_id,
            "alert_text": _alert_evidence_text(alerts_by_id[alert_id]),
            "candidate_technique_id": technique_id,
            "candidate_technique_description": f"{name}: {desc}" if name else desc,
            "human_label": "",  # fill in: "relevant" or "not_relevant"
        })
        entry = {"intended": intended, "expected_technique_for_this_alert": EXPECTED_TECHNIQUE[alert_id]}
        if note:
            entry["note"] = note
        construction_key[pair_id] = entry

    # --- Base set: 40 anchors x (positive, far-shift negative) = 80 pairs ---
    for anchor_id in anchor_ids:
        anchor_index = ordered_ids.index(anchor_id)
        positive_technique = EXPECTED_TECHNIQUE[anchor_id]
        far_distractor_alert = ordered_ids[(anchor_index + FAR_SHIFT) % 150]
        far_negative_technique = EXPECTED_TECHNIQUE[far_distractor_alert]
        assert far_negative_technique != positive_technique, (anchor_id, positive_technique)

        add_pair(f"{anchor_id}__{positive_technique}__pos", anchor_id, positive_technique, "positive")
        add_pair(f"{anchor_id}__{far_negative_technique}__neg_far", anchor_id, far_negative_technique, "negative")

    # --- Near-miss set: +20 harder negative pairs (small shift) ---
    for anchor_id in near_miss_anchor_ids:
        anchor_index = ordered_ids.index(anchor_id)
        near_distractor_alert = ordered_ids[(anchor_index + NEAR_SHIFT) % 150]
        near_negative_technique = EXPECTED_TECHNIQUE[near_distractor_alert]
        positive_technique = EXPECTED_TECHNIQUE[anchor_id]
        assert near_negative_technique != positive_technique, (anchor_id, positive_technique)

        add_pair(
            f"{anchor_id}__{near_negative_technique}__neg_near", anchor_id, near_negative_technique,
            "negative_near_miss",
            note="Small index-shift distractor -- deliberately harder than the far-shift base negatives.",
        )

    # --- Named edge cases: 3 hand-picked pairs from real bait evidence ---
    add_pair(
        "EDGE-KERBEROS__T1558.001", "ATTACK-BAIT-027", "T1558.001", "edge_case",
        note=("Real alert is a large/legacy-encryption Kerberos SERVICE ticket request "
              "(Kerberoasting-shaped); T1558.001 Golden Ticket is about forging a "
              "ticket-GRANTING ticket (TGT). Heavy lexical overlap on 'Kerberos'/'ticket', "
              "different sub-technique -- deliberately ambiguous, left unlabeled."),
    )
    add_pair(
        "EDGE-MALDOC__T1204.002", "ATTACK-BAIT-003", "T1204.002", "edge_case",
        note=("Real alert's own EXPECTED_TECHNIQUE is T1566 (Phishing, the delivery "
              "stage), but the evidence text (macro-enabled Office doc opened, spawns a "
              "child process) also textually and conceptually overlaps T1204.002 "
              "(Malicious File, the execution stage of the same real-world chain) -- "
              "deliberately ambiguous, left unlabeled."),
    )
    add_pair(
        "EDGE-REVOKED__T1156", "ATTACK-BAIT-026", "T1156", "edge_case",
        note=("T1156 (Malicious Shell Modification) is REVOKED in the snapshot. Alert is "
              "an unrelated plaintext-credential-exposure finding -- topically irrelevant "
              "on its own terms. Tests that the relevance classifier's BoW overlap score "
              "(which runs BEFORE the REVOKED check in verify_attack_technique()) isn't "
              "accidentally influenced by revocation status either way."),
    )

    random.Random(RANDOM_SEED).shuffle(rows)

    with open(PAIRS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    with open(CONSTRUCTION_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(construction_key, f, indent=2)

    n_pos = sum(1 for v in construction_key.values() if v["intended"] == "positive")
    n_neg = sum(1 for v in construction_key.values() if v["intended"] in ("negative", "negative_near_miss"))
    n_edge = sum(1 for v in construction_key.values() if v["intended"] == "edge_case")
    print(f"{len(rows)} pairs written to {PAIRS_CSV_PATH}")
    print(f"  {n_pos} positive (by construction) / {n_neg} negative (far + near-miss) / {n_edge} named edge case")
    print(f"Construction key (not for the labeler) written to {CONSTRUCTION_KEY_PATH}")


if __name__ == "__main__":
    build()
