"""
src/guardrails/attack_grounding.py

Second instance of the CVE-checker pattern (output_guardrail.py): extract a
claimed identifier, check if it's grounded in the input alert, verify
against an authoritative external source if not, classify. Applied here to
MITRE ATT&CK technique IDs (e.g. T1055, T1055.011) instead of CVE numbers —
the taxonomy this repo is built around generalizes past CVEs, and this is
the evidence for that.

Two-stage design, same shape as the CVE checker:

  Stage 1 (grounding, deterministic, no network):
    - Extract ATT&CK technique IDs from the LLM's output.
    - Extract any technique IDs present in the input alert.
    - Anything in the output but not the input is "ungrounded" — the model
      cited a technique the alert never gave it.

  Stage 2 (verification against MITRE's real data, local snapshot):
    Unlike NVD, MITRE has no lightweight per-ID REST endpoint — ATT&CK is
    published as a single ~50MB STIX bundle covering the whole Enterprise
    matrix. Querying that live per check would be far too slow and
    bandwidth-heavy for a guardrail that runs per-report, so verification
    here runs against a periodically-refreshed local snapshot
    (build/refresh with `python -m src.data.fetch_mitre_attack`) rather
    than a live network call per technique ID. This is a real, documented
    tradeoff versus the CVE checker's live NVD lookups: the snapshot can
    lag MITRE's published data between refreshes — worth noting explicitly
    rather than presenting this as identical to the NVD case.

        FABRICATED          — the technique ID doesn't exist anywhere in
                               the snapshot. An invented identifier.
        REVOKED              — the ID exists but MITRE has revoked or
                               deprecated it (superseded, merged into
                               another technique, or removed from the
                               framework). Distinct from a genuine current
                               technique — citing a revoked ID is closer to
                               a fabrication than a real-but-wrong
                               citation, mirroring the CVE checker's
                               REJECTED case.
        REAL_BUT_IRRELEVANT  — real, current technique, but its
                               description has no topical overlap with the
                               alert.
        REAL_AND_PLAUSIBLE   — real, current, AND topically matches.
        UNVERIFIED           — local snapshot missing or unreadable.
                               Cannot classify further.

Reuses the shared grounding utilities (stemmer, topical-overlap scorer,
inline annotator) from grounding_utils.py rather than duplicating them —
the underlying pattern is identical to the CVE checker, only the
identifier shape and authoritative source differ.
"""

import json
import os
import re

from src.guardrails.grounding_utils import (
    REPORT_TEXT_FIELDS,
    _topical_overlap,
    annotate_ungrounded_mentions,
)

# Technique IDs look like "T1055" or, for sub-techniques, "T1055.011".
# Word-bounded so this doesn't match a T-number embedded inside a longer
# alphanumeric token.
ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

DEFAULT_SNAPSHOT_PATH = os.path.join("data", "mitre_attack", "enterprise_attack_techniques.json")

# In-process cache of the local snapshot — {technique_id: {name, description,
# revoked, url}}. Loaded once per process since the underlying file doesn't
# change mid-run; keyed by path so tests can point at a fixture snapshot
# without colliding with the real one.
_attack_data_cache: dict = {}


def extract_attack_ids(text: str) -> set:
    """Return the set of normalised (uppercase) ATT&CK technique IDs found in text."""
    if not text:
        return set()
    return {match.upper() for match in ATTACK_ID_PATTERN.findall(text)}


def _load_attack_techniques(snapshot_path: str = DEFAULT_SNAPSHOT_PATH) -> dict:
    """
    Load the local MITRE ATT&CK technique snapshot, caching it in-process.
    Returns {} (not an exception) if the snapshot is missing or unreadable,
    so a stale/missing data file degrades verification to UNVERIFIED
    rather than crashing the whole guardrail — refresh it with
    `python -m src.data.fetch_mitre_attack`.
    """
    if snapshot_path in _attack_data_cache:
        return _attack_data_cache[snapshot_path]

    if not os.path.exists(snapshot_path):
        _attack_data_cache[snapshot_path] = {}
        return _attack_data_cache[snapshot_path]

    with open(snapshot_path, encoding="utf-8") as f:
        snapshot = json.load(f)
    techniques = snapshot.get("techniques", {})
    _attack_data_cache[snapshot_path] = techniques
    return techniques


def verify_attack_technique(technique_id: str, alert_text: str, overlap_threshold: float = 0.15,
                             snapshot_path: str = DEFAULT_SNAPSHOT_PATH) -> dict:
    """
    Classify a single ungrounded ATT&CK technique mention against the local
    MITRE ATT&CK snapshot. Mirrors verify_cve()'s structure and return
    shape (output_guardrail.py), with `technique_id`/`attack_description`
    in place of `cve_id`/`nvd_description`.
    """
    techniques = _load_attack_techniques(snapshot_path)

    if not techniques:
        return {
            "technique_id": technique_id,
            "classification": "UNVERIFIED",
            "attack_description": None,
            "topical_overlap": None,
        }

    record = techniques.get(technique_id)
    if record is None:
        return {
            "technique_id": technique_id,
            "classification": "FABRICATED",
            "attack_description": None,
            "topical_overlap": None,
        }

    if record.get("revoked"):
        return {
            "technique_id": technique_id,
            "classification": "REVOKED",
            "attack_description": record.get("description"),
            "topical_overlap": None,
        }

    description = record.get("description")
    if not description:
        return {
            "technique_id": technique_id,
            "classification": "UNVERIFIED",
            "attack_description": None,
            "topical_overlap": None,
        }

    overlap = _topical_overlap(alert_text, description)
    classification = "REAL_AND_PLAUSIBLE" if overlap >= overlap_threshold else "REAL_BUT_IRRELEVANT"

    return {
        "technique_id": technique_id,
        "classification": classification,
        "attack_description": description,
        "topical_overlap": round(overlap, 3),
    }


def check_hallucinated_attack_techniques(report: dict, alert_text: str) -> list:
    """
    Stage 1 only (grounding) — mirrors check_hallucinated_cves(). Kept as
    its own function so callers that just want "is this technique ID in
    the input or not" don't need the full verified check.
    """
    grounded = extract_attack_ids(alert_text)
    report_text = " ".join(str(report.get(field, "")) for field in REPORT_TEXT_FIELDS)
    mentioned = extract_attack_ids(report_text)
    return sorted(mentioned - grounded)


def check_hallucinated_attack_techniques_verified(report: dict, alert_text: str,
                                                    verify_with_attack_data: bool = True,
                                                    snapshot_path: str = DEFAULT_SNAPSHOT_PATH) -> dict:
    """
    Full two-stage check. Same flagged/requires_review split as
    check_hallucinated_cves_verified() and for the same reason: every
    ungrounded citation requires review regardless of classification tier.
    REAL_AND_PLAUSIBLE is the most convincing-looking case (real technique,
    on-topic), so it's the one an analyst is least likely to double-check
    unprompted — exactly the wrong case to auto-clear.
    """
    ungrounded = check_hallucinated_attack_techniques(report, alert_text)

    verifications = []
    for technique_id in ungrounded:
        if verify_with_attack_data:
            verifications.append(verify_attack_technique(technique_id, alert_text, snapshot_path=snapshot_path))
        else:
            verifications.append({
                "technique_id": technique_id,
                "classification": "UNVERIFIED",
                "attack_description": None,
                "topical_overlap": None,
            })

    flagged = len(ungrounded) > 0
    requires_review = len(ungrounded) > 0

    return {
        "ungrounded_attack_techniques": ungrounded,
        "verifications": verifications,
        "flagged": flagged,
        "requires_review": requires_review,
    }


def annotate_ungrounded_attack_citations(report: dict, verifications: list) -> dict:
    """Inline-tag ungrounded technique mentions — thin wrapper over the shared annotator."""
    return annotate_ungrounded_mentions(report, verifications, id_key="technique_id")
