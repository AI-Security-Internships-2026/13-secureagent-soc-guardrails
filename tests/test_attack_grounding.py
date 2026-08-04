"""
tests/test_attack_grounding.py

Real pytest assertions for src/guardrails/attack_grounding.py — the
MITRE ATT&CK counterpart to tests/test_output_guardrail.py's CVE checker
tests. _load_attack_techniques() is monkeypatched wherever a specific
snapshot content is needed, so this suite runs deterministically with no
dependency on data/mitre_attack/enterprise_attack_techniques.json actually
being present or current.

Run:
    pytest tests/test_attack_grounding.py -v
"""

import pytest

from src.guardrails.attack_grounding import (
    extract_attack_ids,
    check_hallucinated_attack_techniques,
    check_hallucinated_attack_techniques_verified,
    verify_attack_technique,
    annotate_ungrounded_attack_citations,
)


# ---------------------------------------------------------------------------
# extract_attack_ids — pure regex extraction, no data file involved
# ---------------------------------------------------------------------------

def test_extract_attack_ids_finds_standard_id():
    assert extract_attack_ids("Consistent with T1055 process injection.") == {"T1055"}


def test_extract_attack_ids_finds_subtechnique_id():
    assert extract_attack_ids("Consistent with T1055.011 (EWM injection).") == {"T1055.011"}


def test_extract_attack_ids_is_case_insensitive_and_normalises_to_uppercase():
    assert extract_attack_ids("consistent with t1055") == {"T1055"}


def test_extract_attack_ids_finds_multiple():
    text = "Related to T1055 and also T1059.001."
    assert extract_attack_ids(text) == {"T1055", "T1059.001"}


def test_extract_attack_ids_does_not_match_embedded_substring():
    # A T-number embedded inside a longer alphanumeric token isn't a real
    # citation — the word-boundary pattern must not match it.
    assert extract_attack_ids("HOSTT1055XYZ was affected.") == set()


def test_extract_attack_ids_returns_empty_set_when_none_present():
    assert extract_attack_ids("No technique identifiers mentioned here.") == set()


def test_extract_attack_ids_handles_empty_string():
    assert extract_attack_ids("") == set()


def test_extract_attack_ids_handles_none_like_missing_field():
    assert extract_attack_ids(None) == set()


# ---------------------------------------------------------------------------
# check_hallucinated_attack_techniques — Stage 1 grounding check (set
# difference), no data file involved
# ---------------------------------------------------------------------------

def test_technique_present_in_both_input_and_output_is_grounded_not_flagged():
    alert_text = "Alert references T1055 directly."
    report = {"reasoning": "This matches T1055, process injection."}
    assert check_hallucinated_attack_techniques(report, alert_text) == []


def test_technique_in_output_but_not_input_is_ungrounded():
    alert_text = "Suspicious process memory write detected, no technique ID given."
    report = {"reasoning": "This is consistent with T1055."}
    assert check_hallucinated_attack_techniques(report, alert_text) == ["T1055"]


def test_no_technique_anywhere_returns_empty_list():
    alert_text = "Ordinary port scan alert."
    report = {"reasoning": "Sequential scanning behaviour observed."}
    assert check_hallucinated_attack_techniques(report, alert_text) == []


def test_checks_all_relevant_report_fields():
    alert_text = "No technique ID in the input."
    report = {
        "threat_summary": "Process injection attempt detected.",
        "recommended_action": "Investigate for T1055 activity immediately.",
        "reasoning": "Consistent with known injection patterns.",
    }
    assert check_hallucinated_attack_techniques(report, alert_text) == ["T1055"]


# ---------------------------------------------------------------------------
# verify_attack_technique — Stage 2 verification against the local MITRE
# ATT&CK snapshot. _load_attack_techniques is monkeypatched so these run
# without touching the real data file, per classification branch.
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_attack_data(monkeypatch):
    """Returns a helper to set what _load_attack_techniques() returns."""
    import src.guardrails.attack_grounding as ag

    def _set(techniques: dict):
        monkeypatch.setattr(ag, "_load_attack_techniques", lambda snapshot_path=ag.DEFAULT_SNAPSHOT_PATH: techniques)

    return _set


def test_verify_fabricated_when_not_in_snapshot(mock_attack_data):
    mock_attack_data({"T1055": {"name": "Process Injection", "description": "...", "revoked": False}})
    result = verify_attack_technique("T9999", "some alert text")
    assert result["classification"] == "FABRICATED"


def test_verify_unverified_when_snapshot_empty(mock_attack_data):
    mock_attack_data({})
    result = verify_attack_technique("T1055", "some alert text")
    assert result["classification"] == "UNVERIFIED"


def test_verify_revoked_when_technique_marked_revoked(mock_attack_data):
    mock_attack_data({
        "T1086": {"name": "PowerShell", "description": "Superseded by a more specific technique.", "revoked": True},
    })
    result = verify_attack_technique("T1086", "some alert text")
    assert result["classification"] == "REVOKED"


def test_verify_unverified_when_no_description(mock_attack_data):
    mock_attack_data({"T1055": {"name": "Process Injection", "description": None, "revoked": False}})
    result = verify_attack_technique("T1055", "some alert text")
    assert result["classification"] == "UNVERIFIED"


def test_verify_real_and_plausible_when_topically_matching(mock_attack_data):
    mock_attack_data({
        "T1055": {
            "name": "Process Injection",
            "description": "Adversaries may inject code into processes to evade process-based defenses.",
            "revoked": False,
        },
    })
    alert_text = "Suspicious code injection into a running process consistent with process injection."
    result = verify_attack_technique("T1055", alert_text)
    assert result["classification"] == "REAL_AND_PLAUSIBLE"


def test_verify_real_but_irrelevant_when_topically_unrelated(mock_attack_data):
    mock_attack_data({
        "T1055": {
            "name": "Process Injection",
            "description": "Adversaries may inject code into processes to evade process-based defenses.",
            "revoked": False,
        },
    })
    alert_text = "Sequential port scanning activity detected on the internal network."
    result = verify_attack_technique("T1055", alert_text)
    assert result["classification"] == "REAL_BUT_IRRELEVANT"


# ---------------------------------------------------------------------------
# check_hallucinated_attack_techniques_verified — the flagged/requires_review
# split, mirroring the CVE checker's behavioural contract.
# ---------------------------------------------------------------------------

def test_no_ungrounded_technique_means_neither_flagged_nor_requires_review():
    report = {"reasoning": "No technique ID mentioned at all."}
    result = check_hallucinated_attack_techniques_verified(report, "plain alert text",
                                                             verify_with_attack_data=False)
    assert result["flagged"] is False
    assert result["requires_review"] is False


def test_real_and_plausible_citation_is_still_flagged_and_requires_review(mock_attack_data):
    mock_attack_data({
        "T1055": {
            "name": "Process Injection",
            "description": "Adversaries may inject code into processes to evade process-based defenses.",
            "revoked": False,
        },
    })
    alert_text = "Code injection into a running process observed, no technique ID given."
    report = {"reasoning": "Consistent with T1055."}
    result = check_hallucinated_attack_techniques_verified(report, alert_text)

    # Same contract as the CVE checker: REAL_AND_PLAUSIBLE is the most
    # convincing-looking case, so it must not silently auto-clear review.
    assert result["flagged"] is True
    assert result["requires_review"] is True
    assert result["verifications"][0]["classification"] == "REAL_AND_PLAUSIBLE"


def test_fabricated_citation_is_both_flagged_and_requires_review(mock_attack_data):
    mock_attack_data({"T1055": {"name": "Process Injection", "description": "...", "revoked": False}})
    report = {"reasoning": "Consistent with T9999."}
    result = check_hallucinated_attack_techniques_verified(report, "no technique ID in input")

    assert result["flagged"] is True
    assert result["requires_review"] is True


def test_verify_with_attack_data_false_skips_lookup_and_marks_unverified():
    report = {"reasoning": "Consistent with T1055."}
    result = check_hallucinated_attack_techniques_verified(report, "no technique ID in input",
                                                             verify_with_attack_data=False)

    assert result["ungrounded_attack_techniques"] == ["T1055"]
    assert result["verifications"][0]["classification"] == "UNVERIFIED"
    assert result["requires_review"] is True


# ---------------------------------------------------------------------------
# annotate_ungrounded_attack_citations — inline-tags ungrounded technique
# mentions directly in the report's prose fields.
# ---------------------------------------------------------------------------

def test_annotate_tags_ungrounded_mention_in_reasoning():
    report = {"reasoning": "Consistent with T9999."}
    verifications = [{"technique_id": "T9999", "classification": "FABRICATED",
                       "attack_description": None, "topical_overlap": None}]

    annotated = annotate_ungrounded_attack_citations(report, verifications)

    assert "T9999 [⚠ ungrounded — FABRICATED]" in annotated["reasoning"]


def test_annotate_does_not_mutate_the_original_report():
    report = {"reasoning": "Consistent with T9999."}
    verifications = [{"technique_id": "T9999", "classification": "FABRICATED",
                       "attack_description": None, "topical_overlap": None}]

    annotate_ungrounded_attack_citations(report, verifications)

    assert report["reasoning"] == "Consistent with T9999."
