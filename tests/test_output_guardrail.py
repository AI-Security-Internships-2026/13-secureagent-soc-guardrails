"""
tests/test_output_guardrail.py

Real pytest assertions for src/guardrails/output_guardrail.py.

All NVD network calls are mocked via monkeypatch — this test suite must run
correctly with no internet access, deterministically, in well under a
second. Live NVD verification is exercised separately by
experiments/evaluation/cve_bait_test.py, which is deliberately a live
integration check, not a unit test.

Run:
    pytest tests/test_output_guardrail.py -v
"""

import pytest

from src.guardrails.output_guardrail import (
    extract_cves,
    check_hallucinated_cves,
    check_hallucinated_cves_verified,
    verify_cve,
    annotate_ungrounded_citations,
    _topical_overlap,
    _stem,
)


# ---------------------------------------------------------------------------
# extract_cves — pure regex extraction, no network involved
# ---------------------------------------------------------------------------

def test_extract_cves_finds_standard_id():
    assert extract_cves("This matches CVE-2021-44228 exactly.") == {"CVE-2021-44228"}


def test_extract_cves_is_case_insensitive_and_normalises_to_uppercase():
    assert extract_cves("this matches cve-2021-44228") == {"CVE-2021-44228"}


def test_extract_cves_finds_multiple():
    text = "Related to CVE-2021-44228 and also CVE-2014-0160."
    assert extract_cves(text) == {"CVE-2021-44228", "CVE-2014-0160"}


def test_extract_cves_returns_empty_set_when_none_present():
    assert extract_cves("No vulnerability identifiers mentioned here.") == set()


def test_extract_cves_handles_empty_string():
    assert extract_cves("") == set()


def test_extract_cves_handles_none_like_missing_field():
    assert extract_cves(None) == set()


# ---------------------------------------------------------------------------
# check_hallucinated_cves — Stage 1 grounding check (set difference), no
# network involved
# ---------------------------------------------------------------------------

def test_cve_present_in_both_input_and_output_is_grounded_not_flagged():
    alert_text = "Alert references CVE-2021-44228 directly."
    report = {"reasoning": "This matches CVE-2021-44228, the Log4Shell vulnerability."}
    assert check_hallucinated_cves(report, alert_text) == []


def test_cve_in_output_but_not_input_is_ungrounded():
    alert_text = "JNDI lookup string detected, no CVE mentioned."
    report = {"reasoning": "This is consistent with CVE-2021-44228."}
    assert check_hallucinated_cves(report, alert_text) == ["CVE-2021-44228"]


def test_no_cve_anywhere_returns_empty_list():
    alert_text = "Ordinary port scan alert."
    report = {"reasoning": "Sequential scanning behaviour observed."}
    assert check_hallucinated_cves(report, alert_text) == []


def test_checks_all_relevant_report_fields():
    alert_text = "No CVE in the input."
    # CVE only appears in recommended_action, not threat_summary/reasoning —
    # confirm all three fields actually get scanned, not just one.
    report = {
        "threat_summary": "RCE attempt detected.",
        "recommended_action": "Patch against CVE-2021-44228 immediately.",
        "reasoning": "Consistent with known exploit patterns.",
    }
    assert check_hallucinated_cves(report, alert_text) == ["CVE-2021-44228"]


# ---------------------------------------------------------------------------
# _stem / _topical_overlap — the deterministic word-matching logic behind
# NVD relevance scoring. Regression tests for the tokenization bug found
# and fixed in week 7 (alphanumeric terms like "log4j" were being silently
# dropped by a letters-only regex).
# ---------------------------------------------------------------------------

def test_stem_collapses_common_morphological_variants():
    assert _stem("execution") == _stem("execute")
    assert _stem("exploitation") == _stem("exploit")


def test_topical_overlap_preserves_alphanumeric_terms_like_log4j():
    # Regression test for the tokenization bug: a letters-only regex would
    # split "log4j" into fragments too short to survive filtering, silently
    # losing the single most relevant word in a Log4Shell comparison.
    text_a = "Exploitation of the log4j vulnerability via JNDI lookup."
    text_b = "Apache log4j JNDI features allow remote code execution."
    overlap = _topical_overlap(text_a, text_b)
    assert overlap > 0.0, "log4j (and other shared terms) should register as overlap"


def test_topical_overlap_is_zero_for_completely_unrelated_text():
    text_a = "Sequential port scanning activity on the internal network."
    text_b = "A buffer overflow vulnerability in an unrelated FTP server component."
    overlap = _topical_overlap(text_a, text_b)
    assert overlap < 0.15


def test_topical_overlap_handles_empty_input():
    assert _topical_overlap("", "some text") == 0.0
    assert _topical_overlap("some text", "") == 0.0
    assert _topical_overlap("", "") == 0.0


# ---------------------------------------------------------------------------
# verify_cve — Stage 2 NVD verification. _query_nvd is monkeypatched so
# these run without any network access, per CVE classification branch.
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_nvd(monkeypatch):
    """Returns a helper to set what the next _query_nvd() call returns."""
    import src.guardrails.output_guardrail as og

    def _set(response: dict):
        monkeypatch.setattr(og, "_query_nvd", lambda cve_id, timeout=8.0, max_retries=3: response)

    return _set


def test_verify_cve_fabricated_when_nvd_has_no_record(mock_nvd):
    mock_nvd({"exists": False, "description": None, "rejected": False})
    result = verify_cve("CVE-9999-99999", "some alert text")
    assert result["classification"] == "FABRICATED"


def test_verify_cve_unverified_on_network_failure(mock_nvd):
    mock_nvd({"exists": None, "description": None, "error": "timeout"})
    result = verify_cve("CVE-2021-44228", "some alert text")
    assert result["classification"] == "UNVERIFIED"


def test_verify_cve_rejected_when_nvd_marks_it_withdrawn(mock_nvd):
    mock_nvd({
        "exists": True,
        "description": "** REJECTED ** This candidate was withdrawn by its CNA.",
        "rejected": True,
    })
    result = verify_cve("CVE-2021-00000", "some alert text")
    assert result["classification"] == "REJECTED"


def test_verify_cve_unverified_when_no_english_description(mock_nvd):
    mock_nvd({"exists": True, "description": None, "rejected": False})
    result = verify_cve("CVE-2021-44228", "some alert text")
    assert result["classification"] == "UNVERIFIED"


def test_verify_cve_real_and_plausible_when_topically_matching(mock_nvd):
    mock_nvd({
        "exists": True,
        "description": "Apache log4j2 JNDI features allow remote code execution via LDAP.",
        "rejected": False,
    })
    alert_text = "JNDI lookup string detected consistent with log4j remote code execution."
    result = verify_cve("CVE-2021-44228", alert_text)
    assert result["classification"] == "REAL_AND_PLAUSIBLE"


def test_verify_cve_real_but_irrelevant_when_topically_unrelated(mock_nvd):
    mock_nvd({
        "exists": True,
        "description": "A buffer overflow in an unrelated printer driver component.",
        "rejected": False,
    })
    alert_text = "Sequential port scanning activity detected on the internal network."
    result = verify_cve("CVE-2021-44228", alert_text)
    assert result["classification"] == "REAL_BUT_IRRELEVANT"


# ---------------------------------------------------------------------------
# check_hallucinated_cves_verified — the two-signal split (flagged vs.
# requires_review) added in week 8. This is the most important behavioural
# contract in the whole guardrail: a correct-but-ungrounded citation must
# NOT silently look identical to "nothing happened."
# ---------------------------------------------------------------------------

def test_no_ungrounded_cve_means_neither_flagged_nor_requires_review():
    report = {"reasoning": "No CVE mentioned at all."}
    result = check_hallucinated_cves_verified(report, "plain alert text", verify_with_nvd=False)
    assert result["flagged"] is False
    assert result["requires_review"] is False


def test_real_and_plausible_citation_is_still_flagged_and_requires_review(mock_nvd):
    mock_nvd({
        "exists": True,
        "description": "Apache log4j2 JNDI features allow remote code execution via LDAP.",
        "rejected": False,
    })
    alert_text = "JNDI lookup consistent with log4j remote code execution, no CVE given."
    report = {"reasoning": "Consistent with CVE-2021-44228."}
    result = check_hallucinated_cves_verified(report, alert_text)

    # Corrected behaviour: a topical-overlap match above threshold is a weak
    # heuristic, not proof the cited CVE actually applies to THIS alert —
    # and REAL_AND_PLAUSIBLE is the most convincing-looking case, so an
    # analyst is least likely to double-check it unprompted. Every
    # ungrounded citation requires review; the classification tier explains
    # WHY (fabricated vs. wrong vs. plausible-but-unconfirmed vs. couldn't
    # check), it does not decide FOR the analyst whether it's worth a look.
    assert result["flagged"] is True
    assert result["requires_review"] is True
    # The classification itself is still the useful signal for how urgent
    # the review is — this is not lost, just no longer auto-clears anything.
    assert result["verifications"][0]["classification"] == "REAL_AND_PLAUSIBLE"


def test_fabricated_citation_is_both_flagged_and_requires_review(mock_nvd):
    mock_nvd({"exists": False, "description": None, "rejected": False})
    report = {"reasoning": "Consistent with CVE-9999-99999."}
    result = check_hallucinated_cves_verified(report, "no CVE in input", verify_with_nvd=True)

    assert result["flagged"] is True
    assert result["requires_review"] is True


def test_verify_with_nvd_false_skips_network_and_marks_unverified():
    report = {"reasoning": "Consistent with CVE-2021-44228."}
    result = check_hallucinated_cves_verified(report, "no CVE in input", verify_with_nvd=False)

    assert result["ungrounded_cves"] == ["CVE-2021-44228"]
    assert result["verifications"][0]["classification"] == "UNVERIFIED"
    assert result["requires_review"] is True


# ---------------------------------------------------------------------------
# annotate_ungrounded_citations — inline-tags ungrounded CVE mentions
# directly in the report's prose fields, not just the sibling
# hallucinated_cves/cve_verifications JSON fields.
# ---------------------------------------------------------------------------

def test_annotate_tags_ungrounded_mention_in_reasoning():
    report = {"reasoning": "Consistent with CVE-9999-99999."}
    verifications = [{"cve_id": "CVE-9999-99999", "classification": "FABRICATED",
                       "nvd_description": None, "topical_overlap": None}]

    annotated = annotate_ungrounded_citations(report, verifications)

    assert "CVE-9999-99999 [⚠ ungrounded — FABRICATED]" in annotated["reasoning"]


def test_annotate_tags_all_report_text_fields_not_just_one():
    report = {
        "threat_summary": "RCE via CVE-2021-44228 suspected.",
        "recommended_action": "Patch CVE-2021-44228 immediately.",
        "reasoning": "No further detail.",
    }
    verifications = [{"cve_id": "CVE-2021-44228", "classification": "REAL_AND_PLAUSIBLE",
                       "nvd_description": "...", "topical_overlap": 0.5}]

    annotated = annotate_ungrounded_citations(report, verifications)

    assert "[⚠ ungrounded — REAL_AND_PLAUSIBLE]" in annotated["threat_summary"]
    assert "[⚠ ungrounded — REAL_AND_PLAUSIBLE]" in annotated["recommended_action"]


def test_annotate_tags_every_occurrence_of_a_repeated_mention():
    report = {"reasoning": "CVE-2021-44228 explains this. See also CVE-2021-44228 for detail."}
    verifications = [{"cve_id": "CVE-2021-44228", "classification": "FABRICATED",
                       "nvd_description": None, "topical_overlap": None}]

    annotated = annotate_ungrounded_citations(report, verifications)

    assert annotated["reasoning"].count("[⚠ ungrounded — FABRICATED]") == 2


def test_annotate_leaves_grounded_report_untouched_when_no_verifications():
    report = {"reasoning": "Nothing ungrounded here."}
    assert annotate_ungrounded_citations(report, []) == report


def test_annotate_does_not_mutate_the_original_report():
    report = {"reasoning": "Consistent with CVE-9999-99999."}
    verifications = [{"cve_id": "CVE-9999-99999", "classification": "FABRICATED",
                       "nvd_description": None, "topical_overlap": None}]

    annotate_ungrounded_citations(report, verifications)

    assert report["reasoning"] == "Consistent with CVE-9999-99999."


def test_annotate_skips_fields_that_are_missing_or_empty():
    report = {"reasoning": None, "threat_summary": ""}
    verifications = [{"cve_id": "CVE-9999-99999", "classification": "FABRICATED",
                       "nvd_description": None, "topical_overlap": None}]

    annotated = annotate_ungrounded_citations(report, verifications)

    assert annotated["reasoning"] is None
    assert annotated["threat_summary"] == ""