"""
tests/test_soc_agent_schema_parity.py

Issue E2 Task 2: end-to-end schema-parity test across all 6 component
ablation toggle configs (docs/ROADMAP_PLAN.md sec.12, experiments/
evaluation/ablation_study.py). Runs entirely offline with a mocked LLM --
0 network calls, no GROQ_API_KEY required -- and answers a narrower
question than "is the output correct": does every toggle combination
produce a report dict with the same schema shape, so that a disabled
stage's fields are consistently present (as the "nothing found" empty
value) rather than sometimes missing or None?

Note on the mock target: soc_agent.py constructs its ChatGroq client as
a module-level singleton (`llm = ChatGroq(...)`) at import time, and
analyse_alert() calls that same shared `llm.invoke(...)`. Patching the
ChatGroq *class* after import (as a naive mock might attempt) has no
effect on the already-constructed instance -- this test instead patches
the `llm` module attribute itself, which analyse_alert() looks up fresh
on every call.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.agent.alert_schema import SAMPLE_ALERTS
from src.agent.soc_agent import analyse_alert

# Matches soc_agent.SYSTEM_PROMPT's required output schema exactly.
# Deliberately contains no CVE-shaped, ATT&CK-shaped, or PII-shaped text,
# so every guardrail stage that DOES run finds nothing to flag -- keeps
# the mocked report identical and predictable across all 12 combinations.
MOCK_REPORT_JSON = json.dumps({
    "alert_id": "MOCK",
    "severity_assessment": "MEDIUM",
    "threat_summary": "Mocked report for schema-parity testing.",
    "threat_type": "TEST",
    "recommended_action": "None -- this is a test fixture.",
    "confidence_score": 0.5,
    "reasoning": "Mocked, not a real analysis.",
})

CONFIGS = [
    ("C0_FULL",      dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True)),
    ("C1_NO_INPUT",  dict(input_guardrail_enabled=False, cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True)),
    ("C2_NO_CVE",    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=False, attack_guardrail_enabled=True,  pii_guardrail_enabled=True)),
    ("C3_NO_ATTACK", dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=False, pii_guardrail_enabled=True)),
    ("C4_NO_PII",    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=False)),
    ("C5_NONE",      dict(input_guardrail_enabled=False, cve_guardrail_enabled=False, attack_guardrail_enabled=False, pii_guardrail_enabled=False)),
]

# ALERT-001 (SSH brute force) and ALERT-003 (port scan) -- both ordinary,
# non-adversarial alerts, so the input guardrail never blocks either one
# regardless of whether it's enabled. That isolates this test to schema
# shape, not injection-blocking behavior (already covered elsewhere).
FIXTURE_ALERTS = [SAMPLE_ALERTS[0], SAMPLE_ALERTS[2]]

EXPECTED_KEYS = {
    "alert_id", "severity_assessment", "threat_summary", "threat_type",
    "recommended_action", "confidence_score", "reasoning", "processed_at",
    "model", "agent_version", "guardrail_blocked", "hallucinated_cves",
    "cve_verifications", "hallucinated_attack_techniques",
    "attack_technique_verifications", "pii_detections",
    "output_guardrail_flagged", "requires_review", "evidence_pack",
}


def _make_mock_llm():
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = MOCK_REPORT_JSON
    mock_llm.invoke.return_value = mock_response
    return mock_llm


@pytest.mark.parametrize("alert", FIXTURE_ALERTS, ids=lambda a: a.alert_id)
@pytest.mark.parametrize("config_name,cfg", CONFIGS, ids=[c[0] for c in CONFIGS])
def test_schema_parity(alert, config_name, cfg):
    mock_llm = _make_mock_llm()
    with patch("src.agent.soc_agent.llm", mock_llm):
        report = analyse_alert(alert, verify_cves_with_nvd=False, **cfg)

    # (a) full expected key set present, nothing missing, nothing extra.
    assert set(report.keys()) == EXPECTED_KEYS, (
        f"[{config_name}/{alert.alert_id}] schema key mismatch: "
        f"missing={EXPECTED_KEYS - set(report.keys())}, "
        f"extra={set(report.keys()) - EXPECTED_KEYS}"
    )

    # (b) core scalar fields are always populated, never None, correct type.
    assert isinstance(report["confidence_score"], float)
    assert 0.0 <= report["confidence_score"] <= 1.0
    assert isinstance(report["guardrail_blocked"], bool)
    assert isinstance(report["output_guardrail_flagged"], bool)
    assert isinstance(report["requires_review"], bool)
    assert report["severity_assessment"] is not None
    assert report["threat_summary"] is not None

    # (c) list-typed fields are always lists (never None), regardless of
    # whether their guardrail is enabled or disabled -- this is the
    # actual point of the test: a disabled stage still produces its
    # "nothing found" sentinel, not a missing/None field.
    for key in ("hallucinated_cves", "cve_verifications",
                "hallucinated_attack_techniques",
                "attack_technique_verifications", "pii_detections"):
        assert isinstance(report[key], list), f"[{config_name}] {key} is not a list: {report[key]!r}"

    # (d) a disabled stage's fields are specifically empty (this mock
    # report contains no CVE/ATT&CK/PII-shaped text, so an *enabled*
    # stage should also find nothing here -- disabled and enabled are
    # expected to look identical for this deliberately-clean fixture,
    # which is what makes the parity claim checkable at all).
    if not cfg["cve_guardrail_enabled"]:
        assert report["hallucinated_cves"] == []
        assert report["cve_verifications"] == []
    if not cfg["attack_guardrail_enabled"]:
        assert report["hallucinated_attack_techniques"] == []
        assert report["attack_technique_verifications"] == []
    if not cfg["pii_guardrail_enabled"]:
        assert report["pii_detections"] == []

    # (e) the mocked LLM was actually the one invoked -- confirms this
    # test genuinely ran offline rather than silently falling through
    # to a real network call.
    mock_llm.invoke.assert_called_once()


def test_schema_parity_covers_all_12_combinations():
    """Sanity check on the test matrix itself: 6 configs x 2 alerts = 12
    parametrized cases actually collected, not silently fewer."""
    assert len(CONFIGS) == 6
    assert len(FIXTURE_ALERTS) == 2
