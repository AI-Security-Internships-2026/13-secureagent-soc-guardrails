"""
tests/test_evidence_pack.py

src/guardrails/evidence_pack.py — pulls SecurityAlert's structured fields
(IP/host/user/hash/port) into an explicit object, and separates the
free-text surface (description + payload_snippet) that CVE/ATT&CK
grounding runs against from the structured fields that aren't prose.

Run:
    pytest tests/test_evidence_pack.py -v
"""

from src.agent.alert_schema import SecurityAlert
from src.guardrails.evidence_pack import build_evidence_pack


def _alert(**overrides):
    defaults = dict(
        alert_id="ALERT-TEST",
        timestamp="2026-01-01 00:00:00",
        severity="HIGH",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        event_type="TEST_EVENT",
        description="Test description",
        protocol="TCP",
        port=443,
        payload_snippet="Test payload",
        user="alice",
        hostname="host-01",
        file_hash="deadbeef",
    )
    defaults.update(overrides)
    return SecurityAlert(**defaults)


def test_pulls_both_ips():
    pack = build_evidence_pack(_alert())
    assert pack["ips"] == ["10.0.0.1", "10.0.0.2"]


def test_pulls_host_user_hash():
    pack = build_evidence_pack(_alert())
    assert pack["hosts"] == ["host-01"]
    assert pack["users"] == ["alice"]
    assert pack["hashes"] == ["deadbeef"]


def test_pulls_port_as_string():
    pack = build_evidence_pack(_alert(port=22))
    assert pack["ports"] == ["22"]


def test_missing_optional_fields_yield_empty_lists_not_errors():
    pack = build_evidence_pack(_alert(user=None, hostname=None, file_hash=None, port=None))
    assert pack["users"] == []
    assert pack["hosts"] == []
    assert pack["hashes"] == []
    assert pack["ports"] == []


def test_text_field_joins_description_and_payload():
    pack = build_evidence_pack(_alert(description="Alpha", payload_snippet="Beta"))
    assert pack["text"] == "Alpha Beta"


def test_text_field_handles_missing_payload():
    pack = build_evidence_pack(_alert(description="Alpha", payload_snippet=None))
    assert pack["text"] == "Alpha"


def test_text_field_used_for_grounding_excludes_structured_fields():
    # CVE/ATT&CK grounding should only see prose, not IPs/ports/hashes —
    # those live in their own buckets, not smuggled into `text`.
    pack = build_evidence_pack(_alert(description="Suspicious activity", payload_snippet="observed"))
    assert "10.0.0.1" not in pack["text"]
    assert "deadbeef" not in pack["text"]


def test_duplicate_source_and_destination_ip_deduplicated():
    pack = build_evidence_pack(_alert(source_ip="10.0.0.1", destination_ip="10.0.0.1"))
    assert pack["ips"] == ["10.0.0.1"]
