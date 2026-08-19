"""
tests/test_pii_guardrail.py

src/guardrails/pii_guardrail.py — Presidio-based PII detection/redaction
over the model's generated report text (threat_summary/recommended_action/
reasoning), addressing Threat T3 (docs/proposal.md).

Runs against the real Presidio analyzer/anonymizer + spaCy en_core_web_sm
model (no network calls, no LLM/Groq calls — fully local, same as
pytector's real DeBERTa model in test_input_guardrail.py's hybrid tests).
Requires the model to be downloaded once: `python -m spacy download
en_core_web_sm`.

Run:
    pytest tests/test_pii_guardrail.py -v
"""

from src.guardrails.pii_guardrail import DEFAULT_ENTITIES, detect_pii, redact_report_fields, redact_text


def test_detects_email():
    detections = detect_pii("Contact john.smith@example.com for details.")
    assert any(d["entity_type"] == "EMAIL_ADDRESS" and d["text"] == "john.smith@example.com"
               for d in detections)


def test_detects_person_name():
    detections = detect_pii("User John Smith triggered this alert.")
    assert any(d["entity_type"] == "PERSON" for d in detections)


def test_detects_real_ssn():
    detections = detect_pii("SSN on file: 219-09-9999.")
    assert any(d["entity_type"] == "US_SSN" and d["text"] == "219-09-9999" for d in detections)


def test_placeholder_ssn_not_flagged():
    # Documented, known Presidio behaviour (not a bug in this project's
    # code): 123-45-6789 is the textbook example/placeholder SSN, and
    # Presidio's own UsSsnRecognizer explicitly deny-lists it — asserting
    # the CURRENT behaviour so a future Presidio upgrade that changes this
    # is visible and deliberate, not silently "fixed" by flipping the
    # assertion (same convention as test_input_guardrail.py's
    # KNOWN_MISSED_PARAPHRASES tests).
    detections = detect_pii("SSN on file: 123-45-6789.")
    assert not any(d["entity_type"] == "US_SSN" for d in detections)


def test_detects_phone_number():
    detections = detect_pii("Call the analyst at 555-123-4567.")
    assert any(d["entity_type"] == "PHONE_NUMBER" for d in detections)


def test_detects_credit_card():
    detections = detect_pii("Exfiltrated card number 4111 1111 1111 1111 seen in payload.")
    assert any(d["entity_type"] == "CREDIT_CARD" for d in detections)


def test_clean_security_text_no_false_positives():
    detections = detect_pii(
        "Multiple failed SSH login attempts detected from external IP targeting root user on port 22."
    )
    assert detections == []


def test_ip_address_excluded_by_default():
    # Deliberate scope decision (see module docstring): IPs are core
    # security telemetry (evidence_pack.py already treats them as such),
    # not personal data to redact by default.
    detections = detect_pii("Traffic observed from 192.168.1.45.")
    assert not any(d["entity_type"] == "IP_ADDRESS" for d in detections)
    assert "IP_ADDRESS" not in DEFAULT_ENTITIES


def test_ip_address_detectable_when_explicitly_requested():
    detections = detect_pii("Traffic observed from 192.168.1.45.", entities=DEFAULT_ENTITIES + ["IP_ADDRESS"])
    assert any(d["entity_type"] == "IP_ADDRESS" for d in detections)


def test_redact_text_replaces_with_placeholder():
    redacted, detections = redact_text("Contact John Smith at john.smith@example.com.")
    assert "John Smith" not in redacted
    assert "john.smith@example.com" not in redacted
    assert "<PERSON>" in redacted
    assert "<EMAIL_ADDRESS>" in redacted
    assert len(detections) == 2


def test_redact_text_empty_string_returns_empty():
    redacted, detections = redact_text("")
    assert redacted == ""
    assert detections == []


def test_redact_report_fields_scans_only_report_text_fields():
    report = {
        "threat_summary": "Contacted John Smith about this.",
        "recommended_action": "Escalate to on-call.",
        "reasoning": "Nothing sensitive.",
        "alert_id": "ALERT-john.smith@example.com",  # not a scanned field
    }
    result = redact_report_fields(report)
    assert "alert_id" not in result["redacted_fields"]
    assert "<PERSON>" in result["redacted_fields"]["threat_summary"]
    # Fields with no PII still come back unchanged (not omitted) -- callers
    # apply redacted_fields wholesale via report.update(), so every
    # non-empty original field must have a valid value to write back.
    assert result["redacted_fields"]["recommended_action"] == "Escalate to on-call."


def test_redact_report_fields_skips_empty_fields():
    report = {"threat_summary": "", "recommended_action": None, "reasoning": "Nothing sensitive."}
    result = redact_report_fields(report)
    assert "threat_summary" not in result["redacted_fields"]
    assert "recommended_action" not in result["redacted_fields"]
    assert result["redacted_fields"]["reasoning"] == "Nothing sensitive."
    assert result["pii_found"] is False


def test_redact_report_fields_pii_found_flag():
    clean = redact_report_fields({"reasoning": "Nothing sensitive here."})
    assert clean["pii_found"] is False

    dirty = redact_report_fields({"reasoning": "Contact jane.doe@example.com immediately."})
    assert dirty["pii_found"] is True


def test_redact_report_fields_non_mutating():
    report = {"reasoning": "Contact John Smith."}
    redact_report_fields(report)
    assert report["reasoning"] == "Contact John Smith."


def test_redact_report_fields_detection_includes_source_field():
    result = redact_report_fields({"reasoning": "Email jane.doe@example.com now."})
    assert result["detections"][0]["field"] == "reasoning"
    assert result["detections"][0]["entity_type"] == "EMAIL_ADDRESS"
