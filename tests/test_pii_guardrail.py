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


# Regression tests for the PERSON plausibility filter (docs/all_results.md
# #33, #35) -- spaCy's small NER model mistook technical text for a name on
# real live Wazuh alerts. Each string below is a real false positive
# observed in production, not a hypothetical one.
def test_url_path_not_flagged_as_person():
    detections = detect_pii("Request to /profile.php returned 200.", entities=["PERSON"])
    assert detections == []


def test_sql_command_fragment_not_flagged_as_person():
    detections = detect_pii("Payload used xp_cmdshell('whoami') to enumerate the host.", entities=["PERSON"])
    assert detections == []


def test_ampersand_acronym_not_flagged_as_person():
    detections = detect_pii("Matches MITRE ATT&CK technique T1190.", entities=["PERSON"])
    assert detections == []


def test_year_plus_word_not_flagged_as_person():
    detections = detect_pii("Fails the CIS 2023 Benchmark check.", entities=["PERSON"])
    assert detections == []


def test_apostrophe_name_still_detected():
    # The plausibility filter deliberately does NOT reject apostrophes --
    # rejecting them would fix these false positives by breaking real
    # names like this one instead.
    detections = detect_pii("Escalated to Sean O'Brien for review.")
    assert any(d["entity_type"] == "PERSON" for d in detections)


def test_hyphenated_name_still_detected():
    detections = detect_pii("Reported by Jean-Pierre Dubois.")
    assert any(d["entity_type"] == "PERSON" for d in detections)


# Second round of plausibility-filter regressions (docs/all_results.md
# #38) -- the punctuation/digit filter above didn't catch these because
# neither contains any of the filtered characters.
def test_lowercase_phrase_not_flagged_as_person():
    # Real false positive: spaCy misread this ordinary two-word phrase
    # (from generated report prose about a cloud storage bucket policy)
    # as a PERSON entity.
    detections = detect_pii("Recommend action: enforce bucket policy immediately.", entities=["PERSON"])
    assert detections == []


def test_short_acronym_not_flagged_as_person():
    from src.guardrails.pii_guardrail import _is_plausible_person
    for acronym in ["PII", "SOC", "CVE", "DLP"]:
        assert _is_plausible_person(acronym) is False


def test_titlecase_name_still_plausible():
    from src.guardrails.pii_guardrail import _is_plausible_person
    assert _is_plausible_person("Michelle Hayes-Taylor") is True
    assert _is_plausible_person("Emily Davis-Hernandez") is True


# Third false-positive round (docs/all_results.md, live-data bulk expansion
# to n~150): a bare IP address gets the identical 0.4 confidence score
# Presidio gives a real phone number, so score alone can't tell them apart --
# only IPv4 structure can.
def test_ip_address_not_flagged_as_phone_number():
    detections = detect_pii("Traffic observed from 203.0.113.138 to internal host.", entities=["PHONE_NUMBER"])
    assert detections == []
    detections = detect_pii("Beaconing to 198.51.100.45 detected.", entities=["PHONE_NUMBER"])
    assert detections == []


def test_real_phone_number_still_detected_alongside_ip_fix():
    detections = detect_pii("Caller left callback number 555-284-9013, asked for employee John Smith.",
                              entities=["PHONE_NUMBER"])
    assert any(d["entity_type"] == "PHONE_NUMBER" and d["text"] == "555-284-9013" for d in detections)


def test_dotted_phone_number_not_mistaken_for_ip():
    from src.guardrails.pii_guardrail import _is_plausible_phone
    # 555.284.9013 -- first octet 555 is out of IPv4 range, so this must
    # NOT be rejected even though it's dot-separated like an IP.
    assert _is_plausible_phone("555.284.9013") is True


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
