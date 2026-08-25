"""
src/guardrails/pii_guardrail.py

Third output-guardrail check, alongside the CVE (output_guardrail.py) and
MITRE ATT&CK (attack_grounding.py) checkers -- but a different kind of
check. Those two are GROUNDING checks: is a claim the model made backed by
the alert's own evidence. This one is a REDACTION check: does the model's
generated report echo sensitive personal data at all, regardless of
whether it was "grounded" -- a correctly-cited real name/email/SSN is
still a privacy problem if it ends up in a report that gets logged,
ticketed, or shared more broadly than the raw alert was.

Addresses Threat T3 from docs/proposal.md: "Sensitive data present in raw
alerts (names, IPs, emails, SSNs) surfaces unredacted in the generated
analyst report." Built with Microsoft Presidio (presidio-analyzer +
presidio-anonymizer, already in requirements.txt but never wired in --
issue #20/ROADMAP_PLAN.md sec.5) plus spaCy's en_core_web_sm for the NER
step Presidio's PERSON/LOCATION recognizers depend on. Fully local (no
network calls, no LLM calls) -- satisfies the same local-only constraint
as the rest of the guardrail stack (issue #16).

Setup note: en_core_web_sm isn't installable via requirements.txt (spaCy
models aren't normal PyPI packages) -- run `python -m spacy download
en_core_web_sm` once. Deliberately the SMALL model, not Presidio's default
en_core_web_lg (~560MB) -- sm is ~13MB, downloads reliably, and is
sufficient for the coarse PERSON/LOCATION NER this guardrail needs; large
buys higher NER accuracy at a size/setup cost this project doesn't need to
pay for a redaction guardrail (not a research question about NER quality).

Entity scope -- a deliberate departure from the proposal's literal
"(names, IPs, emails, SSNs)" list: DEFAULT_ENTITIES omits IP_ADDRESS.
evidence_pack.py already treats an alert's source_ip/destination_ip as
core structured security telemetry the analyst needs to act on, not
personal data to hide -- redacting them by default would break the
report's usefulness for the most common case (every alert has IPs) to
guard against a case that mostly doesn't apply to them (an alert's own
network telemetry isn't "a person's sensitive data" in the way a name or
SSN embedded in a payload is). IP_ADDRESS is still a supported entity type
(pass it via `entities=`) so a future analysis can measure it separately
without conflating "this alert legitimately reports an IP" with "this
report leaked someone's SSN."
"""

import re

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

from src.guardrails.grounding_utils import REPORT_TEXT_FIELDS

# Genuinely personal categories, redacted by default. IP_ADDRESS
# deliberately excluded -- see module docstring.
DEFAULT_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"]

_analyzer = None
_anonymizer = None


def _get_analyzer() -> AnalyzerEngine:
    # Lazy singleton, same pattern as input_guardrail.py's
    # _get_pytector_detector() -- avoids loading the spaCy model until
    # actually needed, and only once per process.
    global _analyzer
    if _analyzer is None:
        config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=config).create_engine()
        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    return _analyzer


def _get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


# Characters that never appear in a real human name, but do appear in the
# technical text (URL paths, function calls, acronyms, version/year
# numbers) spaCy's small NER model sometimes mistakes for a PERSON.
# Deliberately does NOT include apostrophes or hyphens -- real names like
# "O'Brien" or "Jean-Pierre" use those, so filtering on them would trade a
# false positive for a false negative rather than actually fixing anything.
# Found via 5 real false positives on live Wazuh alert text
# (docs/all_results.md #33): "/profile.php", "xp_cmdshell('whoami",
# "ATT&CK" (x2), "2023 Benchmark" -- every one contains at least one of
# these characters.
_IMPLAUSIBLE_PERSON_PATTERN = re.compile(r"[/()&]|\d")


def _is_plausible_person(text: str) -> bool:
    if _IMPLAUSIBLE_PERSON_PATTERN.search(text):
        return False

    # Real names are Title Case in normal English prose -- every
    # space/hyphen-separated word starts with an uppercase letter
    # ("Michelle Hayes-Taylor", "Sean O'Brien", "Jean-Pierre Dubois").
    # Found via 2 more real false positives (docs/all_results.md #38,
    # the PII bait-set expansion): "enforce bucket" (ordinary lowercase
    # words spaCy misread as a name) and "PII" (a short all-caps acronym,
    # flagged only in specific sentence context -- this filter doesn't
    # need to reproduce that context, it just needs to correctly reject
    # whatever span ends up matched). Ignores words that don't start with
    # a letter at all (dates, numbers already caught above).
    words = [w for w in re.split(r"[\s\-]+", text.strip()) if w]
    if not words:
        return False
    if any(w[0].islower() for w in words if w[0].isalpha()):
        return False

    # A short span that's entirely uppercase letters reads as an acronym
    # (PII, SOC, CVE, ATT&CK once the & above is stripped) -- a real name
    # isn't written ALL CAPS in normal report prose.
    letters_only = re.sub(r"[^A-Za-z]", "", text)
    if letters_only and letters_only.isupper() and len(letters_only) <= 6:
        return False

    return True


def _is_plausible_phone(text: str) -> bool:
    """
    Reject a PHONE_NUMBER match that's actually a valid IPv4 address.
    Found via a real false positive expanding the live Wazuh alert set
    (docs/all_results.md #33-adjacent, live-data bulk expansion): Presidio's
    phone recognizer gives a bare dotted-number sequence like "203.0.113.138"
    the exact same 0.4 confidence score it gives a real phone number
    ("555-284-9013" also scores 0.4) -- score alone can't discriminate them.
    IPv4 structure can: a real phone number is never four dot-separated
    groups each in 0-255 (e.g. "555.284.9013" fails on "555" > 255). This
    project's own policy already treats IP addresses as core operational
    telemetry, not personal data (module docstring), so a confirmed IPv4
    match is unambiguously not a phone number, not a judgment call.
    """
    digits_and_dots = re.sub(r"[^0-9.]", "", text)
    octets = digits_and_dots.split(".")
    if len(octets) != 4:
        return True
    if not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
        return True
    return False  # valid IPv4 -- reject as a phone number


def _analyze(text: str, entities: list) -> list:
    """
    Run Presidio's analyzer, then drop PERSON/PHONE_NUMBER matches that
    fail their plausibility checks above. Shared by detect_pii() and
    redact_text() so the filters can't drift out of sync between the two
    call sites -- both used to call the analyzer directly and
    independently.
    """
    results = _get_analyzer().analyze(text=text, language="en", entities=entities)
    plausibility_checks = {
        "PERSON": _is_plausible_person,
        "PHONE_NUMBER": _is_plausible_phone,
    }
    return [
        r for r in results
        if r.entity_type not in plausibility_checks
        or plausibility_checks[r.entity_type](text[r.start:r.end])
    ]


def detect_pii(text: str, entities: list = None) -> list:
    """
    Run Presidio's analyzer over `text`. Returns a list of dicts:
        [{"entity_type": "PERSON", "text": "John Smith", "score": 0.85,
          "start": 8, "end": 18}, ...]

    `entities` defaults to DEFAULT_ENTITIES; pass an explicit list (e.g.
    DEFAULT_ENTITIES + ["IP_ADDRESS"]) to widen the scan for analysis
    purposes without changing what gets redacted elsewhere.
    """
    if not text:
        return []
    entities = entities if entities is not None else DEFAULT_ENTITIES
    results = _analyze(text, entities)
    return [
        {
            "entity_type": r.entity_type,
            "text": text[r.start:r.end],
            "score": round(r.score, 3),
            "start": r.start,
            "end": r.end,
        }
        for r in results
    ]


def redact_text(text: str, entities: list = None) -> tuple:
    """
    Detect and redact PII in `text` in one pass. Returns
    (redacted_text, detections) where detections is detect_pii()'s output
    (computed on the ORIGINAL text, so start/end offsets and matched values
    are still meaningful for audit display even after redaction replaces
    them with placeholders like "<PERSON>").
    """
    if not text:
        return text, []

    entities = entities if entities is not None else DEFAULT_ENTITIES
    analyzer_results = _analyze(text, entities)
    if not analyzer_results:
        return text, []

    detections = [
        {
            "entity_type": r.entity_type,
            "text": text[r.start:r.end],
            "score": round(r.score, 3),
            "start": r.start,
            "end": r.end,
        }
        for r in analyzer_results
    ]

    anonymized = _get_anonymizer().anonymize(
        text=text,
        analyzer_results=[
            RecognizerResult(entity_type=r.entity_type, start=r.start, end=r.end, score=r.score)
            for r in analyzer_results
        ],
    )
    return anonymized.text, detections


def redact_report_fields(report: dict, entities: list = None) -> dict:
    """
    Scan and redact PII across REPORT_TEXT_FIELDS (threat_summary,
    recommended_action, reasoning) -- the same generated-prose surface the
    CVE/ATT&CK checkers scan, and the actual "generated analyst report"
    text T3 in docs/proposal.md is about.

    Returns:
        {
            "redacted_fields": {field: redacted_text, ...},  # only fields
                that had a non-empty original value
            "detections": [{"field": "reasoning", "entity_type": "PERSON",
                             "text": "John Smith", "score": 0.85}, ...],
            "pii_found": bool,
        }

    Non-mutating: `report` itself is left untouched, matching
    annotate_ungrounded_mentions()'s convention -- callers apply the
    returned redacted_fields onto their own copy.
    """
    redacted_fields = {}
    detections = []

    for field in REPORT_TEXT_FIELDS:
        text = report.get(field)
        if not text:
            continue
        redacted_text, field_detections = redact_text(str(text), entities=entities)
        redacted_fields[field] = redacted_text
        for d in field_detections:
            detections.append({"field": field, **d})

    return {
        "redacted_fields": redacted_fields,
        "detections": detections,
        "pii_found": len(detections) > 0,
    }
