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
    results = _get_analyzer().analyze(text=text, language="en", entities=entities)
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
    analyzer_results = _get_analyzer().analyze(text=text, language="en", entities=entities)
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
