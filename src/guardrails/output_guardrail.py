"""
src/guardrails/output_guardrail.py

Second guardrail layer — runs AFTER the LLM, on its output, rather than
before it on the input (input_guardrail.py). Purpose: catch hallucinated
CVE numbers.

Why this is a real risk: your SYSTEM_PROMPT already tells the model "do not
hallucinate CVE numbers... unless clearly indicated by the alert data" —
but that's a soft instruction, not a guarantee. Small/fast models like
llama-3.1-8b-instant are exactly the kind known to fabricate plausible-
looking CVE IDs when a report "feels like" it should cite one, even when
nothing in the input alert mentions a CVE at all.

Approach (consistent with week 2's finding: deterministic pattern matching
beats LLM-based classification for guardrails with small models):
  1. Extract any CVE-style identifiers (CVE-YYYY-NNNNN) from the LLM's
     output text.
  2. Extract any CVE identifiers that were actually present in the input
     alert (description / payload_snippet) — these are "grounded", not
     hallucinated.
  3. Any CVE in the output that is NOT in the input is flagged as
     hallucinated — the model cited a specific vulnerability that has no
     basis in the alert data it was given.

This does not use an LLM to judge itself (see week 2 rationale) — it's a
static regex extraction and set-difference, so it's fast, deterministic,
and has no false-negative risk from a second model being unreliable.

Note: this cannot verify whether a CVE that IS present in the input is
itself a *real* CVE (that would need an external CVE database lookup —
out of scope for this deterministic layer, flagged as a possible follow-up
using the NVD API if you want to extend this later).
"""

import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Fields in the agent's report that may contain model-generated prose,
# and therefore need scanning for hallucinated CVEs.
REPORT_TEXT_FIELDS = ["threat_summary", "recommended_action", "reasoning"]


def extract_cves(text: str) -> set:
    """Return the set of normalised (uppercase) CVE IDs found in text."""
    if not text:
        return set()
    return {match.upper() for match in CVE_PATTERN.findall(text)}


def check_hallucinated_cves(report: dict, alert_text: str) -> list:
    """
    Compare CVEs mentioned in the report's text fields against CVEs actually
    present in the original alert text. Returns a list of hallucinated CVE
    IDs (empty list if none / all mentioned CVEs are grounded in the input).
    """
    grounded_cves = extract_cves(alert_text)

    report_text = " ".join(
        str(report.get(field, "")) for field in REPORT_TEXT_FIELDS
    )
    mentioned_cves = extract_cves(report_text)

    hallucinated = sorted(mentioned_cves - grounded_cves)
    return hallucinated