"""
src/guardrails/grounding_utils.py

Shared building blocks for the output guardrail's grounding+verify
checkers (output_guardrail.py for CVEs, attack_grounding.py for MITRE
ATT&CK technique IDs). Both follow the same pattern — extract a claimed
identifier, check if it's grounded in the input alert, verify against an
authoritative external source if not, classify, annotate inline — and the
identifier-agnostic parts of that pattern (which report fields to scan,
the topical-overlap scorer, inline annotation) live here once instead of
being duplicated per identifier type.
"""

import re

# Fields in the agent's report that may contain model-generated prose, and
# therefore need scanning for hallucinated claims (CVEs, ATT&CK technique
# IDs, or any future identifier type following this same pattern).
REPORT_TEXT_FIELDS = ["threat_summary", "recommended_action", "reasoning"]

# Words too common to count as meaningful topical overlap (kept small and
# security-domain-aware rather than a full stopword list).
_STOPWORDS = {
    "the", "a", "an", "of", "in", "on", "to", "and", "or", "is", "was",
    "for", "with", "that", "this", "by", "as", "be", "are", "from", "at",
    "attack", "attacker", "vulnerability", "vulnerabilities", "detected",
    "allows", "allow", "via", "used", "known", "server", "system",
}


def _stem(word: str) -> str:
    """
    Lightweight deterministic suffix-stripping stemmer — not a real
    linguistic stemmer (no Porter/Snowball dependency added), just enough
    to collapse common morphological variants that show up constantly in
    security prose: "execution"/"execute", "exploitation"/"exploit",
    "attacker"/"attack", "vulnerabilities"/"vulnerability". Order matters —
    longer/more specific suffixes are checked first so "execution" doesn't
    get stripped to "executio" by the "-s" rule before "-ion" gets a
    chance.
    """
    suffixes = [
        "ational", "ization", "isation", "ariser", "ations", "ication",
        "ibility", "ariser",
        "ation", "ition", "ition",
        "ingly", "edly",
        "ities", "ivity",
        "ers", "ing", "ion", "ive", "ily", "ies", "ied",
        "er", "ed", "ly", "al", "ic",
        "es", "s",
    ]
    w = word
    matched = False
    for suf in suffixes:
        if w.endswith(suf) and len(w) - len(suf) >= 4:
            w = w[: -len(suf)]
            matched = True
            break

    # Fallback: verbs like "execute", "isolate", "mitigate" don't end in
    # any of the suffixes above (they end in a bare "-e"), so without this
    # they'd never collapse with their "-ion" derived nouns
    # ("execution"->"execut" via the "ion" rule above, but "execute" would
    # stay "execute" unchanged — two different stems for the same concept).
    # Only applied when nothing else matched, so it doesn't interfere with
    # words already handled by a more specific suffix rule.
    if not matched and w.endswith("e") and len(w) - 1 >= 4:
        w = w[:-1]
    return w


def _topical_overlap(text_a: str, text_b: str) -> float:
    """
    Crude but deterministic topical similarity: fraction of significant
    (stemmed) words in text_a (typically the alert description) that also
    appear in text_b (typically the external source's description). No
    embeddings, no LLM — bag-of-words overlap with light stemming,
    consistent with keeping this guardrail layer fully deterministic.

    Stemming matters here specifically because alert prose and an external
    source's description prose use different grammatical forms of the same
    underlying concept ("exploitation" vs "exploit", "execution" vs
    "execute") — without stemming, a genuinely correct citation can score
    near-zero overlap purely on word-form mismatch, not topical mismatch.
    """
    def significant_stems(t):
        # letter-led alphanumeric tokens, length >= 4 — deliberately keeps
        # terms like "log4j", "sha256" intact. A letters-only pattern would
        # split "log4j" into "log" (too short, discarded) and "j"
        # (discarded) — silently losing exactly the kind of specific
        # technical term that matters most for topical matching.
        words = re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", t.lower())
        return {_stem(w) for w in words if w not in _STOPWORDS}

    stems_a = significant_stems(text_a or "")
    stems_b = significant_stems(text_b or "")
    if not stems_a or not stems_b:
        return 0.0
    overlap = stems_a & stems_b
    return len(overlap) / len(stems_a)


def annotate_ungrounded_mentions(report: dict, verifications: list, id_key: str = "cve_id") -> dict:
    """
    Return a copy of `report` with every ungrounded mention in
    REPORT_TEXT_FIELDS tagged inline with its classification.

    The sibling JSON fields each checker exposes (e.g. `hallucinated_cves`,
    `cve_verifications`) already carry this information, but an analyst
    reading threat_summary/recommended_action/reasoning as prose has no way
    to tell WHERE in that text the ungrounded claim is from those sibling
    fields alone — they'd have to cross-reference an identifier against a
    separate list while reading. Tagging the mention in place puts the
    warning where the analyst is actually looking.

    Generic over the identifier field name (`id_key`) so both the CVE
    checker (id_key="cve_id") and the ATT&CK checker
    (id_key="technique_id") share one implementation rather than
    duplicating this per identifier type.

    Non-mutating: `report` itself is left untouched, a new dict is
    returned.
    """
    if not verifications:
        return report

    tags = {v[id_key]: v["classification"] for v in verifications}
    annotated = dict(report)

    for field in REPORT_TEXT_FIELDS:
        text = annotated.get(field)
        if not text:
            continue
        for identifier, classification in tags.items():
            pattern = re.compile(re.escape(identifier), re.IGNORECASE)
            text = pattern.sub(f"{identifier} [⚠ ungrounded — {classification}]", text)
        annotated[field] = text

    return annotated
