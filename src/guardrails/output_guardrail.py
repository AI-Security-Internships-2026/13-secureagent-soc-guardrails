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

Two-stage approach:
  Stage 1 (grounding check, deterministic, no network):
    - Extract CVE-style identifiers (CVE-YYYY-NNNNN) from the LLM's output.
    - Extract any CVE identifiers present in the input alert.
    - Anything in the output but not in the input is "ungrounded" — the
      model cited something the alert never gave it.

  Stage 2 (NVD verification, optional, requires network):
    - For each ungrounded CVE, query the real NVD (National Vulnerability
      Database) to check two things: (a) does this CVE ID actually exist,
      and (b) does its real description topically match the alert's
      description. This distinguishes three cases that Stage 1 alone
      cannot tell apart:
        FABRICATED       — the CVE ID doesn't exist in NVD at all. This is
                            an outright invented identifier.
        REAL_BUT_IRRELEVANT — the CVE is real, but its description has no
                            topical overlap with the alert. The model
                            picked a real but wrong CVE.
        REAL_AND_PLAUSIBLE  — the CVE is real AND topically matches. The
                            model likely recalled a genuinely correct CVE
                            from training data — still ungrounded (the
                            alert didn't supply it), but not a fabrication.
        UNVERIFIED        — NVD lookup failed (no network, rate limited,
                            NVD down). Cannot classify further; treat as
                            "flagged, unverified" rather than assuming
                            either fabricated or real.

Consistent with week 2's finding (deterministic beats LLM-based
classification for guardrails with small models): Stage 2 is a real
external database lookup, not a second LLM call — it adds ground truth,
not another unreliable judgment.
"""

import re
import time
import urllib.request
import urllib.error
import json as _json

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Fields in the agent's report that may contain model-generated prose,
# and therefore need scanning for hallucinated CVEs.
REPORT_TEXT_FIELDS = ["threat_summary", "recommended_action", "reasoning"]

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Simple in-process cache so repeated runs / repeated CVEs across a batch
# don't re-hit the API unnecessarily. NVD's public (no-API-key) rate limit
# is ~5 requests per 30 seconds — this cache plus the sleep in
# _query_nvd() keeps you under that during a batch test run.
_nvd_cache = {}

# Words too common to count as meaningful topical overlap (kept small and
# security-domain-aware rather than a full stopword list).
_STOPWORDS = {
    "the", "a", "an", "of", "in", "on", "to", "and", "or", "is", "was",
    "for", "with", "that", "this", "by", "as", "be", "are", "from", "at",
    "attack", "attacker", "vulnerability", "vulnerabilities", "detected",
    "allows", "allow", "via", "used", "known", "server", "system",
}


def extract_cves(text: str) -> set:
    """Return the set of normalised (uppercase) CVE IDs found in text."""
    if not text:
        return set()
    return {match.upper() for match in CVE_PATTERN.findall(text)}


def _query_nvd(cve_id: str, timeout: float = 8.0, max_retries: int = 3) -> dict:
    """
    Query the real NVD for a given CVE ID. Returns:
        {"exists": True, "description": "..." or None, "rejected": bool}
        {"exists": False, "description": None, "rejected": False}   if NVD says it doesn't exist
        {"exists": None, "description": None, "error": "..."}       on network/API failure

    Retries with backoff on NVD rate limiting (HTTP 403/429). NVD's public
    (no-API-key) limit is roughly 5 requests per rolling 30-second window —
    a single alert citing several new CVEs can trip this even with the
    1-second inter-call delay below, so a transient rate-limit response
    should be retried, not treated as a permanent failure.

    Cached per CVE ID within the process to avoid redundant calls.
    """
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]

    url = f"{NVD_API_URL}?cveId={cve_id}"

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecureAgent-SOC/output-guardrail"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = _json.loads(resp.read().decode("utf-8"))

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                result = {"exists": False, "description": None, "rejected": False}
            else:
                cve_data = vulnerabilities[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
                # NVD marks withdrawn/invalid/duplicate CVE IDs with a
                # vulnStatus of "Rejected" and a description that starts
                # with "** REJECTED **" rather than removing the ID
                # entirely. Citing one of these is a distinct, more
                # concerning case than citing a real-but-mismatched CVE —
                # the ID technically exists but was never a valid
                # vulnerability record.
                vuln_status = cve_data.get("vulnStatus", "")
                is_rejected = (
                    vuln_status.lower() == "rejected"
                    or (en_desc is not None and en_desc.strip().upper().startswith("** REJECTED **"))
                )
                result = {"exists": True, "description": en_desc, "rejected": is_rejected}

            _nvd_cache[cve_id] = result
            # Stay comfortably under NVD's public rate limit (~5 req/30s)
            # across multiple ungrounded CVEs checked in one run.
            time.sleep(1.0)
            return result

        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < max_retries - 1:
                wait = 5.0 * (2 ** attempt)
                time.sleep(wait)
                continue
            result = {"exists": None, "description": None, "error": f"HTTP {e.code}: {e}"}
            return result

        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            result = {"exists": None, "description": None, "error": str(e)}
            # Don't cache failures — a transient network blip shouldn't
            # permanently mark a CVE as unverifiable for the rest of the run.
            return result

    # Exhausted retries on rate limiting
    return {"exists": None, "description": None, "error": "NVD rate limit persisted after retries"}


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
    appear in text_b (typically the NVD CVE description). No embeddings, no
    LLM — bag-of-words overlap with light stemming, consistent with keeping
    this guardrail layer fully deterministic.

    Stemming matters here specifically because alert prose and NVD's
    CVSS-style description prose use different grammatical forms of the
    same underlying concept ("exploitation" vs "exploit", "execution" vs
    "execute") — without stemming, a genuinely correct CVE match can score
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


def verify_cve(cve_id: str, alert_text: str, overlap_threshold: float = 0.15) -> dict:
    """
    Classify a single ungrounded CVE mention against real NVD data.

    Returns a dict:
        {
            "cve_id": "CVE-2021-44228",
            "classification": "FABRICATED" | "REJECTED" | "REAL_BUT_IRRELEVANT"
                             | "REAL_AND_PLAUSIBLE" | "UNVERIFIED",
            "nvd_description": "..." or None,
            "topical_overlap": 0.0-1.0 or None,
        }

    Edge cases handled explicitly (not left to fall through silently):
      - REJECTED: the CVE ID exists in NVD's records but was withdrawn,
        never valid, or is a duplicate (NVD's own "** REJECTED **" status).
        Citing one of these is a distinct, more concerning case than citing
        a real-but-mismatched CVE — the ID exists but was never a genuine
        vulnerability record, so it's closer to a fabrication than a
        legitimate-but-wrong citation.
      - Missing English description: some CVE records don't have an "en"
        description. Without a description there's nothing to topically
        compare against, so this is reported as UNVERIFIED ("couldn't
        check") rather than silently scoring 0 overlap and landing in
        REAL_BUT_IRRELEVANT for the wrong reason.
    """
    nvd_result = _query_nvd(cve_id)

    if nvd_result.get("exists") is None:
        return {
            "cve_id": cve_id,
            "classification": "UNVERIFIED",
            "nvd_description": None,
            "topical_overlap": None,
        }

    if nvd_result["exists"] is False:
        return {
            "cve_id": cve_id,
            "classification": "FABRICATED",
            "nvd_description": None,
            "topical_overlap": None,
        }

    if nvd_result.get("rejected"):
        return {
            "cve_id": cve_id,
            "classification": "REJECTED",
            "nvd_description": nvd_result["description"],
            "topical_overlap": None,
        }

    if not nvd_result["description"]:
        return {
            "cve_id": cve_id,
            "classification": "UNVERIFIED",
            "nvd_description": None,
            "topical_overlap": None,
        }

    overlap = _topical_overlap(alert_text, nvd_result["description"])
    classification = "REAL_AND_PLAUSIBLE" if overlap >= overlap_threshold else "REAL_BUT_IRRELEVANT"

    return {
        "cve_id": cve_id,
        "classification": classification,
        "nvd_description": nvd_result["description"],
        "topical_overlap": round(overlap, 3),
    }


def check_hallucinated_cves(report: dict, alert_text: str, verify_with_nvd: bool = True) -> list:
    """
    Compare CVEs mentioned in the report's text fields against CVEs actually
    present in the original alert text. Returns a list of ungrounded CVE
    IDs (empty list if none / all mentioned CVEs are grounded in the input).

    This is Stage 1 only (grounding), kept as its own function so existing
    callers/tests that just want "is this CVE in the input or not" keep
    working unchanged. Use check_hallucinated_cves_verified() for the full
    two-stage check including NVD verification.
    """
    grounded_cves = extract_cves(alert_text)
    report_text = " ".join(str(report.get(field, "")) for field in REPORT_TEXT_FIELDS)
    mentioned_cves = extract_cves(report_text)
    return sorted(mentioned_cves - grounded_cves)


def check_hallucinated_cves_verified(report: dict, alert_text: str, verify_with_nvd: bool = True) -> dict:
    """
    Full two-stage check. Returns:
        {
            "ungrounded_cves": ["CVE-...", ...],
            "verifications": [ {cve_id, classification, nvd_description, topical_overlap}, ... ],
            "flagged": bool,          # True if ANY CVE was cited that wasn't
                                      # in the input — regardless of whether
                                      # it later verifies as real/correct.
                                      # This is the "did the model cite
                                      # something ungrounded at all" signal
                                      # and should never silently read False
                                      # just because the citation happened
                                      # to be accurate.
            "requires_review": bool,  # True only if at least one ungrounded
                                      # CVE is FABRICATED, REAL_BUT_IRRELEVANT,
                                      # or UNVERIFIED — i.e. actually
                                      # suspicious, not just ungrounded. A
                                      # REAL_AND_PLAUSIBLE-only result leaves
                                      # this False.
        }

    Keeping these as two separate fields (rather than one collapsed
    "flagged" bool) matters: collapsing them means a correctly-recalled CVE
    (REAL_AND_PLAUSIBLE) reports identically to "nothing happened at all" —
    a summary metric built on that collapsed field would show 0% even in a
    run where the two-stage system actually caught and verified a citation.
    `flagged` preserves visibility that something was detected; `requires_review`
    is the stricter signal for whether it's actually worth an analyst's attention.
    """
    ungrounded = check_hallucinated_cves(report, alert_text)

    verifications = []
    for cve_id in ungrounded:
        if verify_with_nvd:
            verifications.append(verify_cve(cve_id, alert_text))
        else:
            verifications.append({
                "cve_id": cve_id,
                "classification": "UNVERIFIED",
                "nvd_description": None,
                "topical_overlap": None,
            })

    flagged = len(ungrounded) > 0
    # Every ungrounded citation requires review, regardless of classification
    # tier. REAL_AND_PLAUSIBLE previously auto-cleared review on the
    # assumption that a topical-overlap match above threshold meant "likely
    # correct" — but that overlap score is a crude bag-of-words heuristic,
    # not proof the cited CVE actually applies to THIS alert. Worse,
    # REAL_AND_PLAUSIBLE is the most convincing-looking case (real CVE,
    # on-topic), so an analyst is least likely to double-check it — exactly
    # the wrong case to auto-clear. The classification still tells the
    # analyst WHY it was flagged (fabricated vs. real-but-wrong vs.
    # plausible-but-unverified-for-this-alert vs. couldn't check); it no
    # longer decides FOR them whether it's worth a look.
    requires_review = len(ungrounded) > 0

    return {
        "ungrounded_cves": ungrounded,
        "verifications": verifications,
        "flagged": flagged,
        "requires_review": requires_review,
    }