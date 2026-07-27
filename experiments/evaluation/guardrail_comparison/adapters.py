

import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    is_flagged: bool
    score: Optional[float]
    latency_ms: float
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# 1. Baseline — your own deterministic pattern matcher
# ---------------------------------------------------------------------------

def scan_baseline(text: str) -> ScanResult:
    from src.guardrails.input_guardrail import check_injection

    start = time.perf_counter()
    try:
        flagged = check_injection(text)
        latency_ms = (time.perf_counter() - start) * 1000
        # Deterministic substring match has no confidence score — either it
        # matched a pattern or it didn't.
        return ScanResult(is_flagged=flagged, score=None, latency_ms=latency_ms)
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return ScanResult(is_flagged=False, score=None, latency_ms=latency_ms, error=str(e))


# ---------------------------------------------------------------------------
# 2. LLM Guard (Protect AI) — PromptInjection input scanner
# ---------------------------------------------------------------------------

_llm_guard_scanner = None

def _get_llm_guard_scanner():
    global _llm_guard_scanner
    if _llm_guard_scanner is None:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType
        # Default model as of llm-guard's documented usage: a local
        # HuggingFace classifier, no API calls. Threshold left at the
        # library's own default (do not tune per-framework — same defaults
        # used as ship with the library, per issue #16 constraints).
        _llm_guard_scanner = PromptInjection(match_type=MatchType.FULL)
    return _llm_guard_scanner


def scan_llm_guard(text: str) -> ScanResult:
    start = time.perf_counter()
    try:
        scanner = _get_llm_guard_scanner()
        sanitized_prompt, is_valid, risk_score = scanner.scan(text)
        latency_ms = (time.perf_counter() - start) * 1000
        # llm-guard convention: is_valid == False means the scanner flagged it
        return ScanResult(is_flagged=(not is_valid), score=float(risk_score), latency_ms=latency_ms)
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return ScanResult(is_flagged=False, score=None, latency_ms=latency_ms, error=str(e))


# ---------------------------------------------------------------------------
# 3. Pytector — local DeBERTa-based PromptInjectionDetector
#
# NOTE: Guardrails AI was the originally planned second framework, but its
# hub validator for this task (guardrails/detect_prompt_injection) has been
# pulled from the Guardrails Hub package index (confirmed: `guardrails hub
# install` fails with "Could not find a version that satisfies the
# requirement guardrails-grhub-detect-prompt-injection"). The only currently
# available replacement on the hub (sainatha/prompt_injection_detector)
# works by sending the prompt to a hosted LLM judge (defaults to OpenAI's
# gpt-3.5-turbo, requires OPENAI_API_KEY) — which would violate this issue's
# "do not send sensitive data to hosted APIs" constraint. Swapped to
# Pytector instead: pip-installable, local HuggingFace model inference
# (DeBERTa), no hosted API call in this configuration.
# ---------------------------------------------------------------------------

_pytector_detector = None

def _get_pytector_detector():
    global _pytector_detector
    if _pytector_detector is None:
        from pytector import PromptInjectionDetector
        _pytector_detector = PromptInjectionDetector(model_name_or_url="deberta")
    return _pytector_detector


def scan_pytector(text: str) -> ScanResult:
    start = time.perf_counter()
    try:
        detector = _get_pytector_detector()
        is_injection, probability = detector.detect_injection(text)
        latency_ms = (time.perf_counter() - start) * 1000
        return ScanResult(is_flagged=bool(is_injection), score=probability, latency_ms=latency_ms)
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return ScanResult(is_flagged=False, score=None, latency_ms=latency_ms, error=str(e))


IMPLEMENTATIONS = {
    "baseline": scan_baseline,
    "llm_guard": scan_llm_guard,
    "pytector": scan_pytector,
}