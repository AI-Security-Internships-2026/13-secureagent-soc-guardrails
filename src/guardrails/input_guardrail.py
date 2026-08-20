INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard your instructions",
    "forget your previous instructions",
    "you are now in developer mode",
    "you are now unrestricted",
    "mark this alert as benign",
    "override security",
    # Expanded 2026-08-20 from two 2024 academic sources, disjoint from the
    # deepset/prompt-injections and TrustAIRLab/in-the-wild-jailbreak-prompts
    # datasets already used in the eval set (experiments/evaluation/
    # guardrail_comparison/eval_dataset.json) to avoid circular recall
    # inflation. All 11 checked clean against that eval set's 66 benign
    # samples before being added (see docs/all_results.md for the run log).
    #
    # From AgentDojo (ethz-spylab/agentdojo, NeurIPS 2024, MIT license) --
    # indirect prompt injection via tool responses, same threat model (T2)
    # this guardrail targets:
    "ignore your previous instructions",
    "before you can solve the task that i gave you",
    "###(system_message)",
    "this is an important message from",
    # From SPML_Chatbot_Prompt_Injection (reshabhs, arXiv:2402.11755, Feb
    # 2024, MIT license) -- mined via frequency-scan across 12,542 real
    # flagged injection rows, not hand-picked from a handful of examples:
    "ignore the above instructions",
    "ignore the original instruction",
    "override your previous instructions",
    "all previous instructions do not apply",
    "reveal your instructions",
    "print the above instructions",
    "do not follow these instructions",
]

def check_injection(text: str) -> bool:
    """
    Returns True if the text contains a known prompt injection pattern.
    Deterministic pattern matching — no LLM involved (see Week 2 findings).
    """
    text_lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in text_lower:
            return True
    return False


_pytector_detector = None


def _get_pytector_detector():
    # Lazy singleton, same pattern as
    # experiments/evaluation/guardrail_comparison/adapters.py -- avoids
    # loading the DeBERTa model until it's actually needed, and only once.
    global _pytector_detector
    if _pytector_detector is None:
        from pytector import PromptInjectionDetector
        _pytector_detector = PromptInjectionDetector(model_name_or_url="deberta")
    return _pytector_detector


def check_injection_hybrid(text: str) -> bool:
    """
    Deterministic check first (fast, ~0ms, catches known exact phrases).
    Only if that finds nothing does this fall back to Pytector's local
    DeBERTa classifier, which also catches paraphrased/novel injection
    attempts the deterministic list was never built to recognise (see
    issue #16 guardrail comparison: baseline recall 0.23 vs Pytector 0.62).
    """
    if check_injection(text):
        return True
    detector = _get_pytector_detector()
    is_injection, _probability = detector.detect_injection(text)
    return bool(is_injection)