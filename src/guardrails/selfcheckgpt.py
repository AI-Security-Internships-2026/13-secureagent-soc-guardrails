"""
src/guardrails/selfcheckgpt.py

A SelfCheckGPT-style (Manakul et al., 2023) hallucination-detection
baseline, alongside the deterministic grounding checkers
(output_guardrail.py, attack_grounding.py) and the LLM-judge baseline
(llm_judge.py). All three answer "is this citation a hallucination," but
by fundamentally different mechanisms:

  - deterministic / LLM-judge: is this claim supported by the ALERT'S OWN
    EVIDENCE (external grounding).
  - SelfCheckGPT: does the model keep making the SAME claim when resampled
    at temperature > 0 (internal self-consistency, no evidence needed at
    all -- this is what makes it attractive as a baseline: it works even
    when there's no retrieval source to check against).

This is a real, structural blind spot worth stating plainly, not
discovering by surprise in the results: a claim the model is confidently
(but wrongly) biased toward from training data can be perfectly
self-consistent across resamples while still being completely ungrounded
in the alert's actual evidence. SelfCheckGPT alone cannot distinguish
"consistently correct" from "consistently, confidently wrong" -- only the
evidence-grounding checkers can. See docs/all_results.md for whether this
project's own data actually produced an example of that failure mode.

NOT wired into src/agent/soc_agent.py's live pipeline -- benchmark-only,
same as llm_judge.py and the hybrid_llmguard trial adapter.
"""

import json
import re
import time
from collections import Counter

from groq import RateLimitError
from langchain_core.messages import SystemMessage, HumanMessage

from src.agent.soc_agent import SYSTEM_PROMPT, format_alert

# Sampling needs real stochastic diversity to have any signal at all --
# the production pipeline's temperature=0.1 (soc_agent.py) is deliberately
# near-deterministic and would make every resample nearly identical,
# defeating the point. 0.7 matches the diversity level typically used in
# SelfCheckGPT-style resampling in the literature.
SAMPLING_TEMPERATURE = 0.7


def _extract_report_text(content: str) -> str:
    """
    Parse one sampled response into its combined reasoning text. Falls back
    to the raw content on a JSON parse failure (rather than dropping the
    sample) since even an unparseable response might still contain a
    citation worth extracting -- consistent with soc_agent.py's own
    fallback-on-parse-failure behaviour.
    """
    try:
        report = json.loads(content)
    except json.JSONDecodeError:
        return content
    fields = ["threat_summary", "recommended_action", "reasoning"]
    return " ".join(str(report.get(field, "")) for field in fields)


def sample_citations(llm, alert, extract_fn, n_samples: int = 5,
                      max_retries: int = 5, base_delay: float = 8.0) -> list:
    """
    Generate n_samples independent completions for `alert` at
    SAMPLING_TEMPERATURE and return the list of identifier sets extracted
    from each (via `extract_fn`, e.g. extract_cves / extract_attack_ids).
    Bypasses the guardrail pipeline entirely (no input-guardrail check, no
    NVD/MITRE verification, no annotation) -- only the raw generator's
    citation behaviour across resamples is being tested here, not the full
    guardrailed system.
    """
    alert_text = format_alert(alert)
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Analyse this security alert and produce a threat report:\n{alert_text}"),
    ]

    samples = []
    for _ in range(n_samples):
        for attempt in range(max_retries):
            try:
                response = llm.invoke(messages)
                break
            except RateLimitError:
                if attempt == max_retries - 1:
                    raise
                time.sleep(base_delay * (2 ** attempt))
        report_text = _extract_report_text(response.content)
        samples.append(extract_fn(report_text))

    return samples


def consistency_score(samples: list, agreement_threshold: float = 0.6) -> dict:
    """
    Score a list of identifier sets (one per resample) for self-consistency.

    "Majority identifier" is the single ID that appears in the most
    samples (ties broken by first-seen order). Samples that cite nothing
    are excluded from the vote itself but still count in the denominator
    for agreement_rate, since consistently citing NOTHING is itself a form
    of consistency (matches BAIT-011's observed "declines to guess"
    behaviour in the original bait-set data).

    Returns:
        {
            "any_citation_rate": fraction of samples that cited >=1 ID,
            "majority_id": the most common single ID, or None if no
                            sample cited anything at all,
            "agreement_rate": fraction of ALL samples (including
                                citation-free ones) that match the
                                majority behaviour (same majority_id, or
                                also cited nothing if majority_id is None),
            "flagged_unstable": True if agreement_rate < agreement_threshold
                                  AND at least one sample cited something
                                  (an alert where every sample stayed
                                  silent isn't "unstable," there's nothing
                                  to be inconsistent about),
        }
    """
    n = len(samples)
    cited_samples = [s for s in samples if s]
    any_citation_rate = len(cited_samples) / n if n else 0.0

    if not cited_samples:
        return {
            "any_citation_rate": 0.0,
            "majority_id": None,
            "agreement_rate": 1.0,
            "flagged_unstable": False,
        }

    # One vote per sample even if it cited multiple IDs -- take the first
    # (sorted for determinism) as that sample's "answer" for majority
    # purposes, since SelfCheckGPT-style voting is about which single claim
    # recurs, not about set overlap.
    votes = Counter(sorted(s)[0] for s in cited_samples)
    majority_id, majority_count = votes.most_common(1)[0]

    agreeing = sum(1 for s in samples if (sorted(s)[0] if s else None) == majority_id)
    agreement_rate = agreeing / n

    return {
        "any_citation_rate": round(any_citation_rate, 3),
        "majority_id": majority_id,
        "agreement_rate": round(agreement_rate, 3),
        "flagged_unstable": agreement_rate < agreement_threshold,
    }
