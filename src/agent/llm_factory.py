"""
src/agent/llm_factory.py

DRAFT, NOT YET WIRED IN. Nothing in this project imports this file --
it's a sketch of a backend-switchable LLM client, written for review
before deciding whether to actually adopt it. No existing ChatGroq(...)
call site has been touched.

Why this exists: every result this project has published so far was
generated via Groq's hosted API. Groq's free-tier quota (daily and
per-minute limits) has repeatedly blocked or delayed experiments --
see docs/all_results.md #61 (a 3-day silent quota stall) and #66-#67
(the ATT&CK replication needing two separate multi-hour sessions across
two calendar days purely from quota). Self-hosted compute (e.g. a lab
GPU server reachable over VPN) has no such limit, but switching the
inference backend is NOT a transparent, risk-free swap:

  - A different serving stack (e.g. vLLM) running "the same" open-weight
    model can produce different generations than Groq's own hardware for
    the same prompt/temperature, especially at the higher sampling
    temperatures this project's statistical tests depend on (0.7 for
    SelfCheckGPT resampling). Mixing Groq-generated and self-hosted-
    generated data into the same statistical comparison would be an
    undisclosed confound.
  - Latency/throughput numbers from one backend are not comparable to
    the other at all -- Sect. 4.10.4's concurrency benchmark is
    specifically a measurement of Groq's own hardware and should never
    be re-run against a different backend and treated as the same
    result.

Because of this, LLM_BACKEND defaults to "groq" -- the exact, unchanged,
already-published behavior -- and only switches on an explicit opt-in
env var. Every result this factory helps produce should record which
backend generated it (see `llm_backend` field convention in the
docstring below) so a mixed-backend result set is never silently
treated as directly comparable.

Usage (once actually wired into a call site):
    from src.agent.llm_factory import get_llm, LLM_BACKEND

    llm = get_llm(model=MODEL_NAME, temperature=0.1)
    # ... use llm exactly as a ChatGroq/ChatOpenAI instance ...
    result["llm_backend"] = LLM_BACKEND   # record provenance in every output row

    LLM_BACKEND=groq       python -m experiments.evaluation.some_script       # today's behavior, unchanged
    LLM_BACKEND=selfhosted SELFHOSTED_LLM_BASE_URL=http://<cnit-host>:8000/v1 \\
        python -m experiments.evaluation.some_script
"""

import os

from langchain_groq import ChatGroq

LLM_BACKEND = os.getenv("LLM_BACKEND", "groq")  # "groq" | "selfhosted"


def get_llm(model: str, temperature: float, **kwargs):
    """
    Returns a LangChain chat-model client for `model` at `temperature`,
    routed to whichever backend LLM_BACKEND selects. Drop-in replacement
    for a direct `ChatGroq(...)` call -- same `.invoke()` interface
    either way, since both LangChain integrations implement the same
    BaseChatModel contract.
    """
    if LLM_BACKEND == "groq":
        return ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model=model, temperature=temperature, **kwargs)

    if LLM_BACKEND == "selfhosted":
        # Most self-hosted inference servers (vLLM's own OpenAI-compatible
        # server being the most common choice for exactly this use case)
        # expose an OpenAI-compatible /v1/chat/completions endpoint, so
        # langchain-openai's ChatOpenAI -- pointed at that server instead
        # of api.openai.com -- is the standard, lowest-effort way to talk
        # to it. Deliberately deferred as a local import: this path is
        # unused by default, so a bare Groq-only install doesn't need
        # langchain-openai installed at all unless someone opts in.
        from langchain_openai import ChatOpenAI

        base_url = os.environ.get("SELFHOSTED_LLM_BASE_URL")
        if not base_url:
            raise RuntimeError(
                "LLM_BACKEND=selfhosted requires SELFHOSTED_LLM_BASE_URL "
                "(e.g. http://<cnit-host>:8000/v1) to be set."
            )
        return ChatOpenAI(
            base_url=base_url,
            api_key=os.getenv("SELFHOSTED_LLM_API_KEY", "not-needed"),  # vLLM's default server doesn't require a real key
            model=model,
            temperature=temperature,
            **kwargs,
        )

    raise ValueError(f"Unknown LLM_BACKEND={LLM_BACKEND!r}, expected 'groq' or 'selfhosted'")


def get_retryable_exceptions() -> tuple:
    """
    The exception type(s) worth retrying-with-backoff on, backend-
    dependent -- groq.RateLimitError (used in 4+ places across this
    project already, e.g. src/guardrails/selfcheckgpt.py,
    experiments/evaluation/ablation_study.py) is Groq-specific and
    meaningless against a self-hosted endpoint, which fails differently
    (connection refused, timeout, HTTP 5xx from an overloaded server)
    rather than a quota-style 429. NOT yet used by any retry loop in
    this project -- each existing `except RateLimitError:` call site
    would need updating individually to use this instead of hardcoding
    the Groq-specific exception, if this factory is ever actually
    adopted for a given script.
    """
    if LLM_BACKEND == "groq":
        from groq import RateLimitError
        return (RateLimitError,)

    import httpx
    return (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError)
