# Minimal reproducibility image for LLMCite paper.
# Build:  docker build -t llmcite .
# Run:    docker run --rm llmcite                         # Smoke: schema-parity test (offline, no API key needed)
# Run:    docker run --rm -e GROQ_API_KEY=$GROQ_API_KEY llmcite /bin/bash -c "cd /app && pytest tests/ -v"
# ---------------------------------------------------------------------------
# IMPORTANT (Reviewer / Student note):
# This is a REPRODUCIBILITY image only. It is NOT a web service, REST server,
# frontend, or deployment target. FastAPI / Uvicorn / Kubernetes /
# Streamlit-as-a-service are out of scope.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system deps (spacy models need wget/curl sometimes; slim image is minimal)
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# FIRST copy ONLY requirements-lock.txt and install -- this maximizes Docker layer caching
# (if only source code changes below, this cached layer is reused, pip install doesn't re-run)
COPY requirements-lock.txt /app/requirements-lock.txt
RUN pip install --upgrade pip \
 # torch's default PyPI wheel drags in ~2-3GB of NVIDIA CUDA libraries
 # (cudnn, cusparselt, nccl, cublas, ...) that this CPU-only, GPU-less
 # reproducibility image never uses. Installing the CPU-only build first,
 # pinned to the exact version requirements-lock.txt expects, satisfies
 # that pin so the subsequent full install doesn't pull the GPU variant.
 && pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu \
 && pip install -r requirements-lock.txt \
 && python -m spacy download en_core_web_sm

# Pre-warm pytector's prompt-injection classifier (HuggingFace
# protectai/deberta-v3-base-prompt-injection, ~350MB) into the image at
# build time, the same reason spacy's model is downloaded above rather
# than left for first use. Without this, the very first `docker run`
# silently triggers a live multi-hundred-MB download from the HF Hub --
# directly contradicting this image's "offline, no API key needed"
# claim, since src/guardrails/input_guardrail.py's Pytector fallback is
# exercised by the default schema-parity CMD below. model_name_or_url
# matches that module's own instantiation exactly.
RUN python -c "from pytector import PromptInjectionDetector; PromptInjectionDetector(model_name_or_url='deberta')"

# Once cached, force transformers/huggingface_hub to skip their default
# network freshness-check (a HEAD request against the Hub even when the
# model is already cached locally) -- without this, "offline" would
# still make one small network call per run.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

# NOW copy the rest of the repository (code, data snapshots, tests).
COPY . /app/

# Sanity imports (fail build EARLY if langchain-groq is missing despite E1 lockfile -- catches drift)
RUN python -c "from langchain_groq import ChatGroq ; from groq import Groq ; from src.agent.soc_agent import analyse_alert ; print('imports OK')"

# Default target: run the OFFLINE schema-parity test (no API key required).
# This proves the image runs end-to-end with mocked LLM.
CMD ["pytest", "tests/test_soc_agent_schema_parity.py", "-v", "--no-header"]
