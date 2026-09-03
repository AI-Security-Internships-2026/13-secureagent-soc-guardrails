# E4 · Top-Level Dockerfile (Reproducible Runtime)
- **Labels:** engineering, reproducibility, priority:P1
- **Milestone:** M4 — Reproducibility & Release
- **Depends on:** E1 (requirements-lock.txt MUST be committed to repo first — build will fail without it.)
- **Acceptance items:** 4

---

## Summary
The manuscript's Data-Availability section says "all code is available on GitHub" — that's the minimum. Adding a **top-level Dockerfile** means that statement becomes a single command: `docker build . && docker run`. For a reviewer in 2030 who doesn't have Python 3.11 / WSL2 / correct apt mirrors / spacy mirror, the Dockerfile is the difference between "runs after a 10-min setup" and "can't run."

The Dockerfile is NOT for production deployment, not for a service, not for Wazuh stack, not for Streamlit UI — just a minimal reproducibility image that runs the schema-parity test on build.

---

## Task 1 — Write Dockerfile
Create `Dockerfile` at the repository root:

```dockerfile
# Minimal reproducibility image for LLMCite paper.
# Build:  docker build -t llmcite .
# Run:    docker run --rm llmcite                         # Smoke: schema-parity test (offline, no API key needed)
# Run:    docker run --rm -e GROQ_API_KEY=$GROQ_API_KEY llmcite /bin/bash -c "cd /app && pytest tests/ -v"
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system deps (spacy models need wget/curl sometimes; slim image is minimal)
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# FIRST copy ONLY requirements-lock.txt and install — this maximizes Docker layer caching
# (if only source code changes below, this cached layer is reused, pip install doesn't re-run)
COPY requirements-lock.txt /app/requirements-lock.txt
RUN pip install --upgrade pip \
 && pip install -r requirements-lock.txt \
 && python -m spacy download en_core_web_sm

# NOW copy the rest of the repository (code, data snapshots, tests).
# NVD snapshot dir will be added here after completing E3.
COPY . /app/

# Sanity imports (fail build EARLY if langchain-groq is missing despite E1 lockfile — catches drift)
RUN python -c "from langchain_groq import ChatGroq ; from groq import Groq ; from src.agent.soc_agent import analyse_alert ; print('imports OK')"

# Default target: run the OFFLINE schema-parity test (no API key required).
# This proves the image runs end-to-end with mocked LLM.
CMD ["pytest", "tests/test_soc_agent_schema_parity.py", "-v", "--no-header"]
```

Also add a `.dockerignore` at the root so COPY . doesn't bring in garbage:
```
.git
.gitignore
.venv*
__pycache__
*.pyc
*.pyo
node_modules
_tmp*
.trae
.vscode
Wazuh/
data/nvd_snapshot/*.json.bak
experiments/results/_scratch*
```

- [ ] **AC1:** `Dockerfile` + `.dockerignore` committed at repo root.

---

## Task 2 — Verify Build on WSL2 (Docker Desktop running)
Per user rules: **Docker Desktop must be used for container requirement.**

Run on WSL2:
```bash
# First, check if python:3.11-slim is ALREADY cached locally (per user rule "Always check for already installed docker images before creating new ones")
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^python:3\.11-slim$' || true
# If it's not downloaded, pull is fine; if it is, build uses cached local image.

cd /mnt/d/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails
docker build -t llmcite --no-cache . 2>&1 | tee /tmp/docker_build.log
# Expected: Last line prints schema-parity test passes — all green 145/N assertions.
# Expected: Step "Sanity imports" prints "imports OK".
```

Also test the GROQ run line (optional, only if you have a key set):
```bash
docker run --rm -e GROQ_API_KEY=$GROQ_API_KEY llmcite /bin/bash -c "cd /app && pytest tests/ -v --tb=short"
# Expected: 145 passed, 1 skipped.
```

Save `/tmp/docker_build.log` as `tests/docker_build.log` and commit it.

- [ ] **AC2:** `docker build --no-cache` succeeds. Schema-parity CMD output shows all-green tests. `tests/docker_build.log` committed.

---

## Task 3 — Add One-Line Instructions to README
Edit [README.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/README.md), under a new `## Reproducibility via Docker` heading:

```markdown
## Reproducibility via Docker

We ship a minimal reproducibility image that runs the offline mocked schema-parity test at the end of `docker build` — no API key required.

```bash
docker build -t llmcite .
docker run --rm llmcite
```

To run the full test suite you will need a valid `GROQ_API_KEY` environment variable (see main README for setup):
```bash
docker run --rm -e GROQ_API_KEY=$GROQ_API_KEY llmcite /bin/bash -c "cd /app && pytest tests/ -v"
```

See `REPRODUCIBILITY.md` (Issue E5) for the full checklist.
```

- [ ] **AC3:** README section added and renders (verify no markdown syntax errors).

---

## Task 4 — Dockerfile NOT for Frontend/Service/API — explicitly note
Add a comment block at the top of `Dockerfile` after the header:
```
# ---------------------------------------------------------------------------
# IMPORTANT (Reviewer / Student note):
# This is a REPRODUCIBILITY image only. It is NOT a web service, REST server,
# frontend, or deployment target. See Do-Not-Build list (DN1, DN2, DN3) —
# FastAPI / Uvicorn / Kubernetes / Streamlit-as-a-service are out of scope.
# ---------------------------------------------------------------------------
```

- [ ] **AC4:** Anti-scope-creep comment present at the top of Dockerfile.

---

## Definition of Done
4 acceptance items ticked. `docker build --no-cache .` succeeds on WSL2, default `docker run` produces all-green schema-parity output with 0 API calls. README section renders correctly.
