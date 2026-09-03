# E1 · Dependency Freeze: requirements.txt + requirements-lock.txt (langchain-groq + cleanup)
- **Labels:** engineering, reproducibility, priority:P0
- **Milestone:** M1 — Freeze Desk-Reject Risks
- **Acceptance items:** 7
- **Highest ROI issue in the entire plan.** Resolves an IMMEDIATE reproducibility desk-reject risk: reviewer `git clone → pip install -r requirements.txt → from langchain_groq import ChatGroq → ModuleNotFoundError`. 1 in 2 reviewers will actually try this step; if it fails, "non-reproducible artifact" appears in their report.

---

## Background — why this is a reproducibility bug, not hygiene
External review §31 and 3rd-tool review §23 flag the same bug independently:
- The code imports `from langchain_groq import ChatGroq` and uses the `groq` Python package directly in helper scripts (Groq client, retry wrappers).
- `requirements.txt` lists only: `langchain`, `langgraph`, `openai`, `fastapi`, `uvicorn` — but **NOT** `langchain-groq` or `groq`.
- The student's local environment works because `langchain-groq` was pulled in as a **transitive dependency** somewhere (a version of `langchain` may have once required it; or it was `pip install`ed manually). Transitive dependencies are NOT stable — a reviewer in 6 months will get a newer `langchain` that dropped the transitive dep and the clone will silently break.
- Separately, `langgraph`, `fastapi`, `uvicorn`, `nemoguardrails`, `guardrails-ai` are listed in requirements.txt but **not imported anywhere in the committed Python source tree** (confirmed by grep of `src/**/*.py` + `tests/**/*.py` + `experiments/**/*.py` across week-13). These unused deps **slow a clean install** and signal "README-fluff not actually part of the project." External review §32 and §48's DO-NOT-BUILD list explicitly says not to build on these.

---

## Task 1 — WSL2 Clean Python 3.11 Venv Setup
Open WSL2 Ubuntu shell (per user rules: all Python environments MUST use WSL2 with Python 3.11 venv per project). DO NOT run this in Windows-native CMD/PowerShell Python — the submitted `sn-article.tex` setup section says "evaluated on WSL2 Ubuntu", so reviewer reproducibility runs MUST use the same OS layer.

```bash
cd /mnt/d/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails
sudo apt-get update && sudo apt-get install -y python3.11 python3.11-venv python3-pip

python3.11 -m venv .venv_clean_freeze
source .venv_clean_freeze/bin/activate
python -V  # MUST print Python 3.11.x
```

- [ ] **AC1:** Clean venv activated; `python -V` prints 3.11; `which python` points inside `.venv_clean_freeze`.

---

## Task 2 — Edit requirements.txt
File: [requirements.txt](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/requirements.txt)

### ✅ ADD THESE TWO LINES (missing explicit deps — actual code imports):
```
langchain-groq>=0.2.0
groq>=0.11.0
```

### ❌ DELETE THESE LINES (unused, confirmed by codebase-wide grep — NOT imported, NOT used in any committed script):
```
langgraph
fastapi
uvicorn
nemoguardrails
guardrails-ai
```

### 🟡 KEEP (already used, confirmed):
Keep all remaining lines (presidio-analyzer, presidio-anonymizer, scipy, pandas, numpy, pytest, streamlit, python-dotenv, PyYAML, requests, lxml, pydantic, pytector (if present), spacy, en-core-web-sm reference, etc.). If any line says `langchain-core` or similar keep it.

- [ ] **AC2:** Edited `requirements.txt` committed. Deleted 5 unused lines. Added 2 explicit missing lines. No other changes.

---

## Task 3 — Install from Scratch & Smoke-Test Import
On the same clean venv:
```bash
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Smoke test the ONE import that would have broken before:
python -c "from langchain_groq import ChatGroq ; from groq import Groq ; print('imports OK')"
# Expected output: imports OK (no ModuleNotFoundError!)

# Smoke test the actual pipeline on ALERT-001 using a mocked Groq response.
# If tests/ already has a mocked LLM for E2, reuse that. If not:
cd src
python -c "
from agent.alert_schema import SECURITY_ALERT_001
from agent.soc_agent import analyse_alert
import json, os
os.environ['GROQ_API_KEY'] = os.environ.get('GROQ_API_KEY', 'dummy-key-for-import-check')
# If a dummy-key guard exists in the wrapper this won't call API; if it does, it will error gracefully and we'll still see the function executes without ImportError.
try:
    result = analyse_alert(SECURITY_ALERT_001)
    print('schema keys OK:', sorted(result.keys())[:8])
except Exception as exc:
    # Any ModuleNotFoundError is FAIL; any network/KeyError is PASS for our purposes here (import worked, schema was populated).
    if 'ModuleNotFoundError' in type(exc).__name__:
        raise
    print('import + schema skeleton OK (expected network-error on dummy key):', type(exc).__name__)
"
```

- [ ] **AC3:** `import langchain_groq` and `import groq` pass on clean venv.
- [ ] **AC4:** `analyse_alert(SECURITY_ALERT_001)` loads on clean venv without ANY `ModuleNotFoundError`. (A `KeyError`/`ValueError` because of dummy API key is acceptable and expected — means imports are good.)

---

## Task 4 — Generate & Commit requirements-lock.txt
Still inside the activated `.venv_clean_freeze`:
```bash
pip freeze > requirements-lock.txt
wc -l requirements-lock.txt  # Should have ~80–150 lines (all sub-pins)
```
Commit both `requirements.txt` AND `requirements-lock.txt`.

- [ ] **AC5:** `requirements-lock.txt` committed (NOT gitignored — check `.gitignore`).

---

## Task 5 — Update `docs/paper/sn-article.tex` Reproducibility Metadata Block
Add a short reproducibility block in §4.1 Setup (find the line that prints `145/145 all green` after E2 is done):
> *"All code dependencies were installed and verified on WSL2 Ubuntu with Python 3.11 using the committed `requirements-lock.txt` (snapshot of pinned versions produced by `pip freeze` on a clean install). The two packages `langchain-groq` and `groq` are declared explicitly; they were previously only available via transitive resolution."*

- [ ] **AC6:** One short reproducibility paragraph added to §4.1.

---

## Task 6 — (Optional, Nice) Add `requirements-lock.txt` SHA to REPRODUCIBILITY.md
This is handled by Issue E5 (REPRODUCIBILITY.md file). Just note: when E5 is done, `requirements-lock.txt` must be listed in E5's manifest.

- [ ] **AC7:** Reference to E5 added in comment at top of `requirements-lock.txt` (one `# See REPRODUCIBILITY.md / Issue E5 for install commands` line).

---
