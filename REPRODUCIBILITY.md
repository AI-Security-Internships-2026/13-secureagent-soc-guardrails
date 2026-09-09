# LLMCite — Reproducibility Metadata

This file is the single canonical index of exactly what commit, environment,
data, and commands produced the numbers in the paper. Every value below was
extracted or verified directly from this repository's own files at the time
this document was written — none are copied from the issue template that
originally requested this file, since several of that template's specifics
(operating system, Python version, file paths, an unresolved 479-alert pool)
did not match this project's actual state and are corrected below rather
than repeated.

## 1. Commit & Environment

- **Paper release tag:** `paper-v1.0` (see §8 below)
- **Commit SHA:** `394553cd0b989e08c983770bd2c12bc37c680939`
- **Date of evaluation runs:** `2026-06-10` – `2026-09-09` (repo's first commit to this document's writing date; see `docs/all_results.md` for the dated, numbered log of every individual experiment)
- **Operating system:** Native Windows 11 Home, build `26200` (this project has never run under WSL2 — the issue template that requested this file assumed WSL2/Ubuntu, which is incorrect for this repo's actual development environment)
- **CPU / RAM:** 13th Gen Intel Core i7-1355U · 12 logical cores · 16 GB RAM
- **Python version:** `Python 3.12.6` (not 3.11 — `requirements-lock.txt` itself documents it was generated on 3.12.6, and one of its pinned packages, `scipy==1.18.1`, has no Python 3.11 wheel at all; discovered and documented while building the Dockerfile for Issue E4)
- **Docker Desktop version (for E4 image):** `Docker version 27.4.0, build bde2b89`

## 2. Exact Dependency Versions

Installed via:
```bash
python -m venv .venv
.venv\Scripts\activate        # Windows; use `source .venv/bin/activate` on Linux/macOS
pip install -r requirements-lock.txt
python -m spacy download en_core_web_sm
```
- Pinned versions manifest: [`requirements-lock.txt`](./requirements-lock.txt) — produced by `pip freeze` on a clean venv (Issue E1).
- SHA-256 of requirements-lock.txt: `099938490887c6acd2e62907bfc298a3a334552fea6798767db643e15240cf4c`
- Groq client packages (explicit, Issue E1): `groq==0.37.1`, `langchain-groq==1.1.3`

## 3. Model IDs & Generation Hyperparameters (as used in §4 of the paper)

- **Report generator model (production, t=0.1):** `openai/gpt-oss-20b`
- **Cross-family second generator:** `qwen/qwen3.6-27b`
- **SelfCheckGPT resample temperature, resample count:** `t = 0.7 ; k = 3` (`src/guardrails/selfcheckgpt.py`'s `SAMPLING_TEMPERATURE`, `experiments/evaluation/selfcheckgpt_test.py`'s `N_SAMPLES`)
- **LLM-as-judge same-family:** `openai/gpt-oss-20b` (318/318 samples)
- **LLM-as-judge cross-family:** `qwen/qwen3.6-27b` (442/450 samples, quota-gated — see `docs/all_results.md` #41)
- Groq SDK version used: `groq==0.37.1` (from lock file, §2 above)
- **Prompt locations:** unlike the issue template's assumption, prompts are not stored as separate `.txt` files in this project — they are module-level Python string constants, defined and version-controlled directly alongside the code that uses them:
  - Report generation: `SYSTEM_PROMPT` in `src/agent/soc_agent.py` (line 27)
  - LLM-as-judge: `JUDGE_SYSTEM_PROMPT` in `src/guardrails/llm_judge.py` (line 42)
  - SelfCheckGPT resampling reuses the same report-generation `SYSTEM_PROMPT` above (`src/guardrails/selfcheckgpt.py`'s `sample_citations()` calls `soc_agent.SYSTEM_PROMPT` directly) — there is no separate resample-specific prompt file.

## 4. Prompt Fingerprints (SHA-256 of the exact prompt string content)

```
bc4b216eb3aebed02deb276c3c1c6dda8bdc7321bf041d78f52b3205c0cc483e  SYSTEM_PROMPT (src/agent/soc_agent.py)
c9dc4a980275f736435ed03e7bc957dc1da4c0c87c5266c67ab921000177d475  JUDGE_SYSTEM_PROMPT (src/guardrails/llm_judge.py)
```
Computed via `hashlib.sha256(PROMPT_STRING.encode("utf-8")).hexdigest()` on the live Python objects, not on a file — since these are Python string constants rather than standalone files, hashing "the file" isn't meaningful the way it is for the data snapshots in §5-§6.

## 5. Data Snapshot Hashes

- **MITRE ATT&CK STIX Enterprise snapshot** (`data/mitre_attack/enterprise_attack_techniques.json`, fetched 2026-08-04, 858 techniques): SHA-256 `3655344c1b3428392994a947cb13b04b2236a6818b9ce9e35084db98b4fbd08f` — already cited in `docs/paper/paper_draft.md`/`sn-article.tex` §4.1.
- **NVD snapshot** (Issue E3, all 152 CVE IDs referenced in committed result files): [`data/nvd_snapshot/MANIFEST.sha256`](./data/nvd_snapshot/MANIFEST.sha256) — every `<CVE-ID>.json` listed individually, 152/152 entries verified via `sha256sum -c`. Use the `--use-snapshot` CLI flag (see §7) to reproduce without live network access to the NVD API.

## 6. Data Hashes for Key Evaluation Result/Input Files

The issue template assumed several dedicated JSON "input pool" files (e.g. `cve_bait_alerts/pool_150.json`, `cross_source_pool_479.json`) that do not exist in this repository. The real situation: the CVE-bait and ATT&CK-bait (original 150-alert) sets are defined directly as Python code (`experiments/evaluation/cve_bait_alerts.py`, `experiments/evaluation/attack_bait_alerts.py`), not as static JSON files, so there is no separate JSON pool to hash for those — the *result* files below are the closest verifiable artifact. The one genuine standalone JSON input pool that does exist is the R1 ATT&CK-replication pool. The pooled cross-source figure (currently 575 alerts, not the issue's assumed 479) is computed on the fly by `experiments/evaluation/grounding_benchmark_summary.py` from the individual result files below, not from one dedicated pool file.

```
f112050eca509fd216a8ddd9f1f9ca3f94075ee690f7bdb8abde1ba249615c11  experiments/results/attack_bait_pool_60.json
56501aa866e4cabd03b6e921b41dce5ea9f069d762a770b36e60d797a83c218a  experiments/evaluation/relevance_classifier_validation/relevance_classifier_validation_results.json
```
(A relevance-classifier pool for ATT&CK citations, analogous to the CVE-side 80-pair set, does not yet exist — that is Issue R4's second task, currently blocked on needing a second human annotator; see §10.)

## 7. Commands to Reproduce Each Result

Real script names/flags, verified against the actual code (the issue template's assumed paths like `cve_bait_alerts/run_cve_bait.py` and `--seed 42` do not exist in this repo — none of these scripts currently support a `--seed` flag, since none of them do randomized sampling that a seed would control):

```bash
# Sect. 4.2  CVE-bait, n=150
python -m experiments.evaluation.cve_bait_test --use-snapshot

# Sect. 4.3  ATT&CK-bait, n=150
python -m experiments.evaluation.attack_bait_test

# Sect. 4.4-4.5  SelfCheckGPT + McNemar, CVE-side, both generator families
python -m experiments.evaluation.selfcheckgpt_test
python -m experiments.evaluation.selfcheckgpt_significance_test
GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_test
GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_significance_test

# Sect. 4.5  SelfCheckGPT + McNemar, ATT&CK-side, both generator families (Issue R1)
python -m experiments.evaluation.selfcheckgpt_test_attack
python -m experiments.evaluation.selfcheckgpt_significance_test_attack
GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_test_attack
GENERATOR_MODEL=qwen/qwen3.6-27b python -m experiments.evaluation.selfcheckgpt_significance_test_attack

# Sect. 4.6  Relevance classifier validation (deterministic, no LLM calls, no API cost)
python -m experiments.evaluation.relevance_classifier_validation.score_labels

# Sect. 4.8/4.9 (issue's §4.8) Ablation study, 6 configs (Issue R3)
# NOT YET AVAILABLE AS A SINGLE COMMAND — R3 is not started; its scope
# (which alert pool, how many configs) is explicitly unresolved as of this
# writing. See docs/ROADMAP_PLAN.md Sect. 15, issue #42.

# Sect. 4.10.4  Concurrency benchmark
python -m experiments.evaluation.fresh_process_benchmark
```

## 8. How to Reproduce in Under 10 Minutes (Offline)

```bash
git clone https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails.git
cd 13-secureagent-soc-guardrails
git checkout paper-v1.0

# Option A — Docker (fastest, fully offline, no API key needed):
docker build -t llmcite .
docker run --rm llmcite

# Option B — venv:
python -m venv .venv
.venv\Scripts\activate    # or: source .venv/bin/activate
pip install -r requirements-lock.txt
python -m spacy download en_core_web_sm
pytest tests/test_soc_agent_schema_parity.py -v --no-header    # offline, mocked LLM, no API key needed
```
Verified directly: Issue E4's Docker image builds clean and the default `docker run` completes the offline schema-parity test in 25 seconds using 1.05kB of network I/O (container startup only) — see `docs/all_results.md` #70 for the full verification, including a `docker stats` comparison before/after the fix.

## 9. Test Suite Logs

- [`tests/last_run.log`](./tests/last_run.log): 2026-09-09, `158 passed, 1 skipped, 19 warnings in 144.71s` — regenerated fresh for this document rather than reusing the Sept 5 log already on disk, so it matches the exact commit this file documents.
- [`tests/docker_build.log`](./tests/docker_build.log): Docker build output (Issue E4) proving the reproducibility image builds clean from scratch.

## 10. Verified Reproduction (Task 3)

Ran one full command from §7 for real, at zero API cost, and confirmed it reproduces the paper's committed number byte-for-byte: `python -m experiments.evaluation.relevance_classifier_validation.score_labels` — this is fully deterministic (it recomputes the classifier's accuracy from already-collected human labels, no LLM calls involved), so it was safe and cheap to actually run rather than merely inspect. Result: **92.5% accuracy (95% CI [0.846, 0.965]), 90.5% precision, 95.0% recall, F1 92.7%**, confusion matrix `{tp: 38, fp: 4, tn: 36, fn: 2}` — diffed the freshly-generated output file against the already-committed `relevance_classifier_validation_results.json` and confirmed they are byte-for-byte identical (`diff` exit code 0). This matches Sect. 4.6's reported n=80 accuracy figure exactly.

The other §7 commands were **not** re-run for this document — each involves 50-150+ real Groq API calls, and this project's own history (`docs/all_results.md` #61, #66-#67) documents that re-running any of them can take hours to days depending on Groq's free-tier daily quota. Their committed result files (`experiments/results/*.json`) are the record of record; re-running them is a good sanity check before a real submission but was not done here to avoid burning quota needed for still-open issues (R3's ablation study in particular).

## 11. Integrity Checklist

- [x] Git tag `paper-v1.0` created locally (see §12) — not yet pushed to origin, per the issue's own instruction to hold for supervisor review.
- [x] `requirements-lock.txt` committed; clean venv install works; `import langchain_groq` succeeds (verified in Docker build, Issue E4).
- [x] Dockerfile builds; default `CMD` runs the schema-parity test all-green, fully offline (Issue E4, `docs/all_results.md` #70).
- [x] 0 `[?]` BibTeX refs in the compiled PDF (Issue R2, confirmed clean both before and after this session's reference work).
- [x] `tests/last_run.log` committed, fresh as of this document (§9).
- [x] NVD snapshot committed, manifest verifies 152/152 (Issue E3, `docs/all_results.md` #71).
- [x] MITRE snapshot SHA in the manuscript matches the actual file (§5).
- [x] Issue R1 (ATT&CK SelfCheckGPT replication) executed and complete, both model families (`docs/all_results.md` #66-#67).
- [ ] Issue R3 (ablation study, Table T6 + UpSet/Venn) — **not started.** Scope conflict unresolved: the issue specifies a 479-alert pool that doesn't match this project's real pooled data (575 alerts); needs a scoping decision before it can begin. Tracked in `docs/ROADMAP_PLAN.md` §15.
- [ ] Issue R4 (two-annotator Cohen's κ, ATT&CK relevance validation) — **not started, blocked.** Needs a second human labeler; not something that can be completed without that person's time.
- [ ] Issue R6 (explicit RQ1-RQ4 section, evaluation reordering, de-fluff pass) — **not started.**
- [ ] "This subsection addresses RQx" openers in §4 — not present; depends on R6.
- [ ] Explicit RQ1-RQ4 list in §1 — not present; depends on R6.
- [ ] Standalone architecture/taxonomy figures (Issue E6/#51) — not started; explicitly lowest-priority per that issue's own text.

This checklist is honest, not pre-ticked — several items above are genuinely still open, tracked in `docs/ROADMAP_PLAN.md` §15, and this file will be updated as they close.

## 12. Git Tag

```
paper-v1.0 -> 394553cd0b989e08c983770bd2c12bc37c680939
```
Created locally via `git tag -a paper-v1.0`, working tree clean at the time of tagging. **Not pushed to `origin`** — per the source issue's own instruction, this is held for supervisor review before becoming a public release marker.
