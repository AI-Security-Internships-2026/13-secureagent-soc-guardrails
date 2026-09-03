# E5 · REPRODUCIBILITY.md — Canonical Metadata File + paper-v1.0 Git Tag
- **Labels:** engineering, reproducibility, manuscript, priority:P2
- **Milestone:** M4 — Reproducibility & Release
- **Depends on:** E1 (lock file) · E3 (NVD snapshot) · E4 (Dockerfile) · E2 (test suite log)
- **Acceptance items:** 8

---

## Summary
Springer IJIS/SNCS reviewers at data-availability check time expect a **single canonical file** that says "this commit + these exact instructions → these exact result numbers." This file is that single source of truth. Currently the manuscript scatters reproducibility data across §4.1, Tables, Roadmap.md, Integration_plan.md, and result JSON filenames. Consolidate everything into one reproducibility index.

This is low-code, high-trust. A reviewer who sees this file sees serious reproducibility standards.

---

## Task 1 — Create REPRODUCIBILITY.md at Repo Root
File: `REPRODUCIBILITY.md` (top-level, not under docs/ — visible immediately on GitHub landing page).

Template content (fill in the bracketed `<placeholders>` with real values from your committed files):

```markdown
# LLMCite — Reproducibility Metadata

## 1. Commit & Environment
- **Paper release tag:** `paper-v1.0` (see §8 below)
- **Commit SHA:** `<insert full 40-char commit hash>`
- **Date of evaluation runs:** `<YYYY-MM-DD> – <YYYY-MM-DD>`
- **Operating system:** `WSL2 Ubuntu <version>` on `Windows <version>` build `XXXXXX`
- **CPU / RAM:** `<CPU model> · <cores> vCPU · <GB> GB RAM`
- **Python version:** `Python 3.11.<X>`
- **Docker Desktop version (for E4 image):** `Docker version <XX.Y.Z>, build <hash>`

## 2. Exact Dependency Versions
Installed via:
```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt
python -m spacy download en_core_web_sm
```
- Pinned versions manifest: [`requirements-lock.txt`](./requirements-lock.txt) — produced by `pip freeze` on a clean WSL2 venv.
- SHA-256 of requirements-lock.txt: `<sha256sum requirements-lock.txt>`
- 3rd-party Groq client packages (explicit, Issue E1): `langchain-groq==<VER>`, `groq==<VER>`

## 3. Model IDs & Generation Hyperparameters (as used in §4)
- **Report generator model (production t=0.1):** `openai/gpt-oss-20b`
- **Cross-family 2nd generator:** `qwen/qwen3.6-27b`
- **SelfCheckGPT resample temperature, resamples count:** `t = 0.7 ; k = 3`
- **LLM-as-judge same-family:** `openai/gpt-oss-20b` (used on 318)
- **LLM-as-judge cross-family:** `qwen/qwen3.6-27b` (used on 442)
- Groq SDK version used: `groq==<VER>` (from lock-file)
- Prompt files used (exact commit paths):
  - report generation: `src/agent/prompts/report_generation.txt`
  - LLM judge: `src/guardrails/prompts/judge.txt`
  - SelfCheckGPT: `src/guardrails/prompts/selfcheckgpt_resample.txt`

## 4. Prompt Fingerprints (SHA-256 of every prompt text in §4 evaluation runs)
```
<sha256sum src/agent/prompts/report_generation.txt>  report_generation.txt
<sha256sum src/guardrails/prompts/judge.txt>          judge.txt
<sha256sum src/guardrails/prompts/selfcheckgpt_resample.txt>  selfcheckgpt_resample.txt
```

## 5. Data Snapshot Hashes
- **MITRE ATT&CK STIX Enterprise snapshot (§4.1):** SHA-256 `<EXISTING HASH FROM SN-ARTICLE.TEX>` already in manuscript.
- **NVD snapshot (Issue E3, all CVEs referenced in results):** [`data/nvd_snapshot/MANIFEST.sha256`](./data/nvd_snapshot/MANIFEST.sha256) — every `<CVE-ID>.json` listed individually. Use `--use-snapshot` CLI flag to reproduce without network access to NVD API.

## 6. Data Hashes for Evaluation Input Pools
SHA-256 manifest for each input pool (prevents silent data modification after run):
```
<sha256>  experiments/evaluation/cve_bait_alerts/pool_150.json
<sha256>  experiments/evaluation/attack_bait_alerts/pool_150.json
<sha256>  experiments/evaluation/grounding_benchmark_summary/cve_pool_60.json
<sha256>  experiments/evaluation/attack_bait_pool_60.json        # after R1
<sha256>  experiments/evaluation/relevance_classifier_validation/cve_pairs_80.csv
<sha256>  experiments/evaluation/relevance_classifier_validation/attack_pairs_80.csv  # after R4
<sha256>  experiments/evaluation/cross_source_pool_479.json
```

## 7. Exact Command Lines to Reproduce Each Result JSON
```bash
# §4.2  CVE bait 150
python experiments/evaluation/cve_bait_alerts/run_cve_bait.py --use-snapshot --seed 42

# §4.3  ATT&CK bait 150
python experiments/evaluation/attack_bait_alerts/run_attack_bait.py --use-snapshot --seed 42

# §4.4+§4.5  SelfCheckGPT + McNemar CVE-side, 2 families
python experiments/evaluation/selfcheckgpt_test.py \
  --generator openai/gpt-oss-20b --t 0.7 --resamples 3 --cve-pool experiments/evaluation/grounding_benchmark_summary/cve_pool_60.json --seed 123
python experiments/evaluation/selfcheckgpt_significance_test.py \
  --generator openai/gpt-oss-20b --use-snapshot
# same two commands with --generator qwen/qwen3.6-27b

# §4.4+§4.5 ATT&CK side (after completing Issue R1)
python experiments/evaluation/selfcheckgpt_test.py --attack-bait ... etc.

# §4.6 Relevance classifier
python experiments/evaluation/relevance_classifier_validation/run_relevance_eval.py --use-snapshot

# §4.8 Ablation 6 × 479 (after completing Issue R3)
python experiments/evaluation/ablation_driver.py --pool experiments/evaluation/cross_source_pool_479.json --use-snapshot --resume

# §4.10.4 Concurrency
python experiments/evaluation/fresh_process_benchmark/run_bench.py --repeats 3
```

## 8. How to Reproduce in < 10 Minutes (Offline)
```bash
git clone https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails.git
cd 13-secureagent-soc-guardrails
git checkout paper-v1.0
# Option A — Docker (fastest):
docker build -t llmcite . && docker run --rm llmcite
# Option B — venv:
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt && python -m spacy download en_core_web_sm
GROQ_API_KEY=dummy pytest tests/test_soc_agent_schema_parity.py -v   # offline, mocked LLM
```

## 9. Test Suite Logs
- [`tests/last_run.log`](./tests/last_run.log): `<DATE>` final green run: `<N>` passed, 1 skipped.
- [`tests/docker_build.log`](./tests/docker_build.log): Docker build output proving reproducibility image builds from clean.
```

- [ ] **AC1:** `REPRODUCIBILITY.md` file committed with all sections 1–9 present and placeholders replaced with real values (NOT left as `<placeholder>`).

---

## Task 2 — Verify hashes are reproducible
Run each `sha256sum` command on a freshly checked out copy. Any mismatch → go find which script modified an input pool since the result was generated (that's a latent reproducibility bug itself). Fix that first before committing hashes.

- [ ] **AC2:** All hashes in §5–§6 match actual file contents on disk; `sha256sum -c` passes.

---

## Task 3 — Verify §7 Commands Really Reproduce the Headline Numbers
Run at least ONE command (e.g. `selfcheckgpt_significance_test.py --use-snapshot`) with `--dry-run` flag if exists, or the real one if quota permits. Confirm exact p-value / headline number byte-for-byte matches Table 3/4 numbers in the committed manuscript. For commands you can't run (quota limited), leave a clear `# Verified manually by student on <DATE>; Groq rate-limited at submission — exact JSON from original run is at experiments/results/…` comment.

- [ ] **AC3:** At least one §7 command reproduced on the same commit hash; comments added for commands you explicitly couldn't re-run at submission time.

---

## Task 4 — Create Git Tag `paper-v1.0`
At the exact commit that will be referenced by the submitted PDF:
```bash
git status       # clean working tree!
git tag -a paper-v1.0 -m "LLMCite paper-v1.0 submission-ready, matches reproducibility metadata in REPRODUCIBILITY.md"
git show paper-v1.0
```
Save tag object hash (commit that tag points to) into §1 of REPRODUCIBILITY.md.

- [ ] **AC4:** Annotated git tag `paper-v1.0` created locally (don't push to origin until supervisor review).

---

## Task 5 — Update Manuscript §4.1 with REPRODUCIBILITY.md Link
Add one line to §4.1 reproducibility block:
> *"Full reproducibility metadata including exact commit tag, input-pool SHA-256 manifests, prompt fingerprints, and one-liner command recipes per result JSON file is provided in the repository's `REPRODUCIBILITY.md` at the `paper-v1.0` release tag."*

- [ ] **AC5:** Line added to §4.1.

---

## Task 6 — Update Zenodo/Figshare Deposit Instructions (Optional Preparation)
If IJIS asks for data+code deposit:
- Create a zip of the `paper-v1.0` git archive, plus separate zip of `data/nvd_snapshot/` + `experiments/results/` full JSON.
- Reserve a DOI from Zenodo Sandbox (sandbox.zenodo.org) so manuscript's Data Availability statement can say: *"All artifacts archived at <DOI> (open-access CC-BY)."* This is optional for the next couple weeks; do it only once you're about to submit.

- [ ] **AC6:** Zenodo sandbox reservation OR a note that this is deferred to submission-eve.

---

## Task 7 — Final Integrity Check: Full Checklist in REPRODUCIBILITY.md
Add section §10 at end: a simple 14-item checklist, **pre-ticked** by student for every item:
- [x] Git tag `paper-v1.0` created, clean working tree.
- [x] `requirements-lock.txt` committed; clean venv install works; import langchain_groq OK.
- [x] Dockerfile builds; default CMD runs all-green schema-parity test.
- [x] 0 `[?]` BibTeX refs in PDF (R2 completed).
- [x] E2 pytest `tests/last_run.log` committed.
- [x] NVD snapshot committed + manifest verifies.
- [x] MITRE snapshot SHA in manuscript matches file.
- [x] R1 ATT&CK SelfCheckGPT executed (or honestly noted `in progress, linked`).
- [x] R3 Ablation Phase 3 executed (or honestly noted `in progress, linked`).
- [x] R4 double-annotator κ values present in §4.6.
- [x] Every `[NOT YET RUN]` token deleted from manuscript (R6 completed).
- [x] §4 subsection openings each state "This subsection addresses RQx".
- [x] All 4 explicit RQs in §1.
- [x] Figure F1 architecture diagram in submission, or honestly noted `supplement-only`.

- [ ] **AC7:** Section 10 checklist present; all items with either a ticked box, or a clear "honestly pending at submission, linked" annotation on items R1/R3 if they are still running.

---

## Task 8 — Cross-Reference from README
Add one line to README near top:
> 📘 **Submission release:** See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for exact paper-v1.0 metadata, hashes, commands, and integrity checklist.

- [ ] **AC8:** README contains a visible link to REPRODUCIBILITY.md.

---

## Definition of Done
All 8 acceptance items checked. A reviewer following Section 8 of REPRODUCIBILITY.md verbatim reproduces the offline mocked schema-parity test with no errors in < 10 minutes. All hashes verify. Git tag `paper-v1.0` points to a clean commit.
