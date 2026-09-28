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
- **Commit SHA:** exact commit hash of `paper-v1.0` — run `git rev-parse paper-v1.0` (a hardcoded hash here would go stale the moment this file itself changes again, since the file's own commit hash depends on its content; the tag is the stable reference)
- **Date of evaluation runs:** `2026-06-10` – `2026-09-27` (repo's first commit to this freeze's date; see `docs/all_results.md` for the dated, numbered log of every individual experiment)
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
- SHA-256 of requirements-lock.txt: `747165c71e6dad086e84785f995f949ed4a0d41b81b75bb881cfc2745faebd5e` (changed since this file's original writing — `upsetplot==0.9.0` was added for Issue R3's Figure F4; recomputed for this freeze rather than left stale)
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
- **NVD snapshot** (Issue E3, all 153 CVE IDs referenced in committed result files — 152 originally, plus `CVE-2021-31207` added mid-way through the R3 ablation study when the model spontaneously volunteered a citation the original snapshot didn't cover, `docs/all_results.md` #76): [`data/nvd_snapshot/MANIFEST.sha256`](./data/nvd_snapshot/MANIFEST.sha256) — every `<CVE-ID>.json` listed individually, **153/153 entries re-verified for this freeze** (byte-for-byte SHA-256 recompute against every file, not just a manifest-exists check). Use the `--use-snapshot` CLI flag (see §7) to reproduce without live network access to the NVD API.

## 6. Data Hashes for Key Evaluation Result/Input Files

The issue template assumed several dedicated JSON "input pool" files (e.g. `cve_bait_alerts/pool_150.json`, `cross_source_pool_479.json`) that do not exist in this repository. The real situation: the CVE-bait and ATT&CK-bait (original 150-alert) sets are defined directly as Python code (`experiments/evaluation/cve_bait_alerts.py`, `experiments/evaluation/attack_bait_alerts.py`), not as static JSON files, so there is no separate JSON pool to hash for those — the *result* files below are the closest verifiable artifact. The one genuine standalone JSON input pool that does exist is the R1 ATT&CK-replication pool. The pooled cross-source figure (currently 575 alerts, not the issue's assumed 479) is computed on the fly by `experiments/evaluation/grounding_benchmark_summary.py` from the individual result files below, not from one dedicated pool file.

```
f112050eca509fd216a8ddd9f1f9ca3f94075ee690f7bdb8abde1ba249615c11  experiments/results/attack_bait_pool_60.json
56501aa866e4cabd03b6e921b41dce5ea9f069d762a770b36e60d797a83c218a  experiments/evaluation/relevance_classifier_validation/relevance_classifier_validation_results.json
19136e38d6237695143b7dec4905d464e03096ec3b3732e6dfa014598646bd7f  experiments/results/ablation_pool_436.json
ed39f8f05ad982962d36fea371b9bf70b7b8a1fd553096c879e01ea4ba4695a3  experiments/results/ablation_full.jsonl
3e76ade277b2786fcc67271905881ceb0e4822d1f7c4133883f5db6b661763a5  experiments/results/ablation_table_t6.json
dd7e7b35391e642ee0131af846284647b14508239126d24466bccf73c9e8509c  experiments/evaluation/relevance_classifier_validation/attack_relevance_classifier_validation_results.json
0e68286d7416c997be9df445ce6273bc96b1d3953db9082b52656595d75e7d95  experiments/evaluation/relevance_classifier_validation/inter_rater_agreement_results.json
01fe8e3625ca80b1a0b5213ebce0925df3804383f79e54d261189d62b26e4664  experiments/evaluation/relevance_classifier_validation/cve_crosscheck_kappa_results.json
da0ba4a0e67213acaed554c7c0737e366429669d8a1ddb92e7a43f05ae444a66  experiments/results/temperature_sweep_prompted_30x5.jsonl
d151c52acade1a3720e3c86fec6542a26472e92454104efd0a53c83e21a62749  experiments/results/temperature_sweep_summary.json
```
The ATT&CK-side relevance-classifier pool this section previously flagged as not existing yet (blocked on Issue R4's second annotator) is now built and scored — `relevance_classifier_validation/attack_pairs_to_label.csv` (103 pairs) plus the result file hashed above, n=103, 83.5% accuracy. Both citation families' human-annotation ground truth are also frozen: `annotator1_and_key_HIDDEN.csv` / `annotator2_cve_pairs_labeled.xlsx` (CVE, real independent double-annotation, κ=1.0) and `attack_annotation_labeled.xlsx` (ATT&CK, single rater, disclosed as such in the manuscript). See §10 for the byte-for-byte reproduction check on the ATT&CK scorer.

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

# Sect. 4.6  Relevance classifier validation, both citation families (deterministic, no LLM calls, no API cost)
python -m experiments.evaluation.relevance_classifier_validation.score_labels
python -m experiments.evaluation.relevance_classifier_validation.score_attack_labels

# Sect. 4.6  Human-annotation agreement statistics (deterministic, no LLM calls)
# CVE side: real independent second annotator, n=80, Cohen's kappa=1.0
python -m experiments.evaluation.relevance_classifier_validation.compute_inter_rater_agreement
# CVE side: earlier interim 20% self-check, n=16, superseded by the above but kept for the record
python -m experiments.evaluation.relevance_classifier_validation.compute_cohen_kappa

# Sect. 4.4  Temperature-sensitivity sweep, Figure F6 (Issue R5)
python -m experiments.evaluation.temperature_sweep_driver          # resume until 150/150 complete (quota-gated)
python -m experiments.evaluation.temperature_sweep_driver --validate
python -m experiments.evaluation.make_fig_f6                       # deterministic once the sweep JSONL exists

# Sect. 4.8  Ablation study, 6 configs x 436 alerts (Issue R3)
python -m experiments.evaluation.ablation_driver                   # resume until 2,616/2,616 complete (quota-gated)
python -m experiments.evaluation.ablation_driver --validate
python -m experiments.evaluation.make_ablation_table_t6            # deterministic once the JSONL is complete
python -m experiments.evaluation.make_ablation_figures             # Figures F3 + F4, same precondition

# Sect. 3  Architecture (Fig. 1) and citation-taxonomy (Fig. 2) diagrams (Issue E6, deterministic, no LLM calls)
python -m experiments.evaluation.make_architecture_figure
python -m experiments.evaluation.make_taxonomy_figure

# Sect. 4.10.4  Concurrency benchmark
python -m experiments.evaluation.fresh_process_benchmark
```
The two `--driver` commands above (ablation, temperature sweep) are the ones actually gated by Groq's free-tier daily token quota (200k tokens/model/day) — both are resumable, append-only, and safe to interrupt and re-run across multiple days; `docs/all_results.md` #75-#97 documents the real multi-session history of finishing both. Everything else in this section is either a single live-call pass or fully deterministic post-processing over already-committed data.

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

- [`tests/last_run.log`](./tests/last_run.log): 2026-09-27, `158 passed, 19 warnings in 42.41s` — re-run per issue #47/E2's explicit request, after issues #42-44 (R3/R4/R5) all landed, to confirm none of that week's changes introduced a regression. **0 failures, 0 skipped** (the earlier 2026-09-09 log recorded 1 skipped; no `skip`/`skipif` marker exists anywhere in the current test suite, so whatever caused that skip no longer applies — noted honestly rather than silently updating the count without comment).
- [`tests/docker_build.log`](./tests/docker_build.log): Docker build output (Issue E4) proving the reproducibility image builds clean from scratch.

## 10. Verified Reproduction (Task 3)

Re-ran every fully-deterministic command from §7 for real, at zero API cost, for this freeze specifically (not just inspected), and diffed each freshly-generated output against the already-committed file:

- `score_labels` (CVE relevance classifier): **92.5% accuracy (95% CI [0.846, 0.965]), 90.5% precision, 95.0% recall, F1 92.7%**, confusion matrix `{tp: 38, fp: 4, tn: 36, fn: 2}` — byte-for-byte identical to the committed file (`diff` exit code 0). Matches Sect. 4.6's n=80 figure exactly.
- `score_attack_labels` (ATT&CK relevance classifier): **83.5% accuracy (95% CI [0.752, 0.894]), 74.0% precision, 90.2% recall, F1 81.3%**, confusion matrix `{tp: 37, fp: 13, tn: 49, fn: 4}` — byte-for-byte identical to the committed file. Matches Sect. 4.6's n=103 figure exactly.
- `compute_inter_rater_agreement` (CVE independent double-annotation): **n=80, 100% agreement, Cohen's kappa=1.0, 95% CI [1.0, 1.0]** — byte-for-byte identical to the committed file. Matches Sect. 4.6's headline annotation-agreement figure.
- `compute_cohen_kappa` (CVE 20% self-check, superseded interim result): **n=16, 100% agreement, kappa=1.0** — byte-for-byte identical to the committed file.
- `ablation_driver --validate`: **2,616/2,616 rows, all 6 configs present for each of 436 alerts.**
- `temperature_sweep_driver --validate`: **150/150 rows, all 5 temperatures present for each of 30 alerts.**

The remaining §7 commands (CVE-bait, ATT&CK-bait, SelfCheckGPT, McNemar, and the two resumable drivers' *live-call* portions) were **not** re-run from scratch for this freeze — each involves 50-2,616 real Groq API calls, and this project's own history (`docs/all_results.md` #61, #66-#67, #75-#97) documents that a from-scratch re-run of any of them can take hours to days on Groq's free-tier daily quota. Their committed result files are the record of record; both resumable drivers (`ablation_driver`, `temperature_sweep_driver`) were, however, run to genuine completion during this project's actual evaluation (not merely claimed) — §7's `--validate` flags are exactly the cheap, zero-new-call way to re-confirm that completeness at any later point, including right now.

## 11. Integrity Checklist

- [x] Git tag `paper-v1.0` re-created locally, pointing at the exact commit this frozen document describes (see §12) — still not pushed to origin, per the issue's own instruction to hold for supervisor review.
- [x] `requirements-lock.txt` committed; clean venv install works; `import langchain_groq` succeeds (verified in Docker build, Issue E4). Hash re-verified for this freeze (§2) — it had drifted since this file's original writing (`upsetplot` added for Issue R3's Figure F4) and is now current.
- [x] Dockerfile builds; default `CMD` runs the schema-parity test all-green, fully offline (Issue E4, `docs/all_results.md` #70).
- [x] 0 `[?]` BibTeX refs, 0 undefined LaTeX references/citations in the compiled PDF (Issue R2; reconfirmed via a full `pdflatex`+`bibtex`+`pdflatex`+`pdflatex` sequence at every manuscript edit this week, not just once).
- [x] `tests/last_run.log` committed, fresh as of this freeze: **158 passed, 0 failed, 0 skipped** (Issue E2, `docs/all_results.md` #98 — re-run specifically after R3/R4/R5 landed, per the issue's own request).
- [x] NVD snapshot committed, manifest verifies **153/153** (Issue E3; grew from 152 mid-ablation, `docs/all_results.md` #76 — re-verified byte-for-byte for this freeze, §5).
- [x] MITRE snapshot SHA in the manuscript matches the actual file (§5).
- [x] Issue R1 (ATT&CK SelfCheckGPT replication) executed and complete, both model families (`docs/all_results.md` #66-#67).
- [x] Issue R2 (literature pass, novelty statement) complete — every added reference verified against text and bibliography, novelty statement checked against the supervisor's explicit checklist twice (`docs/all_results.md` #85, #96).
- [x] Issue R3 (ablation study, Table T6 + Figures F3/F4) complete — **2,616/2,616** (config, alert) pairs across all 6 configurations and 436 alerts, re-verified via `--validate` for this freeze (`docs/all_results.md` #75-#84).
- [x] Issue R4 (two-annotator Cohen's κ, ATT&CK relevance validation) complete — genuine independent double-annotation on the CVE side (**n=80, κ=1.0**, a real second person, not the degraded single-rater fallback used in an earlier interim pass), ATT&CK side scored against real human labels for the first time (**n=103, 83.5% accuracy, F1 81.3%**) (`docs/all_results.md` #89-#93).
- [x] Issue R5 (temperature-sensitivity sweep, Figure F6) complete — **150/150** (temperature, alert) pairs; SelfCheckGPT's recall on confirmed-unsupported citations stays low (5-19%) at every temperature 0.1-1.0, all 95% CIs overlapping (`docs/all_results.md` #94-#97).
- [x] Issue R6 (explicit RQ1-RQ4 section, evaluation reordering) complete, including a final consistency pass that caught and fixed a stale RQ4 description and 5 missing RQ-openers (`docs/all_results.md` #73, #86).
- [x] "This subsection addresses RQx" openers present on all 9 evaluation subsections in §4 (Issue R6, `docs/all_results.md` #86).
- [x] Explicit RQ1-RQ4 list present in §1 (Issue R6).
- [x] Architecture and citation-taxonomy figures (Issue E6/#51) built and integrated — both drawn from the real pipeline code, not idealized diagrams (`docs/all_results.md` #87-#88).
- [x] Issue E2 (regression + schema-parity suite) re-run after R3/R4/R5, all green (`docs/all_results.md` #98, §9 above).

This checklist is honest, not pre-ticked. Every item above was individually re-verified for this freeze (not carried over from the original 2026-09-09 writing) — several genuinely drifted since then (the dependency lock hash, the NVD snapshot count, one test-suite skip count) and are reported as found, not silently corrected without comment.

## 12. Git Tag

```
paper-v1.0 -> (run `git rev-parse paper-v1.0` for the exact commit hash)
```
Created locally via `git tag -a paper-v1.0`, working tree clean at the time of tagging. **Not pushed to `origin`** — per the source issue's own instruction, this is held for supervisor review before becoming a public release marker.
