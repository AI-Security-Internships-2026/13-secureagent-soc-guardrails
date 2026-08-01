# Weekly Progress Log: SecureAgent-SOC

**Student:** Emaan Afroz Khuram
**GitHub:** @emaankhuram

---

## Week 1

**Branch:** `emaan-week-01`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/9

### Completed this week
- [x] Read README and proposal
- [x] Set up local Python environment
- [x] Ran `src/main.py` successfully
- [x] Wrote personal introduction (below)
- [x] Identified 5 related papers / tools / datasets

### Personal Introduction
I am a third-year Computer Science student at NUST SEECS with a strong academic and practical foundation in advanced machine learning, backend engineering, and multi-agent systems. My technical experience includes developing predictive pipelines using tree-based models, fine-tuning Vision Transformers, and engineering secure, agentic workflows inside containerized environments. Through this internship at CNIT/PNTLab Pisa, I hope to master the architecture of runtime LLM guardrail frameworks and understand how to build resilient, production-ready AI pipelines that can withstand adversarial exploitation. Ultimately, I aim to apply these secure engineering methodologies to deep-tech solutions within high-stakes, data-sensitive domains.

### Problems / Blockers
no blockers faced

### Next week plan
- Read the 5 identified papers
- Set up NeMo Guardrails locally
- Draft `docs/proposal.md` sections 3 and 4

---

## Week 2

**Branch:** `emaan-week-02`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/10

### Completed this week
- [x] Read all 5 literature review papers identified in Week 1
- [x] Installed Ollama 0.30.8 and pulled Mistral 7B (4.4GB) as local LLM backend
- [x] Created `experiments/nemo_test/` with `config.yml`, `rails.co`, and `actions.py`
- [x] Wired Mistral into NeMo Guardrails 0.22.0 via Ollama's OpenAI-compatible `/v1` endpoint
- [x] Implemented and tested three guardrail scenarios: greeting flow, injection blocking, legitimate SOC query passthrough
- [x] Discovered that LLM-based intent classification in NeMo is unreliable for injection detection with 7B models, switched to deterministic Python action-based input rail
- [x] Drafted and expanded `docs/proposal.md` sections 3 and 4 with actual tech stack details and added RQ5 based on week 2 findings

### Problems / Blockers
- NeMo Guardrails initially returned 404 when connecting to Ollama — resolved by adding `/v1` to the base URL in `config.yml` to use Ollama's OpenAI-compatible endpoint.
- LLM-based Colang intent classification failed to reliably block injection attempts with Mistral 7B, resolved by replacing the intent-matching rail with a deterministic Python input action using pattern matching. This is now documented as RQ5 in the proposal.

### Next week plan
- Begin building the baseline LangChain SOC co-pilot (alert intake → analysis → report pipeline)
- Integrate the NeMo Guardrails input layer with the LangChain agent
- Start drafting `docs/proposal.md` remaining sections

## Week 3

**Branch:** `emaan-week-03`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/11

### Completed this week
- [x] Built baseline SOC co-pilot agent (alert intake → LLM analysis → structured report)
- [x] Defined SecurityAlert dataclass with typed fields in `src/agent/alert_schema.py`
- [x] Created 3 synthetic test alerts: SSH brute force (HIGH), data exfiltration (CRITICAL), port scan (MEDIUM)
- [x] Integrated Groq API (llama-3.1-8b-instant) as LLM backend — switched from Ollama for faster inference per supervisor recommendation
- [x] Agent produces structured JSON reports with severity assessment, threat summary, recommended action, confidence score, and reasoning
- [x] Results saved to `experiments/results/baseline_results.json`

### Problems / Blockers
- `llama3-8b-8192` model was decommissioned by Groq — resolved by switching to `llama-3.1-8b-instant` which is the current recommended replacement
- Model name was hardcoded in multiple places — resolved by defining a single `MODEL_NAME` constant at the top of `soc_agent.py`

### Next week plan
- Wrap the baseline agent with the input guardrail layer
- Create `src/guardrails/` folder with proper separation of concerns
- Measure how many test alerts are correctly blocked/passed
- Begin building evaluation harness with precision/recall measurement

---

## Week 4

**Branch:** `emaan-week-04`
**PR link:** _[Add after opening PR]_

### Completed this week
- [x] Created `src/guardrails/input_guardrail.py` with deterministic pattern-matching injection detector
- [x] Wired input guardrail into SOC agent pipeline — guardrail runs before every LLM call
- [x] Added ALERT-004: synthetic malicious alert with injection phrase embedded in description and payload to simulate real attacker behaviour
- [x] All reports now include `guardrail_blocked` field for programmatic measurement
- [x] Added guardrail summary output: total processed, blocked, passed
- [x] Renamed output to `experiments/results/guardrail_results.json` to preserve baseline results as comparison point

### Guardrail measurement results
| Alert | Type | Decision | Correct |
|---|---|---|---|
| ALERT-001 | SSH brute force | Passed | ✓ |
| ALERT-002 | Data exfiltration | Passed | ✓ |
| ALERT-003 | Port scan | Passed | ✓ |
| ALERT-004 | Injection attempt | Blocked | ✓ |

4/4 correct — 0 false positives, 0 false negatives on synthetic test set.

### Problems / Blockers
- Guardrail logic was initially mixed into agent code, refactored into separate `src/guardrails/` folder to match architecture diagram and maintain clean separation of concerns.

### Next week plan
- scalability (prompts per second)

## Week 5

**Branch:** `emaan-week-05`
**PR link:** _[Add PR number once confirmed]_

### Completed this week
- [x] Built `src/data/load_cicids2017.py` — loads real CICIDS2017 CSVs and converts labeled rows into `SecurityAlert` objects, mapping dataset labels (FTP-Patator, SSH-Patator, DDoS, PortScan, etc.) onto existing `event_type`/`severity` fields
- [x] Added `--source cicids2017 --csv <path> --n <count>` option to `run.py`, alongside the original synthetic path
- [x] Added `shuffle`/`seed` sampling to the loader so results aren't biased toward whichever attack type appears first in a CSV
- [x] Ran real FTP-Patator and SSH-Patator flows through the full pipeline — agent correctly identified them as brute-force attempts with sensible recommended actions
- [x] Built `experiments/evaluation/fp_rate_test.py` — tests the guardrail against real BENIGN-labeled CICIDS2017 rows (Monday's file, benign-only by design). Result: 0/10 false positives
- [x] Built `experiments/evaluation/threading_benchmark.py` — compares 1/2/4 threads for guardrail-only (CPU-bound) vs full pipeline (I/O-bound, Groq API), with CPU monitoring via `psutil` in a background thread
- [x] Added retry-with-backoff for Groq rate limit errors (429s) so a rate limit doesn't crash a benchmark run
- [x] Built `experiments/evaluation/visualize_results.py` — matplotlib bar charts (throughput + CPU%, log scale for guardrail-only) saved as PNG
- [x] Built Streamlit dashboard (`dashboard/app.py`, dark theme via `.streamlit/config.toml`) — Live Demo tab (run any alert through the real pipeline) and Results Viewer tab (summary metrics, charts, browsable result tables)

### Threading benchmark results
| | 1 thread | 2 threads | 4 threads |
|---|---|---|---|
| Guardrail-only (alerts/sec) | 471,231 | 22,138 | 14,724 |
| Full pipeline (alerts/sec) | 2.40 | 3.53 | 6.96 |

Guardrail-only gets *slower* with more threads (GIL contention dominates a microsecond-scale task); full pipeline gets *faster* (GIL releases during the Groq network wait, so threads overlap I/O).

### Problems / Blockers
- `psutil`/`matplotlib`/`streamlit` were used but never actually added to `requirements.txt` — fixed by checking `pip freeze` and adding them explicitly.
- First threading benchmark run hit Groq's free-tier rate limit (6000 TPM) when concurrent threads all fired requests at once — resolved with retry-with-backoff and cooldowns between thread-count runs.
- An HTML `<div>` in the dashboard was split across separate `st.markdown()` calls, which doesn't nest in Streamlit (each call is an isolated element) — rendered as an empty stray box. Fixed by switching to `st.container(border=True)`.

### Next week plan
- Output guardrail: hallucinated CVE detection
- Build a CVE-bait test set to measure hallucination rate

---

## Week 6

**Branch:** `emaan-week-06`
**PR link:** _[Add PR number once confirmed]_ — merged

### Completed this week
- [x] Built `src/guardrails/output_guardrail.py` — second guardrail layer, runs on the LLM's *output* rather than the input
- [x] Grounding check: extracts CVE-style IDs (`CVE-YYYY-NNNNN`) from the report's text fields and compares against CVE IDs present in the original alert — anything in the output but not the input is flagged as ungrounded (the alert schema has no CVE field at all, so any CVE mentioned came from the model, not the data)
- [x] Wired into `soc_agent.py` — every report now carries `hallucinated_cves` and `output_guardrail_flagged`; bumped to `agent_version: guardrail-v0.3`
- [x] Built `experiments/evaluation/cve_bait_alerts.py` — 5 synthetic alerts describing well-known vulnerabilities (Struts2, Log4Shell, Heartbleed, ProxyLogon, Dirty COW) by symptom only, never by CVE number, to test whether the model reaches for a specific CVE anyway
- [x] Built `experiments/evaluation/cve_bait_test.py` — runs the bait set through the pipeline, reports hallucination rate

### Results
0/5 bait alerts produced a hallucinated CVE citation — the model stayed appropriately vague on all 5, consistent with the system prompt's explicit instruction not to cite CVEs unless clearly indicated.

### Problems / Blockers
- None blocking. Result is a genuine finding either way — the guardrail exists as a backstop even where the system prompt's own instruction held up on this test set.

### Next week plan
- Extend the CVE guardrail with real NVD verification, not just grounding
- Multiprocessing benchmark vs. the existing threading results

---

## Week 7

**Branch:** `emaan-week-07`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/18 — merged

### Completed this week
- [x] Extended the output guardrail to a two-stage check: Stage 1 (grounding, as in week 6), Stage 2 (real NVD lookup via NIST's public API — no hosted LLM call, no API key required)
- [x] Classifies every ungrounded CVE into `FABRICATED` (doesn't exist in NVD), `REAL_BUT_IRRELEVANT` (real CVE, doesn't match the alert topically), or `REAL_AND_PLAUSIBLE` (real CVE, topically matches — likely a correct recall, not a fabrication)
- [x] Split the single `flagged` boolean into two signals: `output_guardrail_flagged` (any ungrounded citation) and `requires_review` (actually suspicious) — a correct-but-ungrounded citation no longer silently reads identical to "nothing happened"
- [x] Built a deterministic topical-overlap check (stemmed bag-of-words comparison, no embeddings/LLM) between the alert text and NVD's real description
- [x] Found and fixed a tokenization bug: a letters-only regex was silently dropping alphanumeric technical terms like "log4j" from the comparison entirely, understating topical relevance
- [x] Re-ran the CVE-bait set with a 6th, more direct alert (BAIT-006) that explicitly asks the model to cite a CVE — confirmed the guardrail correctly classifies a real citation (`CVE-2021-44228`) as `REAL_AND_PLAUSIBLE`, not a false alarm
- [x] Surfaced both CVE guardrail signals in the Streamlit dashboard (Live Demo banner + Results Viewer metric/table); added a CVE-bait alert source to the Live Demo tab for one-click testing
- [x] Built `experiments/evaluation/multiprocessing_benchmark.py` — same 1/2/4 worker comparison as week 5's threading benchmark, but using separate processes instead of threads
- [x] Built a grouped comparison chart (threading vs. multiprocessing, both workloads) and wired it into the dashboard

### Multiprocessing benchmark results
Both workloads performed *worse* with multiprocessing than threading — guardrail-only collapsed by over 2000x (process startup + IPC serialization cost dominates a microsecond-scale task); full pipeline also got slower (each process re-creates its own Groq client and connection from scratch, instead of sharing one the way threads do).

### Problems / Blockers
- Guardrails Hub's validator for the originally-planned second comparison framework was removed from their package index mid-project — flagged and worked around in week 8, not blocking at the time since this was still CVE-guardrail work, not the issue #16 comparison itself.

### Next week plan
- Issue #16: benchmark the input guardrail against real open-source alternatives
- Finalize NVD-verification edge cases

---

## Week 8

**Branch:** `emaan-week-08`
**PR link:** _[Add PR number once confirmed]_ — open, in review

### Completed this week
- [x] Issue #16 — built a held-out 29-sample prompt-injection dataset (exact patterns, paraphrased evasions, novel attack strategies, plus benign alerts including a "security jargon in legitimate context" stress set)
- [x] Compared the baseline guardrail against two real open-source frameworks on the same dataset: LLM Guard (Protect AI) and Pytector, with confusion matrices, precision/recall/F1, FPR/FNR, latency percentiles, and throughput recorded for each
- [x] Guardrails AI was originally the planned second framework — documented and worked around: its hub validator for this task has been removed from the package index, and the only remaining hub option sends prompts to a hosted OpenAI model, violating the issue's no-hosted-API constraint. Swapped to Pytector, reasoning documented in the comparison README
- [x] Results: baseline precision 1.0 / recall 0.23, LLM Guard precision 0.87 / recall 1.0, Pytector precision 1.0 / recall 0.62 — committed to `experiments/results/guardrail_comparison.json`, with a separate human-readable write-up in `guardrail_comparison_report.md`
- [x] Addressed review feedback on the issue #16 PR: added exact reproduction commands to the README, added Pytector's version to the environment-capture function
- [x] Finalized NVD-verification edge cases: retry-with-backoff on NVD's own rate limiting (403/429), a distinct `REJECTED` classification for CVE IDs NVD has withdrawn/invalidated (previously misclassified as a normal real-but-irrelevant CVE), and correct `UNVERIFIED` handling when a CVE record has no English description (previously silently scored as a topical mismatch)
- [x] Restructured the dashboard's Live Demo result panel into an explicit 3-step pipeline view (Step 1 — input guardrail, Step 2 — LLM analysis, Step 3 — output guardrail) instead of a stack of separate banners/metrics/containers with no visual connection between them
- [x] Built a real `pytest` test suite — 54 tests across `tests/test_input_guardrail.py` and `tests/test_output_guardrail.py`, covering both guardrails' core logic, all five NVD classification branches (mocked, no network dependency), and the `flagged`/`requires_review` split specifically
- [x] The test suite caught a real bug while being written: the topical-overlap stemmer didn't collapse `"execute"`/`"execution"` to the same stem, understating relevance scores. Fixed the stemmer itself (not the test) and confirmed no regression against the real Log4Shell case — the match score improved as a result (0.174 → 0.261)

### Problems / Blockers
- Same Guardrails Hub package removal noted in week 7 turned into an actual blocker this week once issue #16 needed a working second framework — resolved by substituting Pytector and documenting the full reasoning chain (removed package → hosted-API-only replacement → swap) for reproducibility.
- Adopted the team's new weekly development policy (branch from `dev` every Monday, push daily, draft PR by Tue/Wed, ready for review by Friday) starting this week.

### Next week plan
- Hybrid input guardrail: deterministic check first, Pytector as a second-layer fallback for anything that passes, to trade some latency for better recall on non-exact-match injection attempts
- Benchmark the hybrid against the deterministic-only baseline on the existing dataset
- Build a larger, more systematic eval dataset (real published injection examples, more samples per category, more benign examples from CICIDS2017) — the 29-sample set is directionally useful but too small for statistically stable numbers
- Extend the NVD-grounding pattern to a second identifier type (CWE or MITRE ATT&CK technique IDs), per the roadmap's Aug 16 milestone
- Redo the threading vs. multiprocessing benchmark with repeated runs (the first pass was single-shot per configuration, so a single slow run could skew the whole result) and a larger `n` for the pipeline test
- nDPI substring-match comparison (carried over, unscoped)