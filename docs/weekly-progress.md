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

---

## Week 9

**Branch:** `emaan-week-09`
**PR link:** _[Add after opening PR]_

### Completed this week
- [x] Redid the threading vs. multiprocessing benchmark (Week 5/7) with repeated runs instead of single-shot: `threading_benchmark.py` and `multiprocessing_benchmark.py` now take a `--repeats` flag (default 3) and report mean/median/stdev/min/max per configuration via a shared `aggregate_runs()` helper, keeping every individual repeat's raw result nested under `raw_runs` for full reproducibility
- [x] Updated `visualize_results.py` and `visualize_concurrency_comparison.py` to plot stdev as error bars on every throughput/CPU bar, so the spread is visible instead of collapsed to one point estimate
- [x] Updated the dashboard's Results Viewer (`dashboard/app.py`) to flatten the new aggregate shape into `_mean`/`_stdev` columns for the benchmark tables, and to show stdev + repeat count on the "Best pipeline throughput" summary metric
- [x] Re-ran both benchmarks for real (3 repeats × 1/2/4 threads/processes, guardrail-only n=2000, full pipeline n=6 live Groq calls) and committed fresh results + regenerated charts
- [x] Issue #23 step 3 — MITRE ATT&CK technique checker, second instance of the CVE-checker grounding+verify pattern: extracted the shared stemmer/topical-overlap/inline-annotator logic into `src/guardrails/grounding_utils.py` so both checkers use one implementation; added `src/data/fetch_mitre_attack.py` to snapshot MITRE's public Enterprise ATT&CK STIX bundle locally (no per-ID REST endpoint exists like NVD's, and the live bundle is ~50MB — too large to fetch per check) into `data/mitre_attack/enterprise_attack_techniques.json` (858 techniques, 161 revoked/deprecated); added `src/guardrails/attack_grounding.py` with the same FABRICATED/REVOKED/REAL_BUT_IRRELEVANT/REAL_AND_PLAUSIBLE/UNVERIFIED taxonomy as the CVE checker (REVOKED in place of REJECTED); wired into `soc_agent.py` alongside the CVE check (`output_guardrail_flagged`/`requires_review` now OR across both checkers); 24 new tests in `tests/test_attack_grounding.py`, all mocked against a fixture snapshot — no network/data-file dependency in the test suite

### Results
Repeating the concurrency benchmark surfaced a finding the single-shot version couldn't distinguish from noise: on the full pipeline, 4 threads is consistently ~14x slower than 1 or 2 threads (elapsed ≈9.0s vs ≈1.2–2.2s), with stdev of only 0.02–0.29s across the 3 repeats and `rate_limited_count=0` on every run — ruling out Groq rate limiting as the cause. Since the low variance shows this is reproducible rather than a fluke, it's a candidate for follow-up investigation (thread pool contention or connection-handling behavior at that concurrency level), not something to write off as a bad run.

Manually verified the ATT&CK checker against the real snapshot: `T1055` (Process Injection, topically matching alert text) → `REAL_AND_PLAUSIBLE`; `T9999` (invented) → `FABRICATED`; `T1086` (old standalone PowerShell technique, since folded into `T1059.001`) → `REVOKED`.

### Problems / Blockers
- None blocking. `docs/weekly-progress.md` on this branch doesn't yet include the Week 5–8 sections merged on `emaan-week-08` — flagged here rather than silently duplicated, since resolving it belongs to whichever PR/merge reconciles the two branches, not to this week's entry.
- MITRE ATT&CK verification runs against a periodically-refreshed local snapshot rather than a live lookup like the CVE checker's NVD calls, since ATT&CK is only published as a single ~50MB STIX bundle with no lightweight per-ID endpoint. Documented as a real, explicit tradeoff in `attack_grounding.py` rather than presented as equivalent to the NVD case — the snapshot can lag MITRE's published data between refreshes.

### Next week plan
- Investigate the 4-thread full-pipeline slowdown found above
- Expand the CVE-bait test set and build an equivalent ATT&CK-bait set before running the LLM-judge baseline, SelfCheckGPT comparison, and cross-claim-type adversarial re-run (issue #20/#23) — those should run once against the bigger set, not twice

### Update — Evidence Pack (issue #23 step 4)
- `SecurityAlert` (`src/agent/alert_schema.py`) gained `user`, `hostname`, `file_hash` optional fields — needed because the alert schema had no structured user/host/hash data at all before this, only IP/port. Populated realistically on all 4 sample alerts (e.g. `user="root"` on the SSH brute-force alert, a `file_hash` on the exfiltration alert).
- Added `src/guardrails/evidence_pack.py`: `build_evidence_pack(alert)` pulls the alert's typed fields into explicit `ips`/`hosts`/`users`/`hashes`/`ports` buckets, and separates out a `text` field (description + payload_snippet only) as the surface CVE/ATT&CK identifier grounding actually runs against — instead of the full formatted alert blob used previously.
- `soc_agent.py`'s `analyse_alert()` now builds the evidence pack once per alert and passes `evidence_pack["text"]` to both the CVE and ATT&CK grounding checks (previously passed the full `format_alert()` string). Behaviourally equivalent for CVE/ATT&CK IDs — those never appeared in the IP/timestamp/protocol fields being excluded — but the grounding surface is now explicit rather than an artefact of prompt formatting. The evidence pack itself is attached to every report as `report["evidence_pack"]` for audit visibility.
- The structured buckets (ips/hosts/users/hashes) aren't consumed by any checker yet — CVE and ATT&CK are the only claim types in scope for issue #23. They exist now so a future IOC-grounding claim type doesn't need another schema pass.
- Dashboard Live Demo form (`dashboard/app.py`) gained User/Hostname/File hash text inputs so manually-entered alerts populate the same fields; the existing "Raw report JSON" expander already surfaces `evidence_pack` with no further dashboard change needed.
- 8 new tests in `tests/test_evidence_pack.py`. Full suite: 92/92 passing.

