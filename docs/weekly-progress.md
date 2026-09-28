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
Repeating the concurrency benchmark surfaced a finding the single-shot version couldn't distinguish from noise: on the full pipeline, 4 threads is consistently ~7.7x slower than 2 threads (8.99s vs. 1.17s) and ~4.7x slower than 1 thread (8.99s vs. 1.90s), with stdev of only 0.05–0.29s across the 3 repeats and `rate_limited_count=0` on every run — ruling out Groq rate limiting as the cause. Since the low variance shows this is reproducible rather than a fluke, it's a candidate for follow-up investigation (thread pool contention or connection-handling behavior at that concurrency level), not something to write off as a bad run.

Manually verified the ATT&CK checker against the real snapshot: `T1055` (Process Injection, topically matching alert text) → `REAL_AND_PLAUSIBLE`; `T9999` (invented) → `FABRICATED`; `T1086` (old standalone PowerShell technique, since folded into `T1059.001`) → `REVOKED`.

### Problems / Blockers
- None blocking. `docs/weekly-progress.md` on this branch doesn't yet include the Week 5–8 sections merged on `emaan-week-08` — flagged here rather than silently duplicated, since resolving it belongs to whichever PR/merge reconciles the two branches, not to this week's entry.
- MITRE ATT&CK verification runs against a periodically-refreshed local snapshot rather than a live lookup like the CVE checker's NVD calls, since ATT&CK is only published as a single ~50MB STIX bundle with no lightweight per-ID endpoint. Documented as a real, explicit tradeoff in `attack_grounding.py` rather than presented as equivalent to the NVD case — the snapshot can lag MITRE's published data between refreshes.

### Next week plan
- Expand the CVE-bait test set and build an equivalent ATT&CK-bait set before running the LLM-judge baseline, SelfCheckGPT comparison, and cross-claim-type adversarial re-run (issue #20/#23) — those should run once against the bigger set, not twice

### Update — 4-thread full-pipeline slowdown, investigated
Built `experiments/evaluation/diagnose_thread_slowdown.py`, which instruments each Groq call with a start/end timestamp relative to batch start instead of only measuring total wall time, to distinguish two explanations: threads queuing for a free worker slot (boring, expected) vs. individual requests stalling once already running (points at server-side throttling).

Ran 3 repeats each at 2 and 4 threads (n=6, real Groq calls). Result: at 4 threads, most requests fired together at ~t=0 and completed in ~1s each, exactly as expected — but in 2 of 3 repeats, exactly one request (of the 4-6 in flight) took 5-11s instead of ~1s, while its concurrent siblings finished normally. This isn't queuing — one straggler was among the first 4 requests submitted simultaneously, not the one waiting for a worker slot to free up. Confirmed it isn't a client-side connection-pool bottleneck either: `httpx`'s default `Limits` (used under `groq`'s client) allow 100 concurrent connections / 20 keep-alive, far more than 4.

Conclusion: the slowdown is a single connection occasionally stalling 5-10x longer than its concurrent peers, with no exception raised and no CPU spike — consistent with Groq queuing/throttling requests server-side under concurrent load from one API key rather than rejecting them with an explicit 429. This diagnostic run was noisier than the original benchmark (1.46s/6.05s/10.92s across repeats vs. the original's tight 8.66-9.17s band), suggesting the effect's severity tracks Groq's live server load rather than being a fixed property of "4 threads" specifically — not fully resolved, but the mechanism (server-side per-key concurrency throttling, not client scheduling or rate-limit rejection) is now evidenced rather than guessed at. Results saved to `experiments/results/thread_slowdown_diagnosis.json`.

### Update — Evidence Pack (issue #23 step 4)
- `SecurityAlert` (`src/agent/alert_schema.py`) gained `user`, `hostname`, `file_hash` optional fields — needed because the alert schema had no structured user/host/hash data at all before this, only IP/port. Populated realistically on all 4 sample alerts (e.g. `user="root"` on the SSH brute-force alert, a `file_hash` on the exfiltration alert).
- Added `src/guardrails/evidence_pack.py`: `build_evidence_pack(alert)` pulls the alert's typed fields into explicit `ips`/`hosts`/`users`/`hashes`/`ports` buckets, and separates out a `text` field (description + payload_snippet only) as the surface CVE/ATT&CK identifier grounding actually runs against — instead of the full formatted alert blob used previously.
- `soc_agent.py`'s `analyse_alert()` now builds the evidence pack once per alert and passes `evidence_pack["text"]` to both the CVE and ATT&CK grounding checks (previously passed the full `format_alert()` string). Behaviourally equivalent for CVE/ATT&CK IDs — those never appeared in the IP/timestamp/protocol fields being excluded — but the grounding surface is now explicit rather than an artefact of prompt formatting. The evidence pack itself is attached to every report as `report["evidence_pack"]` for audit visibility.
- The structured buckets (ips/hosts/users/hashes) aren't consumed by any checker yet — CVE and ATT&CK are the only claim types in scope for issue #23. They exist now so a future IOC-grounding claim type doesn't need another schema pass.
- Dashboard Live Demo form (`dashboard/app.py`) gained User/Hostname/File hash text inputs so manually-entered alerts populate the same fields; the existing "Raw report JSON" expander already surfaces `evidence_pack` with no further dashboard change needed.
- 8 new tests in `tests/test_evidence_pack.py`. Full suite: 92/92 passing.

---

## Week 10

**Branch:** `emaan-week-10`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/25

### Completed this week
- [x] Fixed a Docker Desktop/WSL2 integration issue (stale duplicate processes) preventing the local Wazuh Docker stack from staying up reliably, and root-caused a Wazuh dashboard "login not working" report to a credential mismatch, not an infra problem — confirmed `admin`/`SecretPassword` (indexer default) directly against the indexer API.
- [x] Added a **Live Feed** tab to the Streamlit dashboard (`dashboard/app.py`): auto-polls the Wazuh indexer on a configurable interval via `st.fragment(run_every=...)`, dedupes on `(rule.id, full_log)` (same convention as `wazuh_integration_test.py`, since Wazuh's SCA module re-fires identical alerts every scan), and runs each genuinely new alert through the full guardrailed pipeline automatically. Verified live: first poll surfaced 13 real alerts fully analysed, second poll 10s later correctly found 0 new (dedup confirmed working).
- [x] Groq notified (email, Aug 14) that `llama-3.1-8b-instant` — this project's LLM backend since Week 3 — is being decommissioned Aug 16, 2026, giving effectively no runway. This is the second time Groq has discontinued this project's model mid-project (`llama3-8b-8192` was the first, Week 3).
- [x] Compared Groq's suggested replacement (`openai/gpt-oss-20b`) against staying in the Llama family (`llama-3.3-70b-versatile`) on cost, speed, and migration risk; chose `gpt-oss-20b` — cheaper ($0.10/M vs. $0.59/$0.79 per M), faster (~958 tok/s vs. slower dense 70B), and Groq's actively-recommended path. Full writeup in `docs/all_results.md` #22.
- [x] Swapped `MODEL_NAME` in `src/agent/soc_agent.py` to `openai/gpt-oss-20b`; updated now-stale model-name references in comments in `src/guardrails/output_guardrail.py` and `experiments/evaluation/threading_benchmark.py`.
- [x] Issue #20 §3 item 5 — built the **LLM-judge baseline** (`src/guardrails/llm_judge.py`): asks the LLM directly whether a report cites an identifier the alert didn't give it, instead of the deterministic string-diff. Run against the existing CVE-bait/ATT&CK-bait results (`llm_judge_baseline_test.py`): 100% agreement with the deterministic checker, but only 4 positive cases across 106 samples — not citable on its own (`docs/all_results.md` #23).
- [x] Made the LLM-judge result citable: built a class-balanced n=212 synthetic calibration set (`llm_judge_synthetic_test.py` — 106 real reports with citations stripped, paired with a twin injected with one real-but-foreign CVE/ATT&CK identifier). **100% accuracy/precision/recall, 95% Wilson CI floor 96.5%+ on every metric** (`docs/all_results.md` #24).
- [x] Issue #20 §3 item 8 — built the **SelfCheckGPT-style comparison** (`src/guardrails/selfcheckgpt.py`, `experiments/evaluation/selfcheckgpt_alerts.py`, `selfcheckgpt_test.py`): tests resampling self-consistency (does the model keep citing the same identifier at temperature=0.7 across repeats) rather than evidence-grounding, on a 60-alert stated/prompted set derived from `cve_pool.py`. Smoke-tested successfully; full run blocked (see below).
- [x] PR #25 review feedback addressed: rebased onto `dev` (merge commit, resolving 6 overlapping files from #24), corrected the 4-thread slowdown multiplier (~14x → actual ~7.7x/4.7x), added a harder "grounded-cited" construct-validity tier to the LLM-judge synthetic calibration (same distractor identifier injected into both evidence and report, not just the report), added incremental checkpointing to that script after a run crashed at ~97% completion with nothing recoverable, and rewrote the PR title/description to cover the branch's full accumulated scope (hybrid guardrail, eval-set growth, McNemar testing, CVE-bait expansion) instead of just the Week 10 items.
- [x] Issue #20 §5 — built **Presidio-based PII redaction** (`src/guardrails/pii_guardrail.py`), addressing Threat T3 from the proposal. Presidio + spaCy `en_core_web_sm`, fully local (no network/LLM calls). Detects/redacts PERSON/EMAIL_ADDRESS/PHONE_NUMBER/US_SSN/CREDIT_CARD across the report's generated text fields; wired into `soc_agent.py`. IP_ADDRESS deliberately excluded from default redaction — alert IPs are core operational telemetry (`evidence_pack.py` already treats them that way), not personal data. 16 new pytest assertions (`tests/test_pii_guardrail.py`, full suite now 111/111), plus a dashboard section + summary tile, verified rendering in-browser. Along the way: confirmed Presidio correctly deny-lists the textbook placeholder SSN (123-45-6789) as a known non-PII value, and found a real small-model NER gap — `en_core_web_sm` misses at least one non-Western name ("Priya Nair") entirely, worth a mention in the write-up as a fairness/coverage limitation, not swept under the rug. Built `pii_bait_alerts.py` (6 PII / 8 clean) + `pii_bait_test.py` and ran it for real once quota reset: 1/6 PII alerts had a detection (0/8 false positives, 0 residual PII after redaction). Manually verified the 5 "nothing detected" cases — the model consistently summarizes PII abstractly ("...containing a CSV row with sensitive employee PII (name, email, SSN)") rather than quoting raw values; the one detection was a real name quoted directly and correctly redacted. Full writeup in `docs/all_results.md` #25.

### Problems / Blockers
- All results in `docs/all_results.md` (#1–#21) were measured against `llama-3.1-8b-instant`. `gpt-oss-20b` is a different model family and larger, so prior hallucination/guardrail numbers aren't guaranteed to carry over — no re-run has happened yet, flagged as a gap rather than assumed equivalent.
- The full SelfCheckGPT run (180 calls) hit Groq's **daily** token quota (200,000 TPD, free tier) — exhausted by the same day's LLM-judge runs, not a per-minute limit retry could fix. Failed on its first alert before writing any checkpoint data, so nothing was lost, but the run needs to resume once the daily quota resets.
- The LLM-judge synthetic calibration's hard-tier run (318 calls) also hit the same daily quota, twice — once mid-run (no checkpointing existed yet, all progress lost) and once immediately on retry (quota already near-exhausted from the first attempt). Checkpointing added afterward; real run still pending quota reset.

### Next week plan
- Resume and complete the SelfCheckGPT run and the LLM-judge hard-tier run once Groq's daily quota allows; document both in `docs/all_results.md`.
- Re-run the CVE-bait and ATT&CK-bait suites against `gpt-oss-20b` to check whether the baseline hallucination rate shifted from the numbers reported for `llama-3.1-8b-instant`.

---

## Week 11

**Branch:** `emaan-week-11`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/26

### Completed this week
- [x] Resolved a branch-topology issue where `emaan-week-11` had been created before Week 10's PR (#25) was merged, so it was missing that week's work entirely. Merged PR #25 into `dev` and reset `emaan-week-11` onto the updated tip; recovered a locally-committed-but-unpushed fix (the LLM-judge resume-checkpoint logic) via `git cherry-pick` rather than losing it in the reset.
- [x] Completed the **LLM-judge hard-tier run** (issue #20 §3 item 5): the full 318-sample run (easy + hard construct-validity tiers) finished on the same day's Groq quota window that resumed it — **100% accuracy/precision/recall on every tier**, zero parse errors, closing one of the two headline evaluation gaps in the paper draft (`docs/all_results.md` #28).
- [x] Verified and hardened the **Wazuh live-feed dashboard** tab (built the prior week): found and fixed a bug where a single LLM call failure would crash the whole live-polling fragment instead of flagging just that one alert; confirmed live in a real browser session against 13 real Wazuh alerts (`docs/all_results.md` #27).
- [x] Wired the **LLM-judge baseline to support a genuinely different judge model** rather than only the same model used for report generation (`LLM_JUDGE_MODEL` env var, defaults to prior behavior so the completed same-family result is untouched). Fixed a real parsing bug for models that emit a visible reasoning block before their answer (`qwen/qwen3.6-27b`), verified with a full test-suite pass and a real end-to-end smoke test before committing to the full run. 153/318 completed so far, matching the same-family result on every sample judged (`docs/all_results.md` #30).
- [x] Resumed the **SelfCheckGPT** run (checkpoint-resume logic built the prior week) across several Groq quota windows — 16 → 23 → 33 of 60 alerts completed, all safely checkpointed with no lost progress.
- [x] **Expanded the input guardrail's deterministic phrase list from 8 to 19 phrases**, sourced from two 2024 academic datasets (AgentDojo — NeurIPS 2024, MIT license; SPML_Chatbot_Prompt_Injection — arXiv 2402.11755, MIT license), both disjoint from the datasets already used in the 119-sample eval set. Every candidate phrase was checked against all 66 benign eval samples for false positives before being added — all 11 came back clean. Re-ran the guardrail comparison: baseline recall 0.264 → 0.283 (real but not statistically significant at this sample size, paired McNemar p=1.0), precision unchanged at 1.0, hybrid essentially unchanged (`docs/all_results.md` #31).
- [x] **Expanded the ATT&CK-bait adversarial test set from 6 to 50 alerts**, individually sourced from the project's own local MITRE ATT&CK Enterprise STIX snapshot (858 real techniques with official descriptions), spanning all major ATT&CK tactics rather than clustering. Verified none of the 50 alerts leak the underlying technique ID or name into their text. Upgraded `attack_bait_test.py` to match `cve_bait_test.py`'s rigor: Wilson confidence intervals, ground-truth correct-citation tracking, and a symptom-only vs. explicit-citation-request breakdown built in from the start (rather than discovered after the fact, as happened with the CVE-bait set at n=100). Also added checkpoint-resume logic to the test script after an initial run without it would have lost all progress on a mid-run quota failure — caught and fixed before that happened for real.
- [x] Paper draft: wrote up the LLM-judge and PII-redaction sections that were previously placeholder-only; reformatted the whole document to the target venue's (Springer Nature) section-numbering and in-text-reference conventions (Arabic numerals on main headings, "Sect."/"Sects." instead of the § symbol throughout); rewrote the abstract to lead with one central research question instead of itemizing every experiment; revised how strongly the LLM-judge's 100% result is framed, since the specific construct it's tested on is closer to what the deterministic checker already computes than a deep semantic result would be.

### Problems / Blockers
- Groq's free-tier daily token quota (200,000 tokens per model) is shared across every experiment using the same model, so the LLM-judge (same-family), SelfCheckGPT, and ATT&CK-bait expansion runs all compete for the same limited daily budget on `openai/gpt-oss-20b` — only the LLM-judge run finished this week, the other two are checkpointed mid-run and resuming across quota windows.
- Discovered mid-week that Groq's daily quota is tracked per model rather than account-wide — `qwen/qwen3.6-27b` had its own separate, untouched budget even while `gpt-oss-20b` was fully exhausted, which is what made the cross-model judge run possible without waiting for a full reset.
- `attack_bait_test.py`'s first version (before this week's rewrite) didn't checkpoint incrementally, only writing results after all 50 alerts finished — caught this before the real run went far enough for it to matter, and fixed it with the same resume-from-checkpoint pattern already used elsewhere in the project.

### Next week plan
- Resume and complete SelfCheckGPT, the ATT&CK-bait run, and the cross-model LLM-judge run as Groq quota allows; document final numbers in `docs/all_results.md`.
- Continue paper draft revisions.

---

## Week 12

**Branch:** `emaan-week-12`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/27

### Completed this week
- [x] Finished the two runs left mid-flight from Week 11: **SelfCheckGPT (60/60)** and the **ATT&CK-bait set**, and built + ran the **SelfCheckGPT paired significance test** for the first time — deterministic checker significantly more accurate than self-consistency checking (McNemar p=0.0118, n=56), the paper's first statistically-confirmed result.
- [x] Found and fixed a real PII guardrail bug: Presidio's phone-number recognizer was misreading bare IP addresses as phone numbers (identical confidence score to real ones, not threshold-fixable — needed a structural "is this a valid IPv4?" check). Bulk-fired Wazuh live-alert generation from 26 → 139 real alerts across 5 trigger types, cutting the false-alarm rate from 27.3% to 2.9% after the fix.
- [x] Built the **relevance classifier validation** (92.5% accuracy vs. human judgment, n=80, `docs/all_results.md` #36) and applied a Holm-Bonferroni multiple-comparisons correction to the guardrail significance testing — walked back an earlier "LLM Guard beats hybrid" claim once corrected (only baseline-vs-hybrid survives correction).
- [x] Consolidated every already-run grounding source into one **cross-source benchmark** (575 alerts pooled, #43).
- [x] Expanded both **CVE-bait and ATT&CK-bait sets to n=150 each**; found and fixed a real metric-definition bug where PII-only review flags were silently being counted as CVE hallucinations (#44).
- [x] **Redid the concurrency/throughput benchmark** with genuinely independent fresh-process repeats and a mocked-LLM variant to separate guardrail overhead from live Groq network variance — found and fixed a real unlocked race condition in the pytector model loader along the way (#45).
- [x] Commissioned an **independent adversarial peer review** of the full paper draft (a fresh AI agent, no prior context, briefed as a harsh IJIS Reviewer 2) — restructured the whole paper around its one genuinely novel, statistically-confirmed finding (SelfCheckGPT vs. deterministic grounding) instead of five roughly-equal-weight experiments; logged the review and two disclosed-not-planned limitations it surfaced (#46).
- [x] Ran a **full accuracy review pass** on the paper draft: cross-checked every headline number against its actual source result file, found and fixed 6 issues (an off-by-one completion count repeated across 6 places, a stale test-suite count, an overclaimed "identical calibration set," bibliography hygiene — orphan references, missing citation numbers) (#47).
- [x] **Cut the paper's length** (31 pages once ported to LaTeX) toward a 12-18 page target — condensed the "Supporting Evaluation" section and the bait-test expansion history, without cutting a single number or finding (#48).
- [x] **Ported the full paper to LaTeX** (`docs/paper/sn-article.tex`), replacing the unfilled Springer Nature template with the actual content — fixed missing bibliography entries, a title-page rendering bug, and an unnecessary landscape table page; verified with a real `pdflatex`+`bibtex` compile (21/21 citations resolving) (#49).
- [x] **Re-ran the paper's central comparison on a second, independent model family** (`qwen/qwen3.6-27b`) to directly close the paper's disclosed single-model-generalization limitation rather than leave it disclosed-and-untested: the deterministic checker's advantage held and got sharper — McNemar p≈2×10⁻⁷ vs. the original p=0.0118, with SelfCheckGPT never winning a single disagreement on qwen-generated reports (#50, #51).
- [x] Added **two figures** to the paper (SelfCheckGPT correctness by class/model; concurrency throughput vs. worker count), generated directly from committed result files via a new script rather than hand-typed (#52).
- [x] Opened PR #27 (Week 12 → `dev`).

### Problems / Blockers
- Groq's daily token quota (200k tokens/model/day) meant the qwen cross-family SelfCheckGPT run (180 calls) and its paired significance test (60 calls) together spanned roughly a dozen resume-from-checkpoint cycles across 3 days — the single biggest time cost of the week, not a technical blocker.
- The paper's compiled length (24-25 pages) is still above the 12-18 page target discussed this week; decided to hold that decision open rather than cut further without first confirming the venue's actual length policy.
- Two administrative items remain before an actual submission (a real contact email, finalizing the Declarations section) — not blocking, not yet finalized.

### Next week plan
- Close out the qwen LLM-judge cross-family run if worth finishing (currently 442/450, quota-gated, diminishing returns per retry — same-family and cross-family already agree 100% on every shared sample).
- Resolve the paper's page-count gap: either trim further or confirm the venue's real length policy and accept the current length.
- Final full read-through / submission-readiness pass.

---

## Week 13

**Branch:** `emaan-week-13`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/52 (merged jointly with Week 12 as "Weeks 12-13")

### Completed this week
- [x] Ran a full accuracy review pass across the paper draft, cross-checking every headline number against its actual source result file; rewrote for clarity/length, fixed a Table 5 baseline drift, then commissioned a second rigorous peer-review pass and closed out its remaining findings (a RAG-attribution citation, a McNemar-method footnote, two new threats-to-validity disclosures) (`docs/all_results.md` #53–56)
- [x] Verified and added a scholarly-citation-hallucination reference substantiating the Abstract's novelty-contrast claim (#57), then re-ported `sn-article.tex` from the updated draft and confirmed a clean compile (#58)
- [x] Added the four per-stage ablation toggles to `analyse_alert()` (input/CVE/ATT&CK/PII, all default `True`) and recorded the component-ablation execution plan; ran Phase 2 (2-alert × 6-config schema-parity smoke validation, clean) and launched Phase 3 (#59–60)
- [x] Phase 3 crashed on a per-minute rate limit within ~15 minutes and sat dead, unnoticed, for 3 days — caught during a routine progress check, not by any alert firing. Root-caused to a bug in the "notify me when done" monitoring wrapper itself (the real experiment process had died; the watcher hadn't), fixed, and resumed correctly from checkpoint (#61)
- [x] Reviewed the new 12-issue GitHub backlog (#40–51, auto-generated milestones) and cross-checked each issue's factual claims against the actual repo rather than trusting them at face value — found real discrepancies (wrong file paths, a stray WSL2/Python-3.11 assumption, an alert-pool size that doesn't exist in this repo) (#62)
- [x] Closed out issue #46 (E1, dependency freeze) and issue #47 (E2, Week-13 regression suite + schema-parity integration test) (#62–63)
- [x] Investigated issue #41 (R2)'s three requested literature references: the issue's own pre-written citation text described papers that didn't check out on a first pass (fabricated/misdated); a second pass using better verification (DOI → Crossref, bypassing IEEE's anti-scraping block) confirmed 2 of the 3 were real after all and added them with full verification provenance — the third stayed excluded since it was never real as specified (#64–65)
- [x] Completed issue #40 (R1): built the ATT&CK-side SelfCheckGPT/McNemar replication pool (mirroring the CVE-side design, including ≥3 REVOKED technique IDs to exercise that taxonomy branch), ran it on both model families, closing the paper's disclosed CVE-only generalization gap on the central finding (#66–67)

### Problems / Blockers
- Ablation Phase 3's silent 3-day outage was the week's real lesson: a monitoring wrapper that appears to be running tells you nothing if you never verify it against a live check. Fixed the immediate case and stopped trusting a monitor on faith going forward.
- The new 12-issue GitHub backlog contains real factual errors (wrong repo paths, wrong pool sizes, at least one apparently-fabricated citation requirement) — treating every issue's claims with default skepticism from here on rather than assuming they were fact-checked before filing.

### Next week plan
- Build Docker-based reproducibility (issues #48–50 / E3–E5)
- Restructure the manuscript around explicit research questions (issue #45 / R6)
- Continue the component ablation study toward full completion

---

## Week 14

**Branch:** `emaan-week-14`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/54 (merged)

### Completed this week
- [x] Issue #49 (E4): wrote a top-level reproducible Dockerfile. Found and fixed 2 real bugs along the way — a Python-version mismatch against the actual lock file's provenance (the issue template suggested 3.11; the real lock file needs 3.12), and CUDA bloat from torch's default GPU wheel pulling several GB never used by this CPU-only image. A third bug surfaced after the build succeeded: the "offline" default smoke test silently triggered a 600MB+ live HuggingFace download of pytector's model on first use, contradicting the whole point of an offline reproducibility image — fixed by baking the model in at build time and verified via `docker stats` that network I/O dropped to a few KB (`docs/all_results.md` #68–70)
- [x] Issue #48 (E3): built NVD snapshot mode — captures and freezes every real CVE ID's NVD response used across the paper's experiments (152 IDs) into `data/nvd_snapshot/`, with a SHA-256 manifest, so CVE-side experiments reproduce byte-identical years later regardless of NVD's live API (#71)
- [x] Issue #50 (E5): wrote `REPRODUCIBILITY.md`, the canonical reproducibility index — verified every claim in the issue's own template against the actual repo first (several didn't match: wrong OS assumption, wrong Python version, a nonexistent 479-alert pool) rather than copying it as-is. Included a real, verified reproduction run matching a committed result byte-for-byte, and created the `paper-v1.0` git tag locally, held for supervisor review per the issue's own instruction (#72)
- [x] Issue #45 (R6): added an explicit Research Questions section (RQ1–4) and restructured all of Sect. 4 so each subsection opens by naming which RQ it addresses (#73)
- [x] Ran a small ablation smoke test on Groq (24 more real alerts, checkpoint resumed cleanly) and committed an inert backend-switch draft module from a CNIT compute discussion (#74)

### Problems / Blockers
- The reproducibility issue's own template (E5) assumed a different OS, a different Python version, and an alert-pool size that doesn't exist in this repo — verified against the real repo before writing anything, same pattern as the Week 13 backlog review.
- Attempted moving the ablation study to self-hosted CNIT compute; VPN connects and genuinely routes, but no reachable server hostname or credentials yet — left pending real access details rather than guessing at network topology.

### Next week plan
- Continue and complete the full component ablation study (issue #42 / R3)
- Start the human-annotation validation work (issue #43 / R4)

---

## Week 15

**Branch:** `emaan-week-15`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/55 (merged)

### Completed this week
- [x] Issue #42 (R3): resolved a real scope conflict in the issue itself — it asked for a 479-alert pool that doesn't match the actual pooled cross-source set, and separately, 139 live Wazuh alerts can't be reconstructed byte-identical (only rule IDs were ever persisted, not the per-event content). Decided with the user to run the honestly-achievable 436-alert pool instead, disclosed rather than silently substituted.
- [x] Built the frozen 436-alert pool and a resumable, crash-safe driver (`ablation_driver.py`: append-only JSONL, fsync per row, retry-with-backoff on rate limits) and started the real 6-config × 436-alert run against live Groq, seeding 507 already-run pairs from an earlier, differently-scoped run rather than re-spending quota on identical results.
- [x] Issue #43 (R4): built the blind Excel sheet and reconciliation key for a second, independent CVE relevance annotator. Found and fixed a real anonymization gap along the way — 2 of 80 pairs leaked their own CVE ID inside the raw NVD description text itself, a gap the original single-annotator pass never caught.
- [x] Ended the week at 806/2,616 ablation pairs done — C0 (full pipeline) reached completion first — gated entirely by Groq's daily token quota, not by anything in the code.

### Problems / Blockers
- Groq's daily token quota is the sole bottleneck on R3: confirmed it drains/refills gradually through the day rather than resetting cleanly once at midnight, so a same-day re-check only trickles back a handful of rows while a fully-rested day banks roughly 250–280.
- Hit and fixed a genuine pipeline bug mid-run: the model spontaneously volunteered a CVE (`CVE-2021-31207`) that was never in any alert's evidence text and had no pre-captured NVD snapshot entry, crashing the driver instead of failing gracefully. Fixed by capturing the missing snapshot and building a small auto-heal wrapper that does the same automatically if it recurs.

### Next week plan
- Keep resuming the ablation driver across quota windows until the full 2,616-pair matrix is done
- Build Table T6 and Figures F3/F4 once the run completes
- Get the second annotator's blind sheet filled in

---

## Week 16 (in progress)

**Branch:** `emaan-week-16`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/56 (open)

### Completed so far
- [x] Issue #42 (R3) — **complete.** Finished the remaining ablation runs (2,616/2,616), built Table T6 and Figures F3 (taxonomy-tier stacked bar) and F4 (UpSet plot), integrated into the manuscript. Headline finding: the PII checker, not citation checking, is the dominant contributor to the pipeline's review-flag rate (69% relative drop when removed) — the opposite of the issue's own prior assumption. The input guardrail's effect couldn't be read causally from this pool at all, since it never blocked a single alert here — disclosed honestly rather than implied.
- [x] Issue #43 (R4) — **complete.** Built blind-annotation tooling for both citation families. The first attempt used a degraded single-rater self-check (the only option with no second annotator available), but on re-reading the supervisor's explicit follow-up comment, arranged for a genuinely independent second person to do the real double-annotation instead: 80/80 agreement, Cohen's κ = 1.0. Built the ATT&CK-side relevance-classifier validation from scratch (103 pairs — no baseline existed before this week) and scored it against real human labels for the first time: 83.5% accuracy, F1 81.3%, confirming the paper's own hypothesis that the CVE-calibrated threshold is somewhat too permissive for ATT&CK's terser text — left uncalibrated per the issue's own instruction not to retune on this data. Rewrote Sect. 4.6/5 with the real numbers and methodology, not the issue's own two-annotator template text (which never matched what was actually done).
- [x] Issue #41 (R2) — **complete.** Final pre-close verification: every newly-added reference checked against the manuscript and bibliography, novelty statement re-checked against the supervisor's own explicit checklist (SOC-specific grounding, citation taxonomy, `REAL_AND_PLAUSIBLE` failure mode). No changes needed.
- [x] Issue #45 (R6) — **complete.** Final consistency check found and fixed two real gaps: RQ4's own definition text was stale (still said the ablation was in progress after R3 had already landed it), and 5 of 9 evaluation subsections were silently missing the RQ-naming opener the RQ section itself promises every subsection has.
- [x] Issue #51 (E6) — **complete.** Built and integrated both required figures (system architecture, citation-taxonomy decision sequence), both drawn directly from the real pipeline code (`analyse_alert()`, `verify_cve()`/`verify_attack_technique()`) rather than idealized versions.
- [x] Issue #44 (R5) — **started.** Built and launched the temperature-sensitivity sweep driver (30 withheld alerts × 5 temperatures × 3 resamples, 450 calls total); 88/150 done so far.
- [x] Built a full demo-companion slide deck and a shot-by-shot script and narration for the required project demo video (issue #53).
- [x] Opened PR #56 (Week 16 → `dev`).

### Problems / Blockers
- Caught two genuine data-integrity issues before they became silent errors during R4: two different "labeled" files sent for the CVE cross-check didn't actually match the real 16/80-pair sample (wrong CVE IDs, wrong file structure) — verified every `pair_id` against the true sample before computing any statistic, rather than trusting a plausible-looking spreadsheet.
- An early attempt at the ATT&CK blind-annotation sheet over-redacted technique names, destroying readability without adding real blinding — MITRE's own prose uses a technique's plain-English name as an ordinary descriptive noun (unlike NVD's number-based CVE text), so hiding it repeatedly mid-sentence didn't blind anything real. Caught by reading the actual redacted output, not just trusting the script ran without error.
- Issue #53's demo video is still not confirmed recorded, now well past its original due date.

### Next week plan
- Finish the remaining 62/150 temperature-sweep rows, build Figure F6, write up issue #44/R5 in the manuscript
- Re-run the full regression suite (issue #47/E2) once R5 finishes
- Reproducibility freeze + `paper-v1.0` tag (issue #50/E5)
- Record and share the demo video (issue #53)
