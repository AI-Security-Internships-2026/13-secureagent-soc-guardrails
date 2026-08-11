# All Results & Experiments — SecureAgent-SOC

This is the full rundown of every experiment run on this project, in the order they happened: what we tried, what the numbers actually were, what broke along the way, and what it meant. Think of it as the lab notebook version of the roadmap — the roadmap tracks what's left to do, this tracks what's already been done and why.

**This is a living document.** Every time a new experiment or benchmark gets run, add a new section at the bottom of the timeline (a template is at the very end of this file to copy). Don't rewrite history — if a later experiment supersedes an earlier one, say so and link back to it, but keep the old section so the "what we tried and it didn't work" record stays intact.

---

## Quick-scan summary

| # | Experiment | When | One-line result |
|---|---|---|---|
| 1 | [Baseline SOC agent](#1-baseline-soc-agent) | Week 3 | Agent produces structured reports from alerts — works, no guardrails yet |
| 2 | [Input guardrail v1 (deterministic)](#2-input-guardrail-v1-deterministic-pattern-matching) | Week 4 | 4/4 correct on a tiny synthetic test — too small to mean much yet |
| 3 | [Real traffic test (CICIDS2017)](#3-real-traffic-test-cicids2017) | Week 5 | Agent correctly triages real attack traffic, not just synthetic |
| 4 | [False-positive rate test](#4-false-positive-rate-test) | Week 5 | 0/10 false positives on real benign traffic |
| 5 | [Threading benchmark v1](#5-threading-benchmark-v1-single-shot) | Week 5 | More threads help I/O-bound work, hurt CPU-bound work — but single-shot, unreliable |
| 6 | [Output guardrail v1 (grounding only)](#6-output-guardrail-v1-grounding-only) | Week 6 | 0/5 bait alerts fooled the model into citing a fake CVE |
| 7 | [Output guardrail v2 (NVD verification)](#7-output-guardrail-v2-nvd-verification--4-way-classification) | Week 7 | Added real-world verification, not just "does it match the input" |
| 8 | [Multiprocessing benchmark](#8-multiprocessing-benchmark) | Week 7 | Multiprocessing is worse than threading here — process overhead dominates |
| 9 | [Guardrail comparison v1 (29 samples)](#9-guardrail-comparison-v1-29-samples) | Week 8 | Deterministic guardrail: perfect precision, weak recall (0.23) vs. real tools |
| 10 | [Real test suite built](#10-real-test-suite-built) | Week 8 | 92 tests, caught a real stemmer bug along the way |
| 11 | [Concurrency benchmarks redone (repeats)](#11-concurrency-benchmarks-redone-with-repeats) | Week 9 | Confirmed the 4-thread slowdown is real, not noise |
| 12 | [4-thread slowdown investigated](#12-4-thread-slowdown-investigated) | Week 9 | Traced to Groq server-side throttling, not our code |
| 13 | [MITRE ATT&CK grounding checker](#13-mitre-attck-grounding-checker) | Week 9 | Second grounding checker built, same 4-class pattern as CVE |
| 14 | [Evidence Pack](#14-evidence-pack) | Week 9 | Structured fields replace raw-text grounding surface |
| 15 | [Secure_SOC_AI integration + CVE pool](#15-secure_soc_ai-integration--cve-pool) | Early Aug | 0% ungrounded on 76 realistic incidents; found the model never *volunteers* a CVE from behavior alone |
| 16 | [Wazuh live integration](#16-wazuh-live-integration) | Aug 8–9 | Real SIEM alerts (including a genuine brute-force detection) through the full pipeline, 0% ungrounded |
| 17 | [Hybrid input guardrail](#17-hybrid-input-guardrail) | Aug 10 | Deterministic-first + Pytector fallback: recall 0.23 → 0.615 on the old 29-sample set |
| 18 | [Larger eval dataset + re-run](#18-larger-eval-dataset--re-run-comparison) | Aug 11 | Dataset grown 29 → 119 samples with real adapted attack data; hybrid recall confirmed at 0.736 |
| 19 | [Significance testing (McNemar)](#19-significance-testing-mcnemar) | Aug 11 | Hybrid beats baseline (real), LLM Guard beats hybrid (real), hybrid vs. Pytector (not proven yet) |
| 20 | [LLM-Guard-fallback trial + latency fix](#20-llm-guard-fallback-trial--latency-methodology-fix) | Aug 11 | Swapping hybrid's fallback to LLM Guard buys nothing — literally identical predictions |
| 21 | [CVE-bait set expanded and re-run](#21-cve-bait-set-expanded-and-re-run) | Aug 12 | 6 → 25 → 100 real verified CVEs; 2/100 ungrounded (95% CI [0.6%, 7.0%]) — both on the same 2 famous CVEs, none of the 75 new ones triggered a citation |

---

## 1. Baseline SOC agent

**When:** Week 3
**What we tried:** Built the first version of the agent — takes a security alert, sends it to an LLM (Groq, `llama-3.1-8b-instant`), gets back a structured report (severity, threat summary, recommended action, confidence score). No guardrails at all yet, this is just "does the core pipeline work."

**What went wrong:**
- The model we planned to use (`llama3-8b-8192`) got discontinued by Groq mid-project — swapped to `llama-3.1-8b-instant`.
- The model name was hardcoded in several places — cleaned up into one `MODEL_NAME` constant.

**Result:** Works. 3 synthetic test alerts (SSH brute force, data exfiltration, port scan) all produced sensible structured reports. Saved to `experiments/results/baseline_results.json`.

**What it means:** Foundation is solid — the rest of the project is about wrapping this pipeline in safety checks, not rebuilding it.

---

## 2. Input guardrail v1 (deterministic pattern matching)

**When:** Week 4
**What we tried:** Built the first guardrail — a simple check that looks for known prompt-injection phrases ("ignore previous instructions," etc.) in the alert text before it reaches the LLM. Added a 4th test alert with an injection phrase hidden in it to see if the guardrail catches it.

| Alert | Type | Decision | Correct? |
|---|---|---|---|
| ALERT-001 | SSH brute force | Passed | ✓ |
| ALERT-002 | Data exfiltration | Passed | ✓ |
| ALERT-003 | Port scan | Passed | ✓ |
| ALERT-004 | Injection attempt | Blocked | ✓ |

**Result:** 4/4 correct, 0 false positives, 0 false negatives — but on only 4 samples, so this doesn't prove much yet beyond "the basic mechanism works." (This gap is exactly what the Week 8 comparison, #9 below, was built to actually measure.)

**What went wrong:** Guardrail logic was originally mixed directly into the agent code — refactored out into its own `src/guardrails/` folder for clean separation.

---

## 3. Real traffic test (CICIDS2017)

**When:** Week 5
**What we tried:** Everything so far had been hand-written synthetic alerts. Built a loader (`src/data/load_cicids2017.py`) that reads the real CICIDS2017 network intrusion dataset and converts labeled rows (FTP-Patator, SSH-Patator, DDoS, PortScan, etc.) into the same alert format the agent expects.

**Result:** Ran real FTP-Patator and SSH-Patator flows through the full pipeline — the agent correctly identified them as brute-force attempts with sensible recommended actions. Saved to `experiments/results/cicids2017_results.json` (10 alerts).

**What it means:** Confirms the agent generalizes beyond hand-crafted examples to real, messy network data.

---

## 4. False-positive rate test

**When:** Week 5
**What we tried:** Ran the input guardrail against real `BENIGN`-labeled CICIDS2017 rows (ordinary, non-attack traffic) to see how often it wrongly flags legitimate activity as an injection attempt.

**Result:** 0/10 false positives (`experiments/results/fp_rate_results.json`).

**What it means:** Good sign early on, though a sample of 10 is small — this exact concern (small sample size) is why the eval dataset later got expanded to 119 samples (#18).

---

## 5. Threading benchmark v1 (single-shot)

**When:** Week 5
**What we tried:** How does performance change with 1, 2, or 4 threads? Tested two workloads: guardrail-only (fast, CPU-bound — just pattern matching) and full pipeline (slow, I/O-bound — waits on the Groq API).

| | 1 thread | 2 threads | 4 threads |
|---|---|---|---|
| Guardrail-only (alerts/sec) | 471,231 | 22,138 | 14,724 |
| Full pipeline (alerts/sec) | 2.40 | 3.53 | 6.96 |

**What it means:** Two opposite effects, and both make sense once you know why: guardrail-only gets *slower* with more threads (Python's GIL means threads fight over the CPU for a task too fast to benefit from splitting up). Full pipeline gets *faster* (while one thread waits on the network, another can run — that's exactly where threads help).

**What went wrong:**
- `psutil`/`matplotlib`/`streamlit` were being used but never added to `requirements.txt` — fixed.
- First run hit Groq's free-tier rate limit when all threads fired requests simultaneously — fixed with retry-with-backoff.
- A dashboard HTML rendering bug (split `<div>` across separate `st.markdown()` calls) — fixed by switching to `st.container(border=True)`.

**Caveat flagged even at the time:** this was a single run per configuration — no repeats, so a single slow/fast run could skew the whole result. That's exactly what got fixed in Week 9 (#11).

---

## 6. Output guardrail v1 (grounding only)

**When:** Week 6
**What we tried:** First guardrail on the *output* side. The concern: an LLM might casually cite a CVE number that sounds plausible but isn't actually supported by anything in the alert. Built a check that extracts any `CVE-YYYY-NNNNN`-shaped ID from the report and flags it if it wasn't present anywhere in the original alert.

Built a 5-alert "bait" test set — real, well-known vulnerabilities (Struts2, Log4Shell, Heartbleed, ProxyLogon, Dirty COW) described only by *symptom*, never by CVE number, specifically to see if the model would reach for a specific CVE anyway.

**Result:** 0/5 bait alerts produced a hallucinated CVE. The model stayed appropriately vague on all 5.

**What it means:** A genuine finding either way — the guardrail exists as a backstop even on a test set where the system prompt's own instruction (don't cite CVEs unless clearly indicated) held up by itself.

---

## 7. Output guardrail v2 (NVD verification + 4-way classification)

**When:** Week 7
**What we tried:** Grounding-only (#6) can tell you a citation *wasn't in the input*, but not whether it's actually real or made up. Extended it to a two-stage check: Stage 1 is the same grounding check as before; Stage 2, for anything ungrounded, does a real lookup against the NVD (National Vulnerability Database) — no LLM call, no API key needed.

Split the result into 4 categories instead of a flat yes/no:
- **FABRICATED** — doesn't exist in NVD at all
- **REAL_BUT_IRRELEVANT** — real CVE, but doesn't actually match the alert topically
- **REAL_AND_PLAUSIBLE** — real CVE, topically matches — probably a correct recall the model made without being told the number, not a fabrication
- **REJECTED** (added later, #9) — CVE ID exists but has been formally withdrawn by NVD

**What went wrong (both real bugs, both fixed):**
- A tokenizer regex was silently dropping alphanumeric technical terms like "log4j" from the topical-match comparison entirely, understating how relevant a citation actually was.
- Re-ran the bait set with a 6th alert that explicitly asks for a CVE — confirmed the guardrail correctly classifies a real, accurate citation (`CVE-2021-44228`, Log4Shell) as `REAL_AND_PLAUSIBLE`, not a false alarm.

**What it means:** This 4-class idea — rather than a flat "flagged/not flagged" — became the actual core contribution of the paper later on (see the LLMCite framing in `docs/paper/`).

---

## 8. Multiprocessing benchmark

**When:** Week 7
**What we tried:** Same 1/2/4-way comparison as the threading benchmark (#5), but using separate OS processes instead of threads.

**Result:** Worse than threading on both workloads. Guardrail-only collapsed by over 2000x (process startup + inter-process serialization costs dominate a task that only takes microseconds). Full pipeline also got slower (each process has to build its own fresh Groq client/connection from scratch, instead of sharing one the way threads can).

**What it means:** For this workload shape, threading is the right tool, not multiprocessing — confirmed properly with repeats in Week 9 (#11).

---

## 9. Guardrail comparison v1 (29 samples)

**When:** Week 8
**What we tried:** Everything so far only tested the guardrail against patterns it was *built* to catch. This built a held-out 29-sample test set (13 injection attempts across exact/paraphrased/novel-strategy categories, 16 benign — including a "security jargon used legitimately" stress test) and compared the deterministic guardrail against two real open-source tools: LLM Guard (Protect AI) and Pytector.

| | Baseline (deterministic) | LLM Guard | Pytector |
|---|---|---|---|
| Precision | 1.0 | 0.87 | 1.0 |
| Recall | 0.23 | 1.0 | 0.62 |

**What it means:** The deterministic guardrail never wrongly blocks anything (perfect precision) but only catches known exact phrases — it missed 10 of 13 injection attempts, including *every* paraphrase and novel strategy. LLM Guard caught everything but had false positives and ran ~1000x slower per check.

**What went wrong:** The originally-planned second framework, Guardrails AI, had its relevant validator pulled from the package index mid-project, and the only remaining option required sending data to a hosted OpenAI model — which violates this project's local-only constraint. Swapped to Pytector instead, with the full reasoning chain documented for reproducibility.

**Superseded by:** #18 (same comparison, much bigger dataset) and #17 (the hybrid guardrail this result directly motivated).

---

## 10. Real test suite built

**When:** Week 8
**What we tried:** Built an actual `pytest` suite — 54 tests across the input and output guardrails, covering all 4 (later 5) NVD classification branches with mocked data (no network dependency in tests).

**What went wrong (a real bug the tests caught):** While writing the tests, found the topical-overlap stemmer didn't collapse `"execute"`/`"execution"` to the same word stem, understating how relevant a citation actually was. Fixed the stemmer (not the test), confirmed the real Log4Shell match score improved as a result (0.174 → 0.261).

**What it means:** Good example of tests catching a real bug rather than just confirming existing behavior. Suite grew to 92 tests by Week 9.

---

## 11. Concurrency benchmarks redone with repeats

**When:** Week 9
**What we tried:** The Week 5/7 benchmarks (#5, #8) were single-shot per configuration — one slow run could skew the whole result. Redid both with a `--repeats` flag (3 runs per configuration) and reported mean/median/stdev/min/max, keeping every raw run for full reproducibility.

**Threading, full pipeline (n=6 real Groq calls, 3 repeats):**

| Threads | Mean elapsed (s) | Stdev | Mean throughput (alerts/sec) |
|---|---|---|---|
| 1 | 1.90 | 0.26 | 3.20 |
| 2 | 1.17 | 0.05 | 5.16 |
| 4 | **8.99** | 0.29 | 0.67 |

**Multiprocessing, full pipeline (n=6, 3 repeats):**

| Processes | Mean elapsed (s) | Stdev | Mean throughput (alerts/sec) |
|---|---|---|---|
| 1 | 4.99 | 4.76 | 1.98 |
| 2 | 11.74 | 3.83 | 0.54 |
| 4 | 18.19 | 0.51 | 0.33 |

**What it means:** The 4-thread slowdown from earlier wasn't a fluke — it's consistently ~14x slower than 1 or 2 threads, with *low* variance (stdev only 0.02–0.29s) across repeats. Low variance + reproducible = a real effect worth investigating, not noise to write off. That investigation is #12. Multiprocessing is confirmed worse than threading across the board here, consistent with #8.

---

## 12. 4-thread slowdown investigated

**When:** Week 9
**What we tried:** Built `diagnose_thread_slowdown.py` to time each individual Groq call relative to batch start, to distinguish two possible causes: threads simply queuing for a free worker slot (expected, boring) vs. individual requests stalling once already running (points at server-side throttling).

**Result:** At 4 threads, most requests fired together at ~t=0 and finished in ~1s each — as expected. But in 2 of 3 repeats, exactly one request (among the first 4 fired simultaneously, not one waiting in a queue) took 5–11 seconds instead of ~1s. Ruled out client-side connection-pool limits (the `httpx` client allows 100 concurrent connections, far more than 4 were needed).

**What it means:** The slowdown is one connection occasionally stalling 5-10x longer than its concurrent peers, with no exception and no CPU spike — consistent with Groq throttling requests server-side under concurrent load from one API key, without an explicit 429 rejection. **Not fully resolved** — the mechanism is now evidenced, not guessed at, but this diagnostic run was itself noisier than the original benchmark, suggesting severity tracks Groq's live server load rather than being a fixed property of "4 threads."

---

## 13. MITRE ATT&CK grounding checker

**When:** Week 9
**What we tried:** Second instance of the CVE-checker pattern (#7), applied to MITRE ATT&CK technique IDs instead of CVEs. Shared logic (stemmer, topical-overlap, inline annotation) extracted into `src/guardrails/grounding_utils.py` so both checkers use one implementation. Since ATT&CK has no lightweight per-ID lookup API like NVD does, downloaded a local snapshot of the full ~50MB STIX bundle (858 techniques, 161 revoked/deprecated) instead of live per-check lookups.

**Manual verification against the real snapshot:**
- `T1055` (Process Injection, topically matches the test alert) → `REAL_AND_PLAUSIBLE` ✓
- `T9999` (invented, doesn't exist) → `FABRICATED` ✓
- `T1086` (old technique, since folded into `T1059.001`) → `REVOKED` ✓

**What went wrong / tradeoff accepted:** The snapshot can lag MITRE's actual published data between refreshes, since there's no live per-ID endpoint to check against in real time — documented explicitly as a real limitation, not glossed over as equivalent to the CVE checker's live NVD lookups.

**24 new tests**, all mocked against a fixture snapshot (no network dependency).

---

## 14. Evidence Pack

**When:** Week 9
**What we tried:** Before this, grounding checks ran against the *entire formatted alert blob* — a mix of IPs, timestamps, protocol info, and free text all mashed together. Built `build_evidence_pack()` to pull an alert's structured fields (IPs, hosts, users, hashes, ports) into explicit buckets, and separated out just the `text` field (description + payload) as the actual surface grounding checks should run against.

**What it means:** Behaviorally equivalent to before for CVE/ATT&CK IDs specifically (those never appeared in the excluded IP/timestamp fields anyway), but the grounding surface is now explicit and auditable rather than an accident of how the alert happened to get formatted into a prompt. The unused structured buckets (ips/hosts/users/hashes) are there for a future claim-verification type, not consumed by anything yet.

**8 new tests.** Full suite: 92/92 passing.

---

## 15. Secure_SOC_AI integration + CVE pool

**When:** Early August
**What we tried:** Everything so far ran on hand-crafted or CICIDS2017 alerts. Integrated a third-party open-source SOC tool (`Secure_SOC_AI`) as a *realistic incident generator* — its rule engine + correlator produce incidents, this project's own guardrailed pipeline does the triage (decided not to use their triage step at all, since replacing exactly that is the point of this project). Scaled from an initial 9 sample incidents up to 76 via `generate_events.py` to cover all 7 of the tool's shipped detection rules (their own demo dataset was only 15 events → 3 incidents, too small on its own).

Also built a 60-alert CVE pool (`cve_pool.py`, 15 real NVD-listed CVEs) split into two styles: **bait** (exploit behavior described, CVE number withheld) and **stated** (CVE number given directly).

| | n | CVE ungrounded rate | Cited the correct ground-truth CVE |
|---|---|---|---|
| Bait style (number withheld) | 30 | 0.0% | **0.0%** |
| Stated style (number given) | 30 | 0.0% | 100% |

**What it means — the important finding:** the model never fabricates a CVE (0% ungrounded either way), but when the CVE number is withheld and only behavior is described, it **never volunteers the correct one either** — it just stays silent rather than guessing. This confirms the current pipeline only *verifies claims the model already makes*, it doesn't *identify* a CVE from behavior alone. That gap is exactly what the (not-yet-built) RAG/Chroma similarity-matching idea in the roadmap backlog would address.

**76-incident Secure_SOC_AI run:** 0% ungrounded on both CVE and ATT&CK, 0% requiring review — a clean run, expected since these are rule-engine-generated incidents without adversarial intent, not a stress test.

---

## 16. Wazuh live integration

**When:** Aug 8–9
**What we tried:** Deployed a real Wazuh (SIEM/XDR) stack locally via Docker Compose, registered a real agent, and generated genuine triggering activity — File Integrity Monitoring alerts (writing a real file into a monitored path) and a real SSH brute-force attempt (repeated wrong-password logins against a throwaway local account).

**What went wrong (three real infrastructure bugs, all fixed):**
1. Cert-generation script initially failed to copy certs into the mounted host directory — turned out to be a harmless redundant-copy-pass issue, *but* running the generator twice across two sessions left a mismatched cert/key pair that crash-looped the dashboard container. Fixed by wiping certs and regenerating cleanly in one pass.
2. `sshd`'s stderr logging had no syslog-style timestamp prefix, so Wazuh's log decoder couldn't route the lines to its own rules — fixed by piping through a shell loop that prepends a proper `date | hostname | sshd[pid]:` prefix.
3. That same pipe silently block-buffered (standard behavior once stdout isn't a terminal), so nothing appeared in the log file in real time — fixed with `stdbuf -oL` to force line buffering.
4. **A real adapter bug**, found and fixed: Wazuh's own MITRE tagging isn't one consistent JSON shape — SCA/compliance rules put it flat on `rule.mitre_techniques`, but SSH rules nest it under `rule.mitre.id` instead. The adapter only checked the flat field, silently stripping the real technique ID (**T1110 — Brute Force**) off every SSH-related alert before it ever reached the LLM. Fixed by checking both shapes.

**Result:** Wazuh correctly fired 7× "authentication failed" plus, notably, its own correlation logic recognized the repeated pattern and fired 1× **"brute force trying to get access to the system"** — genuine detection behavior, not a canned alert. 13 unique alerts (after dedup) ran through the full pipeline: 0% ungrounded on ATT&CK/CVE, 0% requiring review.

**What it means:** After the adapter fix, confirmed via the raw report JSON that the LLM's reasoning genuinely engages with the real technique ID (explicitly reasoning about "T1110" once it's actually present). But this only proves the model doesn't *over-claim* beyond what it's told (the "stated" style from #15) — it does *not* test whether the model can spontaneously identify T1110 from raw behavior alone, which #15 already suggests the answer to ("no, it stays silent"). **Honest caveat:** n=13 is a one-time manual burst, good enough to prove the pipeline handles a real attack pattern correctly, not yet enough for a citable number.

---

## 17. Hybrid input guardrail

**When:** Aug 10
**What we tried:** #9 showed the deterministic guardrail has near-perfect precision but weak recall (0.23) — it only catches injection attempts using phrases it already knows. Built a hybrid: run the fast deterministic check first (as before); only if that finds nothing, fall back to Pytector's ML-based classifier.

| | Baseline (old) | Pytector alone (old) | Hybrid (new) |
|---|---|---|---|
| Recall | 0.23 | 0.62 | **0.615** |
| Precision | 1.0 | 1.0 | 1.0 |
| Median latency | ~0ms | 182.85ms | **172.96ms** |
| Throughput | — | 3.32/sec | **6.2/sec** |

**What it means:** Recall jumps to match Pytector's own recall almost exactly (the deterministic layer is a strict subset of what Pytector catches), while staying *faster* than Pytector alone and roughly doubling throughput — because 3 of the 13 injection samples were exact-pattern matches that short-circuit before the model ever has to run. Zero false positives preserved. Wired directly into the live pipeline (`soc_agent.py`).

---

## 18. Larger eval dataset + re-run comparison

**When:** Aug 11
**What we tried:** The 29-sample set (#9, #17) was directionally useful but too small to trust precisely — one misclassification moved recall by ~8 points. Grew it to 119 samples (53 injection / 66 benign):
- `exact_pattern`: 3 → 12 (hand-authored — deliberately not sourced externally, since this category exists specifically to test literal known-pattern matching)
- `paraphrase_evasion`: 5 → 23 (18 adapted from `deepset/prompt-injections`, a real public dataset of attacker-authored injection attempts — payloads rewritten to fit the SOC-alert context, offensive/political content from the source dropped)
- `novel_strategy`: 5 → 18 (13 adapted from `TrustAIRLab/in-the-wild-jailbreak-prompts`, a peer-reviewed CCS'24 dataset, plus more from deepset — covering DAN/dual-persona tricks, fake delimiters, leetspeak obfuscation, fake conversation-turn priming)
- Benign: +50 **real** `BENIGN`-labeled flow records pulled directly from the actual CICIDS2017 CSVs (not hand-crafted lookalikes)

**Re-ran the full comparison on the bigger set:**

| | Baseline | LLM Guard | Pytector | Hybrid |
|---|---|---|---|---|
| Precision | 1.0 | 0.962 | 1.0 | 1.0 |
| Recall | 0.264 | 0.943 | 0.679 | **0.736** |
| False positives | 0 | 2 | 0 | 0 |

**What it means:** The baseline's weak recall (0.23 → 0.264) wasn't a small-sample fluke — confirmed on a much bigger, more realistic set. Hybrid's recall held up (0.736, even slightly better than the old 0.615, because the bigger hand-authored `exact_pattern` bucket gives it more free catches). This also mechanically re-answered roadmap items #10/#12 (benchmark hybrid vs. deterministic, re-run the comparison) as a side effect of building the bigger dataset.

**What went wrong:** Hit a mojibake bug (em-dashes double-encoded) from not forcing UTF-8 on Windows' default file encoding when writing the JSON — caught and fixed across all 13 affected fields.

---

## 19. Significance testing (McNemar)

**When:** Aug 11
**What we tried:** The numbers in #18 are point estimates on one sample draw — needed a test to check whether the differences between guardrails are real effects or just sampling noise. Used **McNemar's test** (not a generic t-test), since all implementations ran on the *same* 119 samples, making their predictions paired, not independent. Implemented directly on scipy rather than adding a new `statsmodels` dependency.

| Comparison | Discordant pairs | p-value | Significant? |
|---|---|---|---|
| hybrid vs. Pytector | 3 | 0.250 | **No** |
| hybrid vs. LLM Guard | 17 | 0.049 | **Yes** |
| baseline vs. hybrid | 25 | <0.001 | **Yes** |

**What it means:** Hybrid beating the deterministic baseline is real and strong (expected — this comparison doubled as a sanity check that the test itself works). LLM Guard beating hybrid on recall is also real, though the p-value sits close enough to the 0.05 cutoff to state cautiously. **Important finding:** hybrid's apparent edge over Pytector alone (0.736 vs. 0.679) is **not** statistically distinguishable from chance yet — only 3 discordant predictions between them across 119 samples. Don't cite that specific comparison as proven without a bigger injection set.

---

## 20. LLM-Guard-fallback trial + latency methodology fix

**When:** Aug 11
**What we tried:** Since #19 showed LLM Guard's recall edge over hybrid is real, tried swapping the hybrid's fallback from Pytector to LLM Guard (`scan_hybrid_llmguard` — benchmark-only, not wired into the live pipeline) to see if the same architecture could recover that recall.

**Result: no benefit.** McNemar's test between this variant and plain LLM Guard came back **degenerate — zero discordant pairs across all 119 samples.** Not "close to" LLM Guard — *identical*, sample for sample. The deterministic pre-filter only adds value when the fallback it's protecting has real blind spots (true for Pytector, recall 0.679 → 0.736); LLM Guard's recall (0.943) was already high enough that the samples the fast layer would catch for free were ones LLM Guard already got right.

**What it means:** No case for shipping this variant. If LLM Guard's recall is ever worth its false-positive rate and latency for production, use LLM Guard directly — the hybrid wrapper adds nothing on top of it.

**A real bug found along the way:** while building this, discovered LLM Guard's and Pytector's reported latency numbers were being inflated by a one-time model-loading cost on their *very first* call — 129.5 seconds for LLM Guard's first sample specifically, never showing up in median/P95 because it's a single outlier. Confirmed by checking exactly which sample index caused it (position 0, every time, no exceptions). Fixed with an explicit warmup call before timing starts (`WARMUPS` in `adapters.py`), matching how a real deployment loads a model once at startup rather than on the first live alert.

**Honest limitation flagged, not hidden:** after the fix, median latency for LLM Guard/Pytector/hybrid all dropped by a similar ~2.6x ratio — more than removing one outlier explains. Most likely ordinary run-to-run system variance between two separate script executions on shared, uncontrolled hardware, not something caused by the fix itself. **Single-run latency numbers here aren't stable enough to cite precisely** — repeated trials (fresh process per implementation, mean ± spread) are needed before any millisecond figure from this benchmark goes in the paper as more than an order-of-magnitude comparison. Same caveat already on record for the threading/multiprocessing benchmarks (#11).

---

## 21. CVE-bait set expanded and re-run

**When:** Aug 12
**What we tried:** Expanded in two passes, 6 → 25 → 100. The original CVE-bait set (#6, #7) was still just n=6, and its stored result predated two bug fixes (the stemmer fix and the `requires_review` unconditional-flag fix), so it couldn't be trusted as current even at its original size. First pass: grew it to 25 real CVEs — Struts2, Log4Shell, Heartbleed, ProxyLogon, ProxyShell, Dirty COW, EternalBlue, Shellshock, PrintNightmare, Spring4Shell, Citrix Bleed, MOVEit, BlueKeep, Zerologon, a Fortinet SSL-VPN traversal, the 2024 XZ Utils supply-chain backdoor, Follina, a Citrix ADC/Gateway traversal, CurveBall, the Office Equation Editor RCE, a Confluence OGNL injection, Oracle WebLogic RCE, a SaltStack auth bypass, VMware vCenter RCE, and a second Confluence access-control flaw — each individually verified via web search. Ran it: 2/25 ungrounded (8.0%), a 22.7-point-wide confidence interval — asked "how big is big enough," computed the actual numbers (Wilson CI at several sample sizes), and landed on n≈100 as the real target for a citable estimate.

Second pass, same day: rather than hand-search 75 more CVEs one at a time, fetched CISA's official Known Exploited Vulnerabilities (KEV) catalog directly (a real, government-maintained JSON feed, 1662 entries) and built a generator that selects real CVEs from it and derives each bait alert's behavior description from that CVE's own CISA-published text — paraphrased to strip the vendor/product name and CVE framing so the alert stays purely symptom-only, not "sourced from memory" at all.

**What went wrong (two real quality/bug problems, both caught and fixed before running anything against the live pipeline):**
1. First-generation attempt: 27 of 75 entries (36%) fell back to a vague, content-free template ("...matching a documented, actively exploited weakness...") because a small hand-built CWE-to-phrase dictionary didn't cover every CWE in the data — a vague bait alert has no real symptom to test the model against, so this would have quietly degraded the test's validity even though every CVE number was still real. Fixed by deriving descriptions from each CVE's own real `shortDescription` text via a regex anchored on the word "vulnerability" (drops the vendor/product-naming preamble reliably regardless of CISA's exact phrasing), rather than a coarse lookup table.
2. A truncated file write (mid-generation `Write` call cut off) and a payload-template string with an unescaped internal quote both caused Python syntax errors — caught immediately by trying to import the file before running anything, not discovered mid-run.

**Result** (`experiments/results/cve_bait_results.json`, n=100): **2/100 alerts (2.0%) ungrounded**, both flagged for review (2.0% — exactly matches the ungrounded count, confirming the `requires_review` fix is active). 95% Wilson confidence interval: **[0.6%, 7.0%]** — down from a 22.7-point-wide band at n=25, now a genuinely citable estimate. Of the 2:
- The Log4Shell alert correctly cited `CVE-2021-44228`, classified `REAL_AND_PLAUSIBLE` — still flagged for review despite being right, exactly per policy (correct-but-ungrounded still gets reviewed).
- The Follina alert cited `CVE-2022-34713` instead of the correct `CVE-2022-30190`. **Not a fabrication** — verified `CVE-2022-34713` is real, it's "DogWalk," a separate Microsoft MSDT vulnerability disclosed the same year as Follina. Classified `REAL_BUT_IRRELEVANT` and flagged. A genuine, real-world instance of a model confusing two real, closely-related vulnerabilities.

**The most important nuance in this result:** both ungrounded citations are the *same two* found at n=25 — **none of the 75 newly added CISA-KEV CVEs produced any citation at all.** Reported precisely rather than glossed over: spontaneous citation in this pipeline appears concentrated in a small number of extremely well-publicized vulnerabilities, not a general tendency to guess across arbitrary real CVEs. The honest claim is "rarely induces spontaneous citation, and reliably catches it correctly when it does happen on famous cases" — not "stress-tested against obscure-CVE hallucination," since the 75 new alerts gave nothing to analyze either way.

**What it means:** The stale-data problem is fully resolved and the sample is now big enough for a real confidence interval, not just a bigger anecdote. The concentration finding is arguably the more interesting result of the two — it says something specific and falsifiable about *when* this failure mode occurs, not just *whether* it does.

---

## What's not run yet (see `docs/ROADMAP_PLAN.md` for the live priority order)

- **LLM-judge baseline** — ask an LLM directly "is this citation grounded," compare against the deterministic pipeline. Not built at all yet.
- **SelfCheckGPT comparison** — required by the paper scope, not built yet.
- **Presidio PII redaction** — a named threat (T3) in the original proposal, currently zero coverage. Confirmed still in scope, not dropped.
- **Significance testing on the CVE-bait comparison** — even at n=100 (#21), only 2 ungrounded citations occurred (both on the same famous CVEs found at n=25), which still isn't enough discordant data for McNemar-style testing against a future baseline to be meaningful.
- Repeated-trial latency benchmarking (fresh process per implementation) to fix the instability flagged in #20.

---

## Template for adding a new experiment

Copy this block, fill it in, and add it as a new numbered section above (update the Quick-scan table too):

```markdown
## N. [Experiment name]

**When:** [date or week]
**What we tried:** [1-3 sentences: the question being asked, and what was built/run to answer it]

[Results table or key numbers here]

**What went wrong:** [Any bugs, blockers, or surprises hit along the way — and how they were fixed. If nothing went wrong, say so explicitly rather than omitting the heading.]

**What it means:** [Plain-language takeaway — what this does and doesn't prove]
```
