# Roadmap Plan (working document, reviewed 2026-08-08)

Consolidates: the dated milestone table in `README.md`, the issue #20 paper-track
backlog, the issue #16 input-guardrail track, and everything else mentioned in
conversation that isn't in either of those but should be tracked. Status below
was checked directly against the current codebase, not assumed from memory.

---

## 1. Official roadmap (README.md "Roadmap to September 8, 2026")

| Date | Milestone | Status |
|---|---|---|
| Aug 2 | Finalize NVD-verification edge cases from PR #18 | ✅ Done |
| Aug 9 | Compare guardrail approaches (issue #16) — latency, false-positive rate, coverage | ✅ Done — Week 8 baseline vs. LLM Guard vs. Pytector comparison. NeMo was dropped after Week 2 (not a pending comparison target); Guardrails AI swapped for Pytector because its only working validator required a hosted API, violating the local-only constraint |
| Aug 16 | Extend grounding technique to a second citation type (CWE or MITRE ATT&CK) | ✅ Done — `attack_grounding.py` + ATT&CK-bait test set + dashboard section |
| Aug 23 | Full multi-source grounding benchmark | ❌ Not started — see §5 for what this actually requires before it can be called done |
| Aug 30 | Write-up | ❌ Not started |
| Sep 6 | Paper draft | ❌ Not started |
| **Sep 8** | **Final submission** | ❌ Not started |

---

## 2. Priority flag

The Aug 23 "full multi-source grounding benchmark" milestone reads as one
task, but the guardrail-comparison report's own numbers make the **input
guardrail track** more urgent than its "backlog" framing suggested:

> Deterministic-only input guardrail recall is **0.23** — it misses 10 of 13
> injection attempts in the 29-sample held-out set, including *all*
> paraphrases and novel attack strategies. Only exact known patterns are
> caught.

If issue #20 is the paper track, "our shipped input guardrail catches under
a quarter of non-exact-match injections" is a result a reviewer will ask
about directly. **Recommendation:** treat the hybrid guardrail (item 9 below)
and the larger eval dataset (item 11) as required-before-Aug-23 work, not
optional backlog — they're load-bearing for any credible guardrail-comparison
claim in the paper, not just a nice-to-have improvement.

---

## 3. Output guardrail / paper track (issue #20)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | `requires_review` bug fix | ✅ Done | `output_guardrail.py` / `attack_grounding.py` both set `requires_review = len(ungrounded) > 0` unconditionally, with inline comment on why REAL_AND_PLAUSIBLE no longer auto-clears review |
| 2 | Inline-annotate ungrounded citations in report text (not just sibling JSON) | ✅ Done | `annotate_ungrounded_citations()` / `annotate_ungrounded_attack_citations()` both call shared `annotate_ungrounded_mentions()` (`grounding_utils.py`), tagging every occurrence in `REPORT_TEXT_FIELDS` inline |
| 3 | MITRE ATT&CK checker (2nd instance of CVE-checker pattern) | ✅ Done | `attack_grounding.py` — extract → grounded check → verify against local MITRE data → classify |
| 4 | Evidence Pack (structured fields, explicit grounding surface) | ✅ Done | `evidence_pack.py`; `soc_agent.py` passes `evidence_pack["text"]` into both grounding checks instead of the raw `format_alert()` blob |
| 5 | LLM-judge baseline added to CVE-bait benchmark | ✅ Done, full coverage 2026-08-20 | `src/guardrails/llm_judge.py` + `experiments/evaluation/llm_judge_baseline_test.py`, built for both CVE-bait and ATT&CK-bait together. 100% agreement with the deterministic checker on both sets, but only 4 positive cases total (2 CVE + 2 ATT&CK) — #23. Made citable via `experiments/evaluation/llm_judge_synthetic_test.py`: a class-balanced n=212 calibration set (106 grounded / 106 with a real-but-foreign identifier injected). **100% accuracy/precision/recall, 95% Wilson CI floor 96.5%+ on every metric** — #24. Extended to a harder construct-validity tier (distractor injected into evidence *and* report, not just report) per PR #25 review feedback — full 318-sample run completed 2026-08-20 after a resume-from-checkpoint fix (Groq's daily quota is smaller than one full run needs — #26). **Still 100% accuracy/precision/recall on every tier (easy, hard, overall)** — #28. |
| 6 | Re-run CVE-bait-style adversarial test against the ATT&CK checker | ✅ Done | `attack_bait_test.py` / `attack_bait_alerts.py` — real run: 2/6 ungrounded (33%), both classified REAL_BUT_IRRELEVANT |
| 7 | Expand the CVE-bait test set size | ✅ Done, 2026-08-12 | Expanded in two passes: `cve_bait_alerts.py` grown 6 → 25 (individually web-verified real CVEs) → **100** (75 more sourced directly from CISA's official Known Exploited Vulnerabilities catalog, behavior descriptions derived from CISA's own real per-CVE text rather than hand-recalled). Re-run at n=100 (also resolves the earlier stale-data problem — the old n=6 result predated the stemmer and `requires_review` fixes): **2/100 ungrounded (2.0%), 2/100 requires_review (2.0%, matches ungrounded exactly — fix confirmed active)**. 95% Wilson CI on the rate: **[0.6%, 7.0%]** — a real, citable estimate now (was a 22.7-point-wide band at n=25). **Important nuance, found 2026-08-12 when double-checking the two flagged cases individually:** 97 of the 100 alerts never mention a CVE at all — 0/97 of these ever produced an ungrounded citation, so the true *spontaneous* hallucination rate is 0%, not 2%. Only 3 alerts (`BAIT-002`, `BAIT-011`, `BAIT-017`) explicitly ask the model to cite a CVE identifier it wasn't given (a deliberate second variant, not the main methodology) — and both of the 2 flagged hits come from that subset of 3, not from the 97. `BAIT-011`, the third explicitly-asked alert, produced no ungrounded citation. Of the 2 flagged: `BAIT-002` cited `CVE-2021-44228` (Log4Shell) — **factually correct**, still flagged `REAL_AND_PLAUSIBLE`/review-required purely because the guardrail's rule is mechanical (not present in the input evidence = ungrounded, regardless of real-world correctness — a deliberately conservative design, not a false claim about accuracy). `BAIT-017` cited `CVE-2022-34713` "DogWalk" instead of the correct `CVE-2022-30190` Follina — both real MSDT vulnerabilities from the same year, `REAL_BUT_IRRELEVANT` — a genuine, concrete instance of the exact misattribution risk this project's paper is about, and the only one of the 100 that's a *wrong* citation rather than a correct-but-mechanically-flagged one. Results in `experiments/results/cve_bait_results.json`. Caught and fixed two real bugs while building the generator: a truncated-mid-write file (caught before running anything, via import check) and an unescaped-quote syntax error in one payload template. |
| 8 | SelfCheckGPT comparison, actually implemented and run | 🟡 Built, partially run | `experiments/evaluation/selfcheckgpt_test.py` + `selfcheckgpt_alerts.py` (60 stated/prompted alerts, 3 resamples each = 180 Groq calls) and `src/guardrails/selfcheckgpt.py`. Resume-from-checkpoint fix applied 2026-08-20 (same fix pattern as #26). First run: 16/60 alerts completed and checkpointed before hitting the day's Groq quota wall — #29. Not yet enough data (stated-class only so far) for accuracy/precision/recall. |

---

## 4. Input guardrail track (issue #16 follow-on)

| # | Item | Status | Evidence |
|---|---|---|---|
| 9 | Hybrid input guardrail (deterministic first, Pytector fallback) | ✅ Done, 2026-08-10 | `check_injection_hybrid()` in `input_guardrail.py` — runs the existing deterministic check first, only calls Pytector if that finds nothing. Wired into the live pipeline (`soc_agent.py` now calls the hybrid, not the deterministic-only function). Real re-run of the 29-sample set (`guardrail_comparison/run_comparison.py`, now includes a 4th `hybrid` entry): recall 0.615 (up from baseline's 0.23, matches Pytector's own recall exactly since the deterministic layer is a strict subset of what Pytector catches), precision still 1.0 (0 false positives), median latency 172.96ms (faster than Pytector alone's 182.85ms and throughput nearly doubles, 6.2/sec vs 3.32/sec, because exact-pattern matches — 3/13 injections — short-circuit before the model ever runs). Results in `experiments/results/guardrail_comparison.json`. |
| 10 | Benchmark hybrid vs. deterministic-only on the existing 29-sample set | ✅ Done (superseded by #12's 119-sample re-run below) | — |
| 11 | Larger, systematic eval dataset — 20-30 real injection examples/category, more CICIDS2017 benign samples | ✅ Done, 2026-08-11 | `eval_dataset.json` grown from 29 → 119 samples (53 injection / 66 benign). `exact_pattern` 3→12 (hand-authored, tests literal deterministic matches — deliberately not sourced externally). `paraphrase_evasion` 5→23 (18 adapted from `deepset/prompt-injections`, HF, Apache-2.0 — real attacker override phrasing, payloads rewritten to SOC context, offensive/political source content dropped). `novel_strategy` 5→18 (13 adapted from `TrustAIRLab/in-the-wild-jailbreak-prompts`, HF, MIT, Shen et al. CCS'24, + deepset — DAN/dual-persona, Developer Mode, leetspeak/spaced-letter evasion, fake delimiter, fake-turn priming). Benign: +50 **real** `BENIGN`-labeled CICIDS2017 flow rows sampled directly from `datasets/cicids2017/*.csv` (all 5 day-files) via the existing `load_cicids2017_alerts()` loader — no new loader code needed. Every adapted entry has a `provenance` field citing source/license. Full breakdown in `README_guardrail_comparison.md`. |
| 12 | Re-run the issue #16 guardrail comparison on the bigger dataset once #11 exists | ✅ Done, 2026-08-11 | Re-ran `run_comparison.py` on the 119-sample set: baseline P=1.0/R=0.264 (was 0.23 on 29 samples — confirms the earlier number wasn't a fluke of small-n). llm_guard P=0.962/R=0.943 (2 FP). pytector P=1.0/R=0.679. **hybrid P=1.0/R=0.736** (up from 0.615 on the old set — the larger hand-authored `exact_pattern` bucket gives it more free catches before falling back to Pytector). Results in `experiments/results/guardrail_comparison.json`. §8 significance test now also done — see §8 for the McNemar results (hybrid vs. Pytector not significant, hybrid vs. LLM Guard significant, baseline vs. hybrid significant). |
| 13 | Expand deterministic phrase list (8 → 19) from real 2024 sources | ✅ Done, 2026-08-20 | `INJECTION_PATTERNS` grown from 8 → 19, sourced from AgentDojo (NeurIPS 2024) + SPML_Chatbot_Prompt_Injection (arXiv 2402.11755, Feb 2024) — disjoint from the eval set's own source datasets, false-positive-filtered against all 66 benign samples first. Re-run: baseline recall 0.264→0.283 (real but not statistically significant, paired McNemar p=1.0, only 1 discordant pair), precision held at 1.0, hybrid essentially unchanged (0.736→0.736). `docs/all_results.md` #31. |

---

## 5. Other backlog

| Item | Status | Notes |
|---|---|---|
| nDPI substring-match comparison | ⛔ Descoped, 2026-08-20 | nDPI is a network-packet deep-packet-inspection library for classifying raw traffic by protocol signature — a different problem from this guardrail's actual job (matching English override phrases in alert/log text before it reaches the LLM). Never had any references in the repo; dropped rather than force-fit. The relevant underlying idea (fast matching against a larger pattern set) is instead covered by item 13 above — a real, sourced phrase-list expansion — with a proper multi-pattern string algorithm (Aho-Corasick) as the natural next step if list size ever grows enough to need one. |
| Redo threading vs. multiprocessing benchmark (repeated runs, mean ± spread, larger n) | ⚠️ Partially done | Upgraded from single-shot to n=3 repeats this week; still deferred per your own call ("polish other tasks first, then repeat on the final pipeline") — full-pipeline n is still 6, and the mocked/synthetic-latency variant to separate scheduling overhead from live Groq behavior hasn't been built |
| Presidio-based PII redaction | ✅ Built, 2026-08-18 | `src/guardrails/pii_guardrail.py` — Presidio + spaCy `en_core_web_sm` (local, no network/LLM calls), detects/redacts PERSON/EMAIL_ADDRESS/PHONE_NUMBER/US_SSN/CREDIT_CARD across `REPORT_TEXT_FIELDS`. Wired into `soc_agent.py` (OR'd into `output_guardrail_flagged`/`requires_review`). IP_ADDRESS deliberately excluded from the default redaction set — `evidence_pack.py` already treats alert IPs as core operational telemetry, not personal data (see module docstring for the reasoning). 16 real pytest assertions in `tests/test_pii_guardrail.py` (111/111 full suite passing); also caught and documented a real small-model NER gap (`en_core_web_sm` misses at least one non-Western name, "Priya Nair", entirely). Dashboard section + summary tile added (`dashboard/app.py`), verified rendering in-browser. `pii_bait_alerts.py` (6 PII / 8 clean) + `pii_bait_test.py` harness built and run for real, Aug 18 — 1/6 PII alerts had a detection, 0/8 false positives, 0 residual after redaction (`docs/all_results.md` #25) |
| Local RAG-based CVE verification (Chroma + small CPU embedding model) | ❌ Not started | Offline alternative to live NVD calls; would also enable a "recommend similar CVE" feature. No Chroma/RAG code anywhere in the repo. **Evidence this matters, found 2026-08-08:** ran a 60-alert CVE pool (15 real NVD-listed CVEs, bait-style vs. stated-style, see `experiments/results/soc_integration_cve_pool_results.json`) — when the CVE number is withheld and only the exploit behavior is described, the LLM cites the correct ground-truth CVE **0% of the time** (never hallucinates one either — it just doesn't volunteer a number at all). When the CVE is stated directly, it's correctly reflected 100% of the time. Confirms the current pipeline only *verifies claims the LLM already makes*, it never *identifies* a CVE from behavior alone — this RAG item is the fix, not yet built, deliberately deferred behind the higher-priority hybrid-guardrail/eval-set work for Aug 23 |
| Real test suite | ✅ Done, Week 8 | 92 passing / 1 pre-existing unrelated failure (`experiments/nemo_test/test_rails.py`, async-fixture issue) |

---

## 6. Parked (not an active task)

- **Device-level/proxy-based guardrail interception** — Future Work mention for the paper only. Clarify actual scope with supervisor whenever convenient; not scheduled.

---

## 7. Explicitly out of scope (per issue #20 — noted so nothing drifts toward these by accident)

- Internal KB / past-incidents authority source
- Claim Relevance Gate
- "Uncertain high impact" escalation tier
- Malware/tool claim verification
- Severity/remediation claim verification

---

## 8. Statistical rigor requirement (attached to §3 item 7 / §4 item 12, not its own task)

✅ Done, 2026-08-11 for the guardrail-comparison side. §4 #12 (guardrail
comparison re-run) is done — see §4 for the 119-sample numbers
(baseline/LLM Guard/Pytector/hybrid). Significance testing on those numbers
is now built and run: `experiments/evaluation/guardrail_comparison/significance_test.py`.

**Method: McNemar's test**, not a generic t-test or independent-samples
test — all four implementations (baseline, LLM Guard, Pytector, hybrid)
were run on the *same* 119 examples, so their predictions are paired per
sample, not independent draws. McNemar's test is built for exactly this:
paired binary outcomes on shared test items, using the discordant-pair
counts (A right/B wrong vs. A wrong/B right) rather than raw accuracy.
Implemented directly on scipy (exact binomial test when discordant pairs
< 25, chi-square with continuity correction above that threshold — same
25-pair cutoff `statsmodels.stats.contingency_tables.mcnemar` uses by
default) rather than adding statsmodels as a new dependency just for this
one test. Results in `experiments/results/guardrail_comparison_significance.json`.

**Results** (paired on the same 119 samples, correctness = predicted label
matches actual label):
- **hybrid vs. Pytector**: 3 discordant pairs (hybrid right/Pytector wrong:
  3, reverse: 0), exact binomial p=0.250 — **not significant**. The
  exact-pattern short-circuit's apparent recall edge (0.736 vs. 0.679) is
  not distinguishable from noise at this sample size — too few discordant
  cases to draw a real conclusion, not evidence the effect is fake.
- **hybrid vs. LLM Guard**: 17 discordant pairs (hybrid-only: 4,
  llm_guard-only: 13), exact binomial p=0.049 — **significant** (just
  under alpha=0.05). LLM Guard's higher recall is a real, measurable
  advantage over hybrid on this set, not sampling noise — though still
  worth treating cautiously given how close the p-value sits to the
  threshold.
- **baseline vs. hybrid**: 25 discordant pairs (all in hybrid's favor —
  baseline-only-correct: 0), chi-square p<0.001 — **clearly significant**,
  as expected. Confirms the test setup itself is working correctly (this
  was included specifically as a sanity check).

**What this means for the paper**: don't claim hybrid beats Pytector on
this dataset — that comparison isn't statistically resolved yet, more
injection samples would be needed to tell. Do claim hybrid beats the
deterministic baseline (strongly) and that LLM Guard beats hybrid on raw
recall (real effect, though the latency trade-off argument from the
README still applies — LLM Guard being *more accurate* doesn't make it
*better for this deployment*, just better on this one axis).

Once the CVE-bait test set is also expanded (§3 #7), re-run the same
`significance_test.py`-style testing on that comparison's numbers too.
This is a requirement attached to those two items, not a separate backlog
entry.

### 8a. Trial: LLM Guard as the hybrid's fallback instead of Pytector (2026-08-11)

Prompted directly by the §8 finding that LLM Guard's recall edge over
hybrid is real — natural question: can the same deterministic-first
architecture recover that recall by swapping which model it falls back
to? Built `scan_hybrid_llmguard` in
`experiments/evaluation/guardrail_comparison/adapters.py` (benchmark-only,
**not wired into `soc_agent.py`**) and ran it through the same 119-sample
comparison plus McNemar testing against the other four.

**Finding: no benefit over LLM Guard alone.** `hybrid_llmguard` produced
the *exact same* confusion matrix as plain LLM Guard (TP=50, FP=2, TN=64,
FN=3) — McNemar's test against LLM Guard came back **degenerate: zero
discordant pairs across all 119 samples**, meaning it's not "close to" LLM
Guard, it's identical, sample for sample. The deterministic pre-filter
only pays off when the fallback it's protecting has real blind spots
(Pytector, recall 0.679, where the fix moved recall to 0.736 — see §8).
LLM Guard's recall (0.943) is already high enough that the 12
`exact_pattern` samples the fast layer would catch for free were ones LLM
Guard already got right, so the wrapper adds a redundant fast path and
nothing else.

**Conclusion**: no reason to ship `hybrid_llmguard`. If LLM Guard's
recall/FP/latency trade-off is ever preferred for production, switch to
LLM Guard directly — wrapping it in the hybrid architecture buys nothing.

**Side effect — a real latency methodology bug found and fixed**: while
building this trial, checked exactly which sample caused LLM Guard's and
Pytector's extreme latency outliers noted in §4 (LLM Guard: 129.5 seconds
on one sample). Both landed at position 0 — the first sample each
implementation ever processed, i.e. one-time model-loading cost, not a
recurring stall. Fixed by adding a `WARMUPS` step to `adapters.py` /
`run_comparison.py` that pays this cost once before the timed loop starts,
matching how a real deployment would load the model once at startup.
Re-running after the fix dropped median latency for LLM Guard, Pytector,
and hybrid alike by a similar ratio (~480ms → ~180ms each) — more than
outlier-exclusion alone explains, most likely ordinary run-to-run system
variance rather than something caused by the fix itself. **Honest
limitation, not yet resolved**: single-run latency benchmarks on shared,
uncontrolled hardware aren't stable enough to cite precisely — same caveat
already on record for the threading/multiprocessing benchmark in §5.
Repeated trials (fresh process per implementation, mean ± spread) are
needed before any millisecond figure from this benchmark goes in the
paper as more than an order-of-magnitude comparison. Full writeup in
`README_guardrail_comparison.md`.

---

## 9. Extra tasks mentioned but not on any official list

- **Secure_SOC_AI integration** — ✅ built and run per `docs/INTEGRATION_PLAN.md`: 76 rule-engine-derived incidents (scaled up from an initial 9 via `generate_events.py`) plus a new 60-alert CVE pool (`cve_pool.py`, 15 real CVEs) both ran through the full guardrailed pipeline; results in `experiments/results/soc_integration_results.json` and `soc_integration_cve_pool_results.json`. Not yet committed to git. Supports §3's "full multi-source grounding benchmark" by supplying realistic (non-hand-crafted) incidents instead of relying only on the small bait sets, and the CVE pool run is what surfaced the RAG-matching finding in §5.
- **Overleaf porting + citation spot-check** — your own follow-up task: verify the new literature review citations (SelfCheckGPT, FActScore, TRAM, Instruction Hierarchy, LLM-as-a-Judge) against Google Scholar/dblp before finalizing, then port `docs/literature-review.md` into the actual Overleaf project.

---

## 10a. Wazuh Docker integration — scheduled, week of Aug 10

Decided 2026-08-08: build a local Wazuh (SIEM/XDR) deployment via Docker
Compose as a live, modern alert source. Motivated by two things from the
same conversation: your supervisor flagging CICIDS2017/2018 as outdated
(confirmed against a 2025 survey — *Network intrusion datasets: a survey,
limitations, and recommendations*, Computers & Security — which specifically
names CICIDS2017/CSE-CIC-IDS2018 as capturing attack patterns that no longer
reflect current threat behavior), and the dashboard "click for a new,
never-seen alert" tester idea discussed the same day. This was originally
scoped as too costly to start before Aug 23 (see conversation) — now
explicitly scheduled instead of deferred indefinitely.

Docker satisfies the local-only constraint (issue #16) the same way
Secure_SOC_AI's rule engine does: the whole stack runs on your own machine,
no hosted API calls.

Scope:
- Deploy Wazuh's Docker Compose stack (indexer + manager + dashboard) locally.
- Configure at least one log source/agent that actually generates triggering
  activity (needs a real or simulated host producing auth/process/network
  events — this is the part that makes it "live" rather than another static
  file).
- Build an adapter mapping Wazuh's native alert format onto this project's
  `SecurityAlert` schema — same pattern as `incident_to_security_alert()` in
  `experiments/evaluation/soc_integration_test.py` for Secure_SOC_AI.
- Optional: wire the dashboard "click for new alert" button to this feed
  instead of/alongside the synthetic generator (`generate_events.py`).

**Flagging, not re-litigating:** this runs the same week as the
already-agreed §2 priority (hybrid input guardrail + larger eval dataset,
load-bearing for Aug 23). Both are now live at once — worth a checkpoint
before Aug 16 to confirm the Aug 23 milestone isn't slipping because of it.

**Progress (2026-08-08, first session):**
- Official repo cloned into `experiments/evaluation/wazuh_integration/wazuh-docker/`
  (gitignored — upstream infra repo, not vendored, same pattern as Decision 3
  in `INTEGRATION_PLAN.md`), pinned to stable tag `v4.14.7` (5.0.0 is still
  beta, deliberately avoided).
- Ran `docker compose -f generate-indexer-certs.yml run --rm generator`
  (single-node stack). Image pulled fully; the cert-generation script itself
  ran and produced certs, but **failed to copy them into the mounted host
  directory**: `cp: cannot create regular file '/certificates/*.pem':
  Permission denied` for every cert file. This is a Docker Desktop
  Windows/WSL2 bind-mount permission issue, not a code or config-value
  problem — `single-node/config/wazuh_indexer_ssl_certs/` never got created.
- Session also hit an unrelated slow-network problem (image pull degraded
  from ~4.5MB/min to ~1MB/min over ~25 min) that triggered pausing for the
  night before the permission error was even noticed — so next session
  should fix the permission issue **first**, independent of network speed.
**Progress (2026-08-08, second session):** ✅ stack is up. Root cause of the
permission errors turned out to be harmless (redundant second copy pass over
already-written read-only files) — but running the generator **twice**
across two sessions left a stale `wazuh.dashboard.pem`/`-key.pem` pair
mismatched (cert from one run, key from another), which crash-looped the
dashboard container with `x509 certificate routines::key values mismatch`.
Fixed by `docker compose down -v`, wiping `wazuh_indexer_ssl_certs/*.pem`
and `*.key`, regenerating certs in a single clean run, verifying the
dashboard cert/key modulus hashes matched (`openssl x509 -modulus` /
`openssl rsa -modulus`, compared via md5), then `docker compose up -d`
again. All three containers (manager, indexer, dashboard) now up with 0
restarts; indexer cluster health is green; dashboard reachable on
`https://localhost:443` (302 login redirect); manager API responds on
`https://localhost:55000` (401, needs auth — expected). Default creds
(`admin`/`SecretPassword` for indexer, `API_USERNAME=wazuh-wui` for the
manager API) are dev-only and fine since nothing is exposed off this
machine.

**Lesson for next time:** don't re-run `generate-indexer-certs.yml` against
a non-empty certs directory — wipe it first, or the tool's read-only file
permissions silently produce a mismatched cert/key pair instead of erroring
loudly.

**Progress (2026-08-08, third session):** ✅ all core scope done end to end.
- Registered a real Wazuh agent (`wazuh-agent/`, image `wazuh/wazuh-agent:4.14.7`,
  hostname `soc-guardrails-agent-01`) on the stack's Docker network, enrolled
  via open authd on port 1515, confirmed `status: active` via the manager API.
  Config templated from the repo's own `wazuh-agent-conf` (placeholders filled
  with `wazuh.manager`/1514/1515; `authorization_pass_path` line stripped
  since enrollment is unauthenticated in this dev setup).
- Verified it produces **real** alerts, not synthetic: its default File
  Integrity Monitoring (`/usr/bin`, `/usr/sbin`) and CIS Security
  Configuration Assessment modules fired genuine alerts against the
  container's actual state. Forced a live demonstration by writing a real
  file into a FIM-monitored path and triggering an on-demand scan via the
  manager API (`PUT /syscheck?agents_list=001`) — produced a real rule-554
  "File added to the system" alert with actual sha256/md5 hashes, confirmed
  in both the manager's `alerts.json` and the indexer (`wazuh-alerts-*`).
- Built `experiments/evaluation/wazuh_integration_test.py`: queries the
  indexer directly (`GET wazuh-alerts-*/_search`, `rule.level >= 5`),
  `wazuh_alert_to_security_alert()` maps Wazuh's alert JSON onto
  `SecurityAlert` (severity bucketed from `rule.level` 0-15; MITRE IDs read
  from `rule.mitre_techniques` — later found to be only ONE of two shapes
  Wazuh actually uses, see the bug note further down), dedupes
  on `(rule.id, full_log)` since the SCA module re-fires its entire CIS
  checklist on every scan (95 raw alerts collapsed to 3 truly unique ones —
  this is a quiet, freshly-provisioned container with only one deliberate
  trigger, not a sign anything is broken).
- Ran it for real: all 3 unique alerts went through the full guardrailed
  pipeline (input guardrail → Groq LLM → CVE/ATT&CK output grounding).
  0% ungrounded ATT&CK, 0% ungrounded CVE, 0% requires-review, 0% blocked.
  Results in `experiments/results/wazuh_integration_results.json`.

**Progress (2026-08-08/09, fourth session — real attack-style trigger
activity):** ✅ done. Installed `openssh-server` inside the agent container,
enabled `PasswordAuthentication` (off by default — first attempt correctly
generated zero events because the server refused the auth method before
even checking a password), then ran repeated wrong-password logins against
a throwaway local test account (`sshtestuser`), entirely inside the one
container, nothing external.

Two real infra bugs hit and fixed along the way:
1. sshd's `-e` (log-to-stderr) output has no syslog-style timestamp/host
   prefix — Wazuh's `syslog` log-format decoder needs one to route lines to
   the sshd rules. Fixed by piping sshd's output through a small shell loop
   that prepends `date | hostname | sshd[pid]:` before appending to
   `/var/log/secure`.
2. That pipe silently buffered everything until the process was killed
   (standard C library behaviour: stdout block-buffers once it's not a
   terminal), so nothing appeared in the log file in real time. Fixed with
   `stdbuf -oL` to force line buffering through the pipeline.

Result: Wazuh correctly fired 7× rule 5760 ("sshd: authentication failed")
plus, notably, **1× rule 5763 ("sshd: brute force trying to get access to
the system")** — its own correlation logic recognized the repeated-failure
pattern as an attack, not just individual mistakes. This is genuine
detection behavior, not a canned alert. Unique alert count (after the same
dedup logic) went from 3 to 13. Re-ran `wazuh_integration_test.py` on all
13 through the full guardrailed pipeline: 0% ungrounded ATT&CK/CVE, 0%
requires-review — consistent with the earlier n=3 run, now on a real mix of
auth-attack, file-integrity, and compliance alert types instead of just
compliance noise. Results in `experiments/results/wazuh_integration_results.json`.

**Honest caveat, updated:** n=13 is still small and was a one-time manual
burst, not sustained/repeatable activity — good enough to prove the
pipeline handles a real attack pattern correctly, not yet enough for a
citable number. The SSH test setup itself (test user, host keys, password
auth enabled) lives only in the running container's writable layer, not in
version control or the compose file — it will NOT survive a container
recreate (`down`/`up --force-recreate`), only a plain `restart`. If this
needs to be reproducible later, it should be scripted properly (e.g. a
small init script baked into a custom agent image or run via
`docker compose up` command override) rather than redone by hand each time.

**Bug found and fixed (2026-08-08/09, same session) — adapter was silently
dropping ground-truth MITRE data for a whole rule family.** Wazuh's own
MITRE tagging is NOT one consistent JSON shape across rule types (confirmed
against real payloads, not documentation): SCA/compliance rules put it flat
on `rule.mitre_techniques`, but sshd rules (5760 "authentication failed",
5763 "brute force") nest it under `rule.mitre.id` instead.
`wazuh_alert_to_security_alert()` only checked the flat field, so every
SSH-related alert reached the LLM with its real technique ID (**T1110 —
Brute Force**, plus T1110.001/T1021.004 on individual failures) silently
stripped out. Fixed in `wazuh_integration_test.py` by checking both shapes.
Re-ran after the fix; confirmed via the raw report JSON that the LLM's
`reasoning` field now correctly engages with the real ID once it's actually
present (e.g. explicitly reasoning about "T1110" for the brute-force alert).

**What the unchanged 0%-ungrounded result does and doesn't mean, now that
the fix is in:** `check_hallucinated_attack_techniques()`
(`src/guardrails/attack_grounding.py`) only flags technique IDs the LLM
*added* that weren't in the alert text it was given (`mentioned - grounded`,
same convention `soc_integration_test.py` already uses — realistic alerts
keep detector-tagged IDs visible, unlike the adversarial bait sets). Since
T1110 was present in both the input alert and the LLM's output, it's
correctly excluded from "ungrounded" — that's the **"stated" style** from
the CVE-pool test (§5), not the **"bait" style**. It confirms the LLM isn't
over-claiming beyond what it's told, but it does NOT test whether the LLM
can spontaneously identify T1110 from the raw behavior alone without the
label — that's the harder, more interesting test (and the CVE-pool result
already suggests the answer would be "no, it stays silent rather than
guessing" — 0% spontaneous correct citation, but also 0% fabrication).
Running a withheld-label ("bait" style) version of this against real
Wazuh alerts, instead of only the hand-authored CVE pool, is a natural
follow-up, not yet done.

**Progress (2026-08-14):** ✅ dashboard wiring done — `dashboard/app.py`'s
"Live Feed" tab (added in commit `57ce2fe`) continuously polls the Wazuh
indexer via `st.fragment(run_every=...)`, dedupes on the same
`(rule.id, full_log)` key as `wazuh_integration_test.py`, and runs every new
alert through `analyse_alert()` (full guardrailed pipeline) automatically —
no manual per-alert click needed. This line in the roadmap doc was stale;
the item was done the same week it was written, just never checked off here.
2026-08-20: hardened so a failed LLM call (e.g. Groq daily quota exhausted)
records that one alert as an `ERROR` row instead of crashing the whole
polling fragment.

Remaining/optional: make the SSH trigger setup reproducible/scripted;
consider adding a second trigger type (e.g. network-based) for more
variety; decide on a target n before citing this anywhere; run a bait-style
(label-withheld) version of the ATT&CK grounding test against real Wazuh
alerts.

---

## 10. Suggested near-term order

§4 #9-#12 and §8's significance test (hybrid guardrail, larger eval
dataset, re-run comparison, McNemar testing) are now all done as of
2026-08-11 — see §4 and §8 for numbers. Remaining order:

1. ~~Hybrid input guardrail (§4 #9)~~ ✅ done
2. ~~Larger eval dataset (§4 #11)~~ ✅ done — 29 → 119 samples
3. ~~Re-run guardrail comparison + hybrid benchmark (§4 #10, #12)~~ ✅ done — hybrid now P=1.0/R=0.736 on the bigger set.
4. ~~Significance test on the guardrail comparison (§8)~~ ✅ done — McNemar's test via `significance_test.py`: baseline-vs-hybrid and hybrid-vs-LLM-Guard are both real, statistically significant differences; hybrid-vs-Pytector is not (too few discordant samples to tell). Full numbers in §8.
5. ~~Expand CVE-bait set (§3 #7)~~ ✅ done, 2026-08-12 — 6 → 25 → **100** real CVEs (75 sourced from CISA's KEV catalog); re-run resolved the stale-data problem too. Headline 2/100 ungrounded (95% CI [0.6%, 7.0%]) — but both hits come from the 3 alerts that explicitly ask for a CVE citation, not the 97 that don't; true spontaneous rate is 0/97. Of the 2: one is a factually correct citation flagged only by policy (Log4Shell), the other a real-but-wrong misattribution (Follina vs. DogWalk). Full breakdown in §3 item 7. Significance testing on this comparison still not meaningful — only 2 ungrounded cases even at n=100, not enough discordant data for McNemar against a future baseline.
6. ~~LLM-judge baseline (§3 #5)~~ ✅ done, full coverage 2026-08-20 — built for both CVE-bait and ATT&CK-bait together (`llm_judge.py` + `llm_judge_baseline_test.py`); 100% agreement with the deterministic checker on both sets (`docs/all_results.md` #23), then made citable with a class-balanced n=212 synthetic calibration set (100% accuracy/precision/recall, 95% Wilson CI floor 96.5%+, #24), then extended to a 318-sample hard/construct-validity tier — still 100% across every tier (#26, #28)
7. SelfCheckGPT comparison (§3 #8) — required by issue #20; built and resume-checkpoint-fixed 2026-08-20, first run got 16/60 alerts done before the day's Groq quota wall (#29); needs a few more quota windows to finish
8. ~~Presidio PII redaction (§5)~~ ✅ built, 2026-08-18 — see §5 for details; full-pipeline bait-test run still pending (Groq quota)
9. Everything else in §5 (nDPI descoped, RAG/Chroma, full benchmark rigor pass) as time allows before Aug 30 write-up

This is a working document — update statuses here as items land rather than
re-deriving them from scratch each time.

---

## 11. External manuscript review (2026-08-20) — priority additions

A detailed external review of `docs/paper/paper_draft.md` (as it stood
2026-08-20, before this section was added) gave per-venue acceptance
estimates (~45-60% at IJIS, ~60-75% at SN Computer Science if the draft
is tightened) and a specific, evidence-engaged critique — not generic
feedback; it correctly quoted exact sentences and caught a real
construction issue. Assessed against the actual codebase/results and
largely agreed with; see conversation log for the full point-by-point.
New/changed items below, prioritized by the Aug 30 deadline and this
project's actual bottlenecks (Groq daily quota; manual labeling time).

**Tier 1 — do before submission, ranked by cost:**

1. **Finish SelfCheckGPT (§3 #8)** — already in progress (23/60 as of
   2026-08-20, #29/#30 in all_results.md). Non-negotiable per the review:
   can't keep it in the abstract half-finished. Don't force a "LLMCite
   wins" framing if the data shows complementary failure-mode detection
   instead — that would be a stronger, more interesting result than
   simple superiority.
2. **Soften the LLM-judge framing (§4.8, abstract, §II)** — the review's
   sharpest point: the hard tier's grounded-cited-vs-ungrounded split is
   essentially "does this ID also appear in the evidence," mechanically
   close to what the deterministic checker already does. 100%
   accuracy there isn't a deep semantic result, it's an expected floor.
   Reframe from "counterexample to determinism-is-necessary" to
   "demonstrates the LLM can reproduce the binary decision on a
   controlled set; the deterministic implementation keeps the
   latency/cost/determinism advantages." Writing-only, no new data
   needed — do this early, it's nearly free.
3. **Rewrite the abstract around one central question** — current draft
   (~287 words) itemizes ~12 different components instead of leading
   with the actual research question. Proposed central framing (from the
   review, endorsed): *can LLM-generated SOC reports be checked for
   citations ungrounded in their evidence, and does distinguishing
   real-but-irrelevant/real-and-plausible from fabricated add useful
   assurance over a binary flag.* Everything else becomes supporting
   evidence, not co-equal headline material. Writing-only.
4. **Center the REAL_AND_PLAUSIBLE taxonomy class as the paper's main
   novelty angle** (Intro contributions, §3.5, discussion) — agreed as
   the strongest available novelty argument, since the LLM-judge result
   (item 2 above) no longer carries that weight on its own. **Important
   correction while doing this: the review's own two favorite examples
   are in different classes.** Log4Shell (`BAIT-002`, §4.3) is the real
   REAL_AND_PLAUSIBLE case (correct CVE, still flagged — the actual
   "looks right, still not verifiably grounded" story). Follina
   (`BAIT-017`) is `REAL_BUT_IRRELEVANT` (wrong-but-plausible-neighbor
   CVE) — a different, also-good story, but not this one. Lead with
   Log4Shell for this class, keep Follina as the separate
   REAL_BUT_IRRELEVANT illustration. **Honesty caveat to keep in the
   text:** REAL_AND_PLAUSIBLE has been spontaneously observed exactly
   **once** across the entire evaluation (n=100 CVE-bait + n=6
   ATT&CK-bait combined) — frame as "rare but the highest-consequence
   failure mode, hardest for manual review to catch," not as a common
   occurrence. This makes item 5 below load-bearing, not optional.
5. **Expand ATT&CK-bait set beyond n=6 (§3 #6)** — the review's most
   concrete, lowest-risk-to-implement Tier-1 item: this project already
   has the exact recipe (CVE-bait went 6→25→100, §3 #7, individually
   verified + CISA KEV-sourced). Target 30-50 real ATT&CK techniques
   the same way. Also directly strengthens item 4: more trials = more
   chances to observe additional REAL_AND_PLAUSIBLE cases instead of
   resting the paper's central claim on n=1. **Cost: real Groq calls,
   competing with #29/#30's queued quota** — needs explicit scheduling
   against SelfCheckGPT/cross-model-judge, not free.
6. **Validate the relevance classifier itself (§3.4 Stage 2)** — the
   deterministic, stemmed bag-of-words topical-overlap score is what
   actually produces the REAL_AND_PLAUSIBLE / REAL_BUT_IRRELEVANT split.
   If item 4 makes that split the paper's centerpiece, an unvalidated
   heuristic behind it is a much bigger liability than before. Build a
   manually-labeled CVE-alert relevance benchmark (~50-100 pairs),
   report precision/recall/F1, optionally compare against a semantic
   embedding baseline. **Cost: this needs a human (you) to actually
   label the ground-truth relevance pairs — not something that can be
   automated or run against Groq quota.** The single most
   labor-intensive Tier-1 item.

**Tier 2 — cheap, mechanical, do alongside the above:**

7. **Reproducibility metadata** — explicit MITRE ATT&CK STIX snapshot
   version/date/hash, NVD retrieval-date note, confirm all package
   versions are captured (`4.1` already lists most of this; snapshot
   versioning is the actual gap).
8. **"Real-world validation" → "live integration demonstration"**
   (§4.6 Wazuh) — the current phrase claims more statistical weight than
   n=13 from one manual session supports. Matches this project's own
   honesty norm everywhere else; just needs the two occurrences reworded.
9. **McNemar multiple-comparisons correction (§4.2, §8)** — 6 pairwise
   comparisons now run (`significance_test.py`'s `COMPARISON_PAIRS`), no
   Holm-Bonferroni or similar correction applied across the family yet.
   Report both raw and corrected p-values; the `hybrid vs llm_guard`
   p=0.049 result is the one closest to the line and most likely to draw
   scrutiny.
10. **Reference #10 citation spot-check** — already tracked in §9, still
    open, needs doing before submission regardless of everything above.

**Tier 3 — optional, only if time remains after Tier 1-2:**

11. **Expand PII bait set (§5, §4.11)** — review's own framing agreed
    with what's already written (§4.11 already hedges n=6 as "a first
    real signal, not a citable rate"). Lower priority than Tier 1 items —
    T3 is not the thesis; only expand if Tier 1-2 finish early.
12. **Second LLM-judge model family** — qwen/qwen3.6-27b run already in
    progress (#30, 141/318 as of 2026-08-20) independent of this review;
    continue opportunistically on quota resets, not a new ask.

This section supersedes/extends §10's ordering above where they
overlap — treat §11 as the current priority list, §10 as the historical
record of what was already true before this review.
