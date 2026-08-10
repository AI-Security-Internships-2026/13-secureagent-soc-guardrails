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
| 5 | LLM-judge baseline added to CVE-bait benchmark | ❌ Not built | No code anywhere; only literature-review citations (FActScore, LLM-as-a-Judge) |
| 6 | Re-run CVE-bait-style adversarial test against the ATT&CK checker | ✅ Done | `attack_bait_test.py` / `attack_bait_alerts.py` — real run: 2/6 ungrounded (33%), both classified REAL_BUT_IRRELEVANT |
| 7 | Expand the CVE-bait test set size | ❌ Not done | Still n=6 — too small to support a journal-level claim |
| 8 | SelfCheckGPT comparison, actually implemented and run | ❌ Not built | Zero code references; design-decision mentions only in `docs/proposal.md` / `docs/literature-review.md`. Required by issue #20, not optional |

---

## 4. Input guardrail track (issue #16 follow-on)

| # | Item | Status | Evidence |
|---|---|---|---|
| 9 | Hybrid input guardrail (deterministic first, Pytector fallback) | ✅ Done, 2026-08-10 | `check_injection_hybrid()` in `input_guardrail.py` — runs the existing deterministic check first, only calls Pytector if that finds nothing. Wired into the live pipeline (`soc_agent.py` now calls the hybrid, not the deterministic-only function). Real re-run of the 29-sample set (`guardrail_comparison/run_comparison.py`, now includes a 4th `hybrid` entry): recall 0.615 (up from baseline's 0.23, matches Pytector's own recall exactly since the deterministic layer is a strict subset of what Pytector catches), precision still 1.0 (0 false positives), median latency 172.96ms (faster than Pytector alone's 182.85ms and throughput nearly doubles, 6.2/sec vs 3.32/sec, because exact-pattern matches — 3/13 injections — short-circuit before the model ever runs). Results in `experiments/results/guardrail_comparison.json`. |
| 10 | Benchmark hybrid vs. deterministic-only on the existing 29-sample set | ❌ Blocked on #9 | Current numbers (deterministic / LLM Guard / Pytector, run separately): recall 0.23 / 1.0 / 0.62; precision 1.0 / 0.87 / 1.0; latency ~0ms / 450ms / 452ms |
| 11 | Larger, systematic eval dataset — 20-30 real injection examples/category, more CICIDS2017 benign samples | ❌ Not done | Still 29 samples total (13 injection / 16 benign) |
| 12 | Re-run the issue #16 guardrail comparison on the bigger dataset once #11 exists | ❌ Blocked on #11 | — |

---

## 5. Other backlog

| Item | Status | Notes |
|---|---|---|
| nDPI substring-match comparison | ❌ Unscoped, carried since Week 5 | No references anywhere in the repo |
| Redo threading vs. multiprocessing benchmark (repeated runs, mean ± spread, larger n) | ⚠️ Partially done | Upgraded from single-shot to n=3 repeats this week; still deferred per your own call ("polish other tasks first, then repeat on the final pipeline") — full-pipeline n is still 6, and the mocked/synthetic-latency variant to separate scheduling overhead from live Groq behavior hasn't been built |
| Presidio-based PII redaction | ❌ Genuinely missing since Week 1 | `presidio-analyzer`/`presidio-anonymizer` are in `requirements.txt` and named in the README tech stack, but **zero references in `src/`** — never wired in. This is not just an unbuilt nice-to-have: `docs/proposal.md` names it explicitly as the planned fix for **Threat T3 (PII leakage)**, output-guardrail tier, same as hallucination (T4, which *was* built). "PII leakage rate" is also a committed success metric in the proposal with no way to currently produce it. Needs: an output-guardrail step running Presidio over the generated report, a PII-bait test set (alerts containing names/IPs/emails/SSNs), and a dashboard section, mirroring the CVE/ATT&CK grounding pattern |
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

Once the CVE-bait test set is expanded (§3 #7) and the guardrail comparison
is re-run on the larger dataset (§4 #12), add a significance test on the
resulting comparison numbers before they go into the paper. This is a
requirement attached to those two items, not a separate backlog entry.

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

Remaining/optional: wire the dashboard "click for new alert" button to this
feed; make the SSH trigger setup reproducible/scripted; consider adding a
second trigger type (e.g. network-based) for more variety; decide on a
target n before citing this anywhere; run a bait-style (label-withheld)
version of the ATT&CK grounding test against real Wazuh alerts.

---

## 10. Suggested near-term order

Given the priority flag in §2, and what's actually blocking what:

1. Hybrid input guardrail (§4 #9) — directly fixes the 0.23-recall weakness, unblocks #10 and #12
2. Larger eval dataset (§4 #11) — unblocks #10, #12, and is also required for §3 #7 (CVE-bait expansion uses the same "need more real/varied samples" work)
3. Re-run guardrail comparison + hybrid benchmark (§4 #10, #12) on the bigger dataset, with the significance test from §8
4. Expand CVE-bait set (§3 #7), using the same larger dataset effort from #2
5. LLM-judge baseline + SelfCheckGPT comparison (§3 #5, #8) — both required by issue #20, currently fully unbuilt
6. Presidio PII redaction (§5) — separate track, T3 in the proposal's threat model, currently has zero coverage
7. Everything else in §5 (nDPI, RAG/Chroma, full benchmark rigor pass) as time allows before Aug 30 write-up

This is a working document — update statuses here as items land rather than
re-deriving them from scratch each time.
