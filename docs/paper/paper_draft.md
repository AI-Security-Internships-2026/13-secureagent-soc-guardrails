> ## Draft status — read this first (remove before submission)
>
> This is a **working draft**, not a finished paper. It follows the outline and
> section requirements from issue #20 (target: *International Journal of
> Information Security*, Springer; backup: *SN Computer Science*). Every
> number in this document is either (a) a real result pulled directly from a
> committed results file in this repo, with the file named so it can be
> checked, or (b) explicitly marked **`[NOT YET RUN]`** with a pointer to the
> roadmap item that will produce it. Nothing has been rounded, estimated, or
> invented to fill a gap — where evidence doesn't exist yet, the section says
> so plainly instead.
>
> **Known gaps, tracked in `docs/ROADMAP_PLAN.md`:**
> - LLM-judge baseline (§3 item 5) — not built
> - SelfCheckGPT comparison (§3 item 8) — not built
> - CVE-bait test set expansion (§3 item 7) — ✅ done 2026-08-12, expanded in
>   two passes (6 → 25 → 100 real, verified CVEs, §4.3). The old n=6 result
>   predated two bug fixes and has been fully superseded; n=100 now gives a
>   citable 95% CI of [0.6%, 7.0%] on the ungrounded rate.
> - Significance testing on the CVE-bait comparison — still open; only 2
>   ungrounded citations occurred even at n=100 (both on the same famous
>   vulnerabilities found at n=25), which still isn't enough discordant
>   data for McNemar-style testing against a future baseline to be
>   meaningful (§8)
> - Presidio / PII redaction (T3 in the threat model) — zero coverage, confirmed
>   still in scope, not dropped to future work
> - Repeated-trial latency benchmarking (current numbers are single-run and
>   flagged as such in §4.7)
>
> Full chronological detail behind every claim below lives in
> `docs/all_results.md`. This draft summarizes and organizes that record into
> paper form; it doesn't replace it as the source of truth.

---

# LLMCite: Grounded Verification of Hallucinated CVE and MITRE ATT&CK Citations in LLM-Generated SOC Reports

**Author:** Emaan Afroz Khuram
**Affiliation:** CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna
**Target venue:** International Journal of Information Security (Springer). Backup: SN Computer Science.

---

## Abstract

*(target: 250 words; current draft: ~273, including a bracketed
placeholder note that will shrink once §4.8–4.9 land — trim further once
those results replace it)*

Large language models increasingly generate Security Operations Center
(SOC) threat reports, citing supporting evidence such as CVE identifiers
and MITRE ATT&CK techniques. These citations are rarely verified: models
can fabricate plausible identifiers, misattribute real ones, or recall
correct citations the alert never provided. A flat "flagged/not flagged"
treatment obscures an important distinction — an invented CVE and a
real-but-unevidenced one carry different risk profiles for an analyst
deciding how much to trust a report.

We present LLMCite, a two-stage groundedness-verification pipeline for
LLM-generated SOC reports. Stage one checks whether a cited CVE or ATT&CK
identifier is supported by the source alert; stage two verifies ungrounded
citations against authoritative sources (the National Vulnerability
Database, the MITRE ATT&CK STIX corpus) and classifies each as Fabricated,
Real-but-Irrelevant, Real-and-Plausible, or Unverified, rather than a
binary label. Real-and-Plausible citations, despite appearing legitimate,
are the case most likely to evade a naive review trigger.

We evaluate the pipeline against adversarial CVE/ATT&CK-citation
benchmarks, a third-party incident generator (76 incidents), a 60-alert CVE
pool distinguishing withheld- from stated-identifier framing, and live
Wazuh SIEM alerts (13, including a genuinely detected brute-force attack).
We also benchmark the input guardrail — deterministic matching with an ML
fallback — against two open-source alternatives on 119 samples, with
McNemar's test establishing which differences are statistically real.
**[Headline comparative result pending an LLM-judge baseline and
SelfCheckGPT comparison — see Draft status above.]** We position LLMCite as
a domain-specialized instance of citation-grounding verification for
security-critical LLM applications, distinct from prior work targeting
scholarly references.

---

## I. Introduction

Large language models (LLMs) are being adopted in Security Operations Centres
(SOCs) to automate alert triage, enrich threat intelligence, and generate
analyst-facing reports. This promises real efficiency gains, but it
introduces a specific, under-examined risk: when a model cites a CVE
identifier or a MITRE ATT&CK technique as supporting evidence for its
assessment, nothing in a typical deployment checks whether that citation is
real, relevant, or actually present in the alert the model was given.

This is not a hypothetical concern. Across our own adversarial testing
(§IV), models given ambiguous or withheld-identifier prompts either stay
silent or occasionally cite something real but topically unrelated — and
critically, a citation that *is* real but *isn't* actually supported by the
evidence at hand is not obviously distinguishable from a correct one without
independent verification. An analyst who sees a CVE number in a report has
no way to know, from the report alone, which of these happened.

Existing guardrail frameworks (NeMo Guardrails, Guardrails AI) are
general-purpose input/output filters. They were not built with a
threat-domain ontology for security claims, and none of them verify a
technical citation's factual grounding against an authoritative external
source. Existing hallucination-detection research (SelfCheckGPT
[2], FActScore [6]) establishes the
general pattern of decomposing a generation into checkable claims and
verifying them, but neither is specialized to a domain where the
verification source is a structured, versioned technical database (NVD,
MITRE ATT&CK) rather than free-text biography or open-domain knowledge.

**We want to be precise about what is and is not novel here.** The
underlying pattern — extract a claim, check if it is grounded in the
available evidence, verify against an authoritative source if not, classify
the outcome — is established in the hallucination-detection literature,
most directly in FActScore. **What this paper contributes is not a new
verification architecture; it is that pattern applied specifically to SOC
threat reports, with a four-class taxonomy in place of the binary
grounded/ungrounded label most such checkers use, and empirical evidence
that the taxonomy and the pipeline generalize across two distinct claim
types (CVE identifiers and MITRE ATT&CK techniques) rather than being a
one-off built around a single verification API.**

### Contributions

1. **A domain-specialized, two-stage citation-verification pipeline** for
   SOC LLM reports: a fast deterministic grounding check, followed by
   authoritative-source verification (NVD for CVEs, the MITRE ATT&CK STIX
   corpus for techniques) only for citations that fail grounding.
2. **A four-class outcome taxonomy** — FABRICATED, REAL_BUT_IRRELEVANT,
   REAL_AND_PLAUSIBLE, UNVERIFIED (plus a fifth, REJECTED/REVOKED, for
   identifiers formally withdrawn by their authority) — applied to two
   distinct claim types, with the specific finding that REAL_AND_PLAUSIBLE
   is the category most likely to read as legitimate to a human reviewer
   while still being unsupported by the evidence the model was actually
   given.
3. **An empirical evaluation spanning adversarial, third-party-generated,
   and live real-world data**: bait-style adversarial tests for both claim
   types, a 76-incident run through an independent third-party incident
   generator, a 60-alert CVE pool isolating whether the model can identify
   a CVE from behavior alone versus merely verify one it is given, and 13
   real alerts from a live Wazuh SIEM deployment including a genuinely
   detected brute-force attack — plus a statistically tested comparison of
   the pipeline's input-guardrail layer against two maintained open-source
   alternatives.

The remainder of this paper is organized as follows: §II reviews related
work; §III describes the pipeline architecture and taxonomy; §IV presents
the evaluation; §V discusses what the results do and do not establish,
including explicit limitations; §VI concludes.

---

## II. Related Work

**Hallucination detection and grounding.** SelfCheckGPT [2]
detects likely-hallucinated sentences by sampling multiple stochastic
responses to the same prompt and measuring consistency between them, without
requiring an external knowledge source. This is a fundamentally different
signal from what LLMCite measures: SelfCheckGPT asks "is the model
consistent about this claim," while LLMCite asks "is this claim actually
true, checked against an authoritative record." The two are complementary,
not competing — a **[NOT YET RUN — see Draft status]** direct comparison
against SelfCheckGPT on the same claim set is planned to make this
distinction empirical rather than only architectural. FActScore
[6] is the closer methodological ancestor: it decomposes
long-form generations into atomic facts and checks each against a reference
corpus (Wikipedia), reporting even strong commercial models achieve only
~58% atomic-fact precision on biographical text. LLMCite specializes this
exact pattern — decompose, ground, verify, classify — to a domain where the
reference corpus is a structured, versioned technical database rather than
open-domain prose, and to claim types (CVE and ATT&CK identifiers) that have
an unambiguous ground truth in a way free-text biographical claims do not.

**LLM-as-judge evaluation.** Zheng et al. [8] show strong LLM
judges achieve human-comparable agreement rates on open-ended response
quality, but document real biases (position, verbosity, self-enhancement)
that are a specific risk when the judge and the generator share a model
family. A **[NOT YET RUN]** LLM-judge baseline against the same CVE/ATT&CK
citation set LLMCite evaluates is planned, using a different model family
for the judge than for report generation specifically to control for
self-enhancement bias per that paper's own recommendation.

**Prompt injection and guardrail frameworks.** InjecAgent
[1] establishes the threat model this paper's input-guardrail
layer defends against — instructions hidden inside tool/log output that a
downstream agent processes as legitimate input, rather than instructions
from a trusted user. NeMo Guardrails [4] was evaluated
directly early in this project as a candidate input-guardrail framework; its
LLM-based Colang intent classification proved unreliable for injection
detection when run against a small local model, motivating a switch to
deterministic pattern matching as the first layer of this paper's own
guardrail (§III). The Instruction Hierarchy [7]
addresses the same underlying problem — distinguishing trusted from
untrusted instruction sources — at the model-training level via fine-tuning,
which is the correct fix in principle but is not available as an option when
the report-generation model is a third-party hosted API rather than a model
this project can fine-tune. LLMCite's input guardrail is instead a
runtime, deployment-side control operating on exactly the models available
in practice.

**Grounding for structured security artifacts.** TRAM
[3] is the closest existing system to LLMCite's ATT&CK
component, but solves a different problem: it extracts ATT&CK technique
mentions from *trusted*, analyst-authored threat intelligence reports. It
does not address the adversarial case this paper targets — a model
*fabricating* a technique ID that was never present in the source, or citing
a real-but-irrelevant one. TRAM is extraction from trusted text; LLMCite is
adversarial verification of a claimed citation.

**PII protection.** Presidio [5] is the planned
implementation for this project's third threat category (PII leakage in
generated reports) — **`[NOT YET BUILT — see Draft status]`**, currently
zero coverage in the implemented pipeline, discussed as an explicit
limitation in §V rather than omitted.

**Comparable commercial systems.** Deployed LLM-assisted SOC products
(Microsoft Security Copilot, Google Chronicle/Gemini for Security, IBM
QRadar Advisor with Watson, Elastic AI Assistant for Security, CrowdStrike
Charlotte AI) produce analyst-facing triage summaries, but none of their
public technical documentation describes verifying individual technical
citations against an authoritative source, and none expose a
reviewer-auditable classification of *why* a given claim should or should
not be trusted. This is the concrete "why does this matter" contrast for
LLMCite's contribution: every commercial system in this category currently
asks an analyst to trust its output as a black box.

---

## III. Proposed Method

### 3.1 Threat model

| # | Attack type | Description | Guardrail layer |
|---|---|---|---|
| T1 | Direct prompt injection | Alert/user input contains instruction-override phrases ("ignore previous instructions") attempting to hijack agent behavior | Input |
| T2 | Indirect prompt injection | Adversarial instructions embedded inside ingested alert/log data, processed as part of normal triage | Input |
| T3 | PII leakage | Sensitive data in raw alerts (names, IPs, emails, SSNs) surfaces unredacted in the generated report | Output — **`[NOT YET BUILT]`** |
| T4 | Hallucinated citation | Agent fabricates or misattributes a CVE ID or ATT&CK technique not grounded in the source alert | Output |

T1/T2 are addressed by the input guardrail (§3.2); T4 is the paper's
headline contribution (§3.3–3.4); T3 is scoped into this project (it is a
named threat in the original proposal, with "PII leakage rate" a committed
evaluation metric) but not yet implemented — see §V for why this gap is
disclosed rather than quietly dropped.

### 3.2 Input guardrail layer

The input guardrail runs deterministic substring matching against a fixed
list of known injection phrases first (near-zero latency). Text that passes
this check falls back to Pytector, a local DeBERTa-based prompt-injection
classifier, so that paraphrased or novel-strategy injection attempts not
covered by the deterministic list still have a second chance to be caught.
This ordering matters for both latency (most legitimate traffic never needs
the model call) and coverage (the deterministic layer alone has a
significant recall gap — quantified in §IV.2).

### 3.3 Evidence Pack

Rather than running grounding checks against the full formatted alert
string (a mixture of IPs, timestamps, protocol fields, and free text), an
explicit Evidence Pack is built per alert, separating structured fields
(IPs, hosts, users, file hashes, ports) from the free-text `description` and
`payload_snippet` fields that are the actual surface any CVE/ATT&CK
grounding check runs against. This makes the grounding surface an explicit,
auditable object attached to every report rather than an artifact of how a
prompt happened to be formatted.

### 3.4 Output guardrail: two-stage grounding and verification

**Stage 1 — grounding.** Any CVE-style (`CVE-YYYY-NNNNN`) or ATT&CK-style
(`Txxxx[.xxx]`) identifier is extracted from the generated report's text
fields via regex. Each extracted identifier is checked against the Evidence
Pack's `text` field: if present, it is grounded (the model is not being
scored against a citation the alert never mentioned). If absent, it proceeds
to Stage 2.

**Stage 2 — authoritative verification.** Ungrounded CVE identifiers are
looked up live against the National Vulnerability Database (NIST's public
API, no hosted-LLM call, no API key). Ungrounded ATT&CK identifiers are
checked against a periodically refreshed local snapshot of the MITRE ATT&CK
Enterprise STIX bundle (858 techniques as of the current snapshot; no
lightweight per-ID lookup endpoint exists for ATT&CK the way NVD provides
for CVEs, so this is a real, disclosed tradeoff rather than treated as
equivalent to the live CVE lookup). A deterministic, stemmed bag-of-words
topical-overlap score between the alert's evidence text and the
authoritative record's own description determines relevance.

### 3.5 Classification taxonomy

| Class | Meaning |
|---|---|
| **FABRICATED** | The identifier does not exist in the authoritative source at all |
| **REAL_BUT_IRRELEVANT** | The identifier is real but its authoritative description does not topically match the alert |
| **REAL_AND_PLAUSIBLE** | The identifier is real and topically matches — likely a correct recall the model made without being given the number, not a fabrication, but still *unverified as actually grounded in this specific alert* |
| **UNVERIFIED** | The authority source could not confirm or deny (e.g. no English-language description available, or the source was unreachable) |
| **REJECTED** (CVE) / **REVOKED** (ATT&CK) | The identifier is formally withdrawn/deprecated by its authority |

Every ungrounded citation sets `requires_review = True` unconditionally,
regardless of class. This is a deliberate design decision, not an oversight:
an earlier version of the pipeline treated REAL_AND_PLAUSIBLE as
self-evidently safe and did not flag it for review. We changed this after
recognizing that REAL_AND_PLAUSIBLE is precisely the case a human reviewer
is *least* likely to catch on manual read-through, since it looks correct —
making it the highest-risk category for silent trust, not the lowest.

---

## IV. Evaluation

### 4.1 Experimental setup

Report generation uses Groq's hosted inference (`llama-3.1-8b-instant`) as
the LLM backend throughout. All guardrail components (deterministic
matching, Pytector, LLM Guard, NVD/ATT&CK verification) run locally with no
sensitive alert data sent to any hosted API beyond the report-generation
call itself. The input-guardrail comparison (§4.2) additionally reports
package versions and environment details alongside its results file
(`experiments/results/guardrail_comparison.json`) for reproducibility. The
project's core test suite currently stands at **95 passing / 1 failing**
(the one failure is a pre-existing async-fixture issue in an abandoned,
unrelated NeMo Guardrails experiment kept for historical record — not part
of the shipped pipeline), verified directly against the repository at the
time of writing.

### 4.2 Input guardrail comparison (supporting evaluation)

The input guardrail was benchmarked against two maintained open-source
alternatives — LLM Guard (Protect AI) and Pytector — on a 119-sample
held-out set (53 injection attempts across exact-pattern, paraphrase, and
novel-strategy categories; 66 benign samples including real CICIDS2017
network-flow text and a security-jargon-in-legitimate-context stress test).
18 of the paraphrase-category and 13 of the novel-strategy-category
injection samples were adapted from two real, licensed public sources —
`deepset/prompt-injections` (Apache-2.0) and `TrustAIRLab/in-the-wild-jailbreak-prompts`
(MIT; Shen et al., "Do Anything Now," ACM CCS 2024) — with attacker-authored
override phrasing/technique preserved and payloads rewritten to fit the
SOC-alert context; every adapted entry carries a `provenance` field citing
its source. Guardrails AI, originally planned as the second comparison
framework, was excluded after its relevant hub validator was removed from
the package index mid-project, with its only remaining alternative
requiring a hosted-API call — documented in full in
`experiments/evaluation/guardrail_comparison/README_guardrail_comparison.md`.

**Results (119 samples):**

| | Baseline (deterministic) | LLM Guard | Pytector | Hybrid (deterministic + Pytector fallback) |
|---|---|---|---|---|
| Precision | 1.0 | 0.962 | 1.0 | 1.0 |
| Recall | 0.264 | 0.943 | 0.679 | 0.736 |
| F1 | 0.418 | 0.952 | 0.809 | 0.848 |
| False positives | 0 | 2 | 0 | 0 |

**Statistical significance (McNemar's test, paired on the same 119 samples,
since predictions from all implementations are correlated rather than
independent draws):**

| Comparison | p-value | Significant at α=0.05? |
|---|---|---|
| Baseline vs. Hybrid | <0.001 | **Yes** |
| Hybrid vs. LLM Guard | 0.049 | **Yes** |
| Hybrid vs. Pytector | 0.250 | **No** |

We disclose the third result plainly: hybrid's apparent recall advantage
over Pytector alone (0.736 vs. 0.679) is **not** statistically distinguishable
from chance at this sample size — only 3 discordant predictions separate
them across 119 samples. We do not claim this comparison as a proven effect.

**A follow-up trial and a methodology correction.** Since LLM Guard's
recall advantage over hybrid is real (per the test above), we tried
substituting LLM Guard for Pytector as the hybrid's fallback classifier.
The result was a **degenerate McNemar test — zero discordant predictions
against plain LLM Guard across all 119 samples** — meaning the two are
identical, sample for sample. The deterministic pre-filter adds value only
when the model it protects has meaningful blind spots (true for Pytector);
against a classifier already near ceiling recall, it adds a redundant fast
path and nothing else. While building this trial we also found that LLM
Guard's and Pytector's originally reported latency figures were inflated by
a one-time model-loading cost counted against their first-ever call
(confirmed: the extreme outlier in each case was always the first sample
processed). This is corrected via an explicit warmup step before timing in
the current benchmark; **we flag as an open limitation that single-run
latency figures on shared, uncontrolled hardware still vary by a similar
ratio (~2.6×) between separate runs of the identical code**, and do not
present exact millisecond figures as more than an order-of-magnitude
comparison until repeated-trial benchmarking (mean ± spread across multiple
isolated runs) is completed.

### 4.3 Output guardrail: CVE-bait adversarial test

**Re-run and expanded in two passes, 2026-08-12** (superseding the earlier
n=6 result, which predated the `requires_review` unconditional-flag fix
and could no longer be trusted as current). First pass: 6 → 25 real CVEs,
individually verified via web search before inclusion. Second pass: 25 →
100, sourcing the additional 75 directly from CISA's official Known
Exploited Vulnerabilities (KEV) catalog — a real, government-maintained
feed — with each alert's behavior description derived from that CVE's own
CISA-published description (paraphrased to remove the vendor/product name
and CVE framing, keeping only the exploit mechanism, so the bait alert
still tests spontaneous citation rather than pattern-matching a restated
product name). Using an authoritative bulk source for the second pass is
what made individually verifying 75 more real CVE numbers tractable at
this quality bar. Every one of the 100 CVE numbers is real and checked
against a source; a wrong "ground truth" in the test set itself would have
undermined the entire point of the exercise. 3 of the 100 alerts
additionally ask the model to name a specific identifier, rather than
staying purely symptom-only.

**Result** (`experiments/results/cve_bait_results.json`, n=100): 2/100
alerts (2.0%) produced an ungrounded CVE citation; both were flagged for
review (2.0% — identical to the ungrounded rate, confirming the
unconditional `requires_review` fix is active). The 95% Wilson confidence
interval on this rate is **[0.6%, 7.0%]** — a real, citable estimate, down
from a 22.7-point-wide interval at the original n=25.

**The two ungrounded citations are the same two found at n=25** — no
citation occurred on any of the 75 newly added, CISA-KEV-sourced alerts.
This is itself a finding worth stating precisely rather than glossing
over: spontaneous citation in this pipeline appears concentrated in a
small number of extremely well-publicized vulnerabilities, not a general
tendency to guess across arbitrary real CVEs. Of the 2:

- The Log4Shell alert (with an explicit citation request) correctly
  produced `CVE-2021-44228`, classified `REAL_AND_PLAUSIBLE` — and,
  correctly per the current taxonomy policy, still flagged for review
  despite being accurate, since the alert text itself never stated the
  number.
- The Follina alert (also an explicit citation request) produced
  `CVE-2022-34713` instead of the correct `CVE-2022-30190` — classified
  `REAL_BUT_IRRELEVANT`. This is not a fabrication: `CVE-2022-34713`
  ("DogWalk") is a real, separate Microsoft MSDT vulnerability disclosed
  the same year as Follina, patched around the same time. **This is a
  concrete, real instance of exactly the risk this paper's introduction
  describes** — a model citing a real identifier, confused with a
  closely related one, in a way indistinguishable from a correct citation
  without independent verification.

At n=100, this is now a genuinely citable estimate rather than a
qualitative-only demonstration, though the concentration finding above
means the honest framing is "the pipeline rarely induces spontaneous
citation, and reliably catches it correctly when it does occur on famous
vulnerabilities" — not "the pipeline has been stress-tested against
obscure-vulnerability hallucination," since the 75 newly added alerts
produced zero citations to analyze in the first place.

### 4.4 Output guardrail: ATT&CK-bait adversarial test

A parallel 6-alert bait set was built for MITRE ATT&CK technique citations,
covering process injection, LOLBin-style PowerShell abuse, macro-based
initial access, credential-based auth bypass, lateral movement, and
firmware-level persistence — the last two alerts explicitly asking the
model to name a specific technique ID.

**Result** (`experiments/results/attack_bait_results.json`, current, post-fix):
2/6 alerts (33%) produced an ungrounded ATT&CK citation, and — consistent
with the current `requires_review` logic — both were correctly flagged for
review. Both ungrounded citations were classified `REAL_BUT_IRRELEVANT`.

**What this shows:** the same grounding-and-classify pattern generalizes to
a second, structurally different claim type (technique IDs verified against
a static STIX snapshot rather than a live per-ID API), which is the
concrete evidence behind Contribution 2's generalization claim.

### 4.5 Real-world validation: third-party incident generator and CVE pool

To move beyond hand-authored bait alerts, `Secure_SOC_AI` (an independent,
third-party open-source SOC tool) was integrated as an incident *generator*
only — its own triage step was not used, since replacing exactly that step
is this project's contribution. Its rule engine and correlator produced 76
incidents (scaled from an initial 9 via `generate_events.py` to cover all 7
of its shipped detection rules) which were run through the full LLMCite
pipeline.

**Result:** 0% ungrounded on both CVE and ATT&CK citations, 0% requiring
review across all 76 incidents. This is an expected clean result on
non-adversarial, rule-engine-generated incidents rather than a stress test
— included for completeness, not presented as evidence of adversarial
robustness (§4.3–4.4 cover that).

A second, purpose-built 60-alert CVE pool (15 real NVD-listed CVEs, split
into **bait** style — exploit behavior described, CVE number withheld — and
**stated** style — CVE number given directly) isolates a specific question:
can the model *identify* a CVE from behavior alone, or does the pipeline
only *verify* citations it is already given?

| Style | n | CVE ungrounded rate | Cited the correct ground-truth CVE |
|---|---|---|---|
| Bait (number withheld) | 30 | 0.0% | **0.0%** |
| Stated (number given) | 30 | 0.0% | 100% |

**This is the most important finding in this subsection.** The model never
fabricates a CVE under either framing (0% ungrounded both ways), but when
the number is withheld, it also **never volunteers the correct one** — it
stays silent rather than guessing. This confirms the pipeline as built only
*verifies claims the model already makes*; it does not *identify* a CVE from
behavior alone. This is a genuine capability gap, not a guardrail failure,
and directly motivates a specific piece of future work (retrieval-based CVE
matching against behavioral description, not yet built) rather than being
glossed over as a limitation with no concrete next step.

### 4.6 Live validation: real Wazuh SIEM data

To validate against genuinely live, non-synthetic alert data rather than
only CICIDS2017 (flagged elsewhere in this project's own records as
outdated for claiming *current attack-pattern* coverage — see §V), a local
Wazuh SIEM/XDR stack was deployed via Docker Compose with a real registered
agent. Real triggering activity was generated, not just passively observed:
File Integrity Monitoring alerts from an actual file write to a monitored
path, and a genuine SSH brute-force attempt (repeated failed logins against
a throwaway local account) that Wazuh's own correlation engine correctly
recognized and escalated to a dedicated "brute force" rule — not a canned
alert, a real detection.

**Result:** 13 unique alerts (after deduplication) run through the full
pipeline: 0% ungrounded on ATT&CK/CVE, 0% requiring review. Manual
inspection of the raw report JSON confirmed the model's reasoning explicitly
engaged with the real MITRE technique ID present in the alert (**T1110 —
Brute Force**) once an adapter bug stripping it from SSH-rule alerts
specifically was found and fixed (Wazuh nests MITRE tags differently for
SCA/compliance rules versus SSH rules — the adapter originally only checked
one of the two shapes).

**Honest limitation:** n=13 is a one-time manual burst of activity, not
sustained or repeatable — sufficient to demonstrate the pipeline handles a
real, live-detected attack pattern correctly, not sufficient to support a
precise statistical claim. This result also tests the "stated" condition
only (T1110 was present in the alert Wazuh generated); it does not test
whether the model can spontaneously identify T1110 from raw behavior alone
without the label, which §4.5's CVE-pool finding already suggests the
answer to.

### 4.7 Performance benchmarks

Threading and multiprocessing were compared across 1/2/4 workers for both a
CPU-bound guardrail-only workload and the full I/O-bound pipeline (3
repeats per configuration, mean/stdev reported):

**Full pipeline, threading (n=6 real Groq calls, 3 repeats):**

| Threads | Mean elapsed (s) | Stdev | Mean throughput (alerts/sec) |
|---|---|---|---|
| 1 | 1.90 | 0.26 | 3.20 |
| 2 | 1.17 | 0.05 | 5.16 |
| 4 | **8.99** | 0.29 | 0.67 |

The 4-thread slowdown is reproducible (low stdev across repeats) rather
than a single bad run, and was traced — via a dedicated diagnostic
instrumenting per-request timestamps — to one request among several fired
simultaneously occasionally stalling 5-10x longer than its concurrent
peers, with no client-side connection-pool limit reached and no exception
raised. This is consistent with Groq applying server-side per-key
concurrency throttling under load, though we describe this as evidenced
rather than definitively proven, since the diagnostic run's own severity
varied run-to-run in a way that tracks live server load rather than being a
fixed property of "4 threads."

**Full pipeline, multiprocessing (n=6, 3 repeats):** worse than threading
at every worker count tested (1 process: 4.99s mean; 4 processes: 18.19s
mean) — process-creation and per-process Groq-client setup overhead
dominates a workload this small, and multiprocessing brings no benefit for
I/O-bound work the way threading's ability to overlap network waits does.

### 4.8 LLM-judge baseline

**`[NOT YET RUN]`** Planned: prompt a separate LLM (different model family
from the report-generation model, per §II's discussion of self-enhancement
bias) to directly judge whether a CVE/ATT&CK citation is grounded and
accurate, and compare its precision/recall/latency against LLMCite's
deterministic pipeline on the same bait sets (§4.3–4.4). This is required to
turn "a deterministic pipeline should outperform an LLM judge on this task"
from a design assumption into a measured result.

### 4.9 SelfCheckGPT comparison

**`[NOT YET RUN]`** Planned: run SelfCheckGPT-style multi-sample consistency
checking against the same claim set, to empirically characterize the
self-consistency-vs-external-grounding contrast discussed in §II rather
than only arguing it architecturally.

### 4.10 Significance testing on the CVE/ATT&CK grounding comparison

**`[NOT YET RUN, BLOCKED ON §4.3/§4.8/§4.9]`** Once the CVE-bait set is
re-run and expanded (§4.3) and the LLM-judge/SelfCheckGPT baselines exist
(§4.8–4.9), the same McNemar approach used in §4.2 will be applied to that
comparison before any recall/precision difference between LLMCite and the
baselines is cited as a real effect.

---

## V. Discussion

**What REAL_AND_PLAUSIBLE means for trust.** The central practical argument
of this paper is that a citation which is real and topically plausible is
the *hardest* case for a human reviewer to catch, not the easiest — it looks
correct. §3.5's classification taxonomy and its unconditional review-flag
policy exist specifically because an earlier version of this pipeline got
this wrong (treating REAL_AND_PLAUSIBLE as self-evidently safe), and the
fix is documented as a deliberate correction, not presented as though the
pipeline always worked this way.

**What the CVE-pool finding (§4.5) means.** The 0%-fabrication /
0%-spontaneous-citation result is genuinely two findings, not one: the
pipeline's grounding check is not the reason the model stays silent (there
is nothing to ground-check if nothing is cited) — the model itself,
independent of any guardrail, does not volunteer technical identifiers it
wasn't given. This is safe behavior, but it also means the current system
architecturally cannot help an analyst who needs a CVE *identified* from
symptoms, only one *verified* once cited. We name this explicitly as the
boundary of the current contribution rather than implying broader coverage
than what was tested.

**Limitations, stated plainly:**
- Multiple evaluation components (§4.8, §4.9, §4.10) are not yet built —
  this draft is explicit about that rather than presenting an incomplete
  evaluation as complete.
- The CVE-bait result (§4.3) is now current and at n=100 gives a
  legitimately citable 95% CI ([0.6%, 7.0%]), but both observed ungrounded
  citations occurred on the same two extremely famous vulnerabilities
  (Log4Shell, Follina) — the 75 newly added, less-famous CVEs produced
  zero citations to analyze. The honest claim is "rarely induces
  spontaneous citation, catches it correctly when it does happen on
  famous cases," not "stress-tested against obscure-CVE hallucination."
- Latency figures (§4.2, §4.7) are single-run and demonstrably variable
  run-to-run on shared, uncontrolled hardware; only order-of-magnitude
  comparisons should be drawn from them until repeated-trial benchmarking
  is complete.
- The Wazuh live-data validation (§4.6) is n=13 from a single manual
  session — a real-world sanity check, not a statistically powered claim.
- The ATT&CK verification path relies on a periodically refreshed local
  snapshot rather than a live per-ID lookup (no such endpoint exists
  publicly), which can lag MITRE's published data between refreshes — a
  disclosed asymmetry with the CVE path's live NVD lookups, not treated as
  equivalent.
- CICIDS2017, used for realistic benign-traffic text in §4.2, has been
  independently flagged (by this project's own supervisor, corroborated
  against Goldschmidt & Chudá's 2025 survey [16])
  as no longer representative of *current attack patterns*. We used it here
  only for its `BENIGN`-labeled rows, as generic non-injection text to
  measure false-positive behavior — a different and, we argue, still valid
  use — while relying on the live Wazuh integration (§4.6) for any claim
  about current, real attack data. This distinction is stated explicitly so
  it is not mistaken for an oversight.
- T3 (PII leakage) remains entirely unaddressed in the implemented
  pipeline, despite being a named threat and a committed evaluation metric
  ("PII leakage rate") in the original project proposal. This is disclosed
  as an open gap, not silently dropped from the paper's scope.
- The report-generation backend is a single small model
  (`llama-3.1-8b-instant` via Groq); generalization to larger or
  differently-trained models is untested.

**Threats to validity.** The input-guardrail comparison (§4.2) uses a
dataset partly adapted from public sources rather than fully independent
attacker data, which could inflate apparent recall if those sources overlap
with data the compared tools were themselves validated against — provenance
is tracked per-sample specifically so this can be audited. The CVE-bait set
(§4.3, n=100) now supports a legitimate confidence interval on the
ungrounded rate, but the vulnerability *selection* is not a random sample
of all CVEs — it's biased toward well-documented, high-profile, actively
exploited vulnerabilities (25 individually chosen for fame, 75 drawn from
CISA's KEV catalog, which itself only lists confirmed actively-exploited
vulnerabilities). This is deliberate — an obscure CVE with no public
writeup isn't a meaningful test of spontaneous citation either way — but
it means the estimated rate should not be read as generalizing to
citation behavior on arbitrary, less-documented CVEs. The ATT&CK-bait set
(§4.4) remains hand-authored at small scale (n=6); only qualitative claims
are drawn from it.

---

## VI. Conclusion

We presented LLMCite, a domain-specialized citation-grounding verification
pipeline for LLM-generated SOC reports, built around a four-class outcome
taxonomy rather than a binary flagged/not-flagged label. We showed this
taxonomy and its underlying grounding pattern generalize across two
distinct claim types (CVE identifiers via live NVD lookup, MITRE ATT&CK
techniques via a local STIX snapshot), and evaluated the pipeline across
adversarial bait tests, an independent third-party incident generator, a
CVE pool isolating identification from verification, live SIEM data
including a genuinely detected attack, and a statistically tested
comparison of the pipeline's input-guardrail layer against maintained
open-source alternatives. We were explicit throughout about what remains
unproven: an LLM-judge baseline and a SelfCheckGPT comparison are not yet
built, one adversarial result needs re-verification against a bug fix made
after it was recorded, and a named threat (PII leakage) has no
implementation yet. **`[Final headline result and closing sentence to be
written once §4.8–§4.10 land — see Draft status at the top of this
document.]`**

---

## References

*(Numbered per the target venue's Math and Physical Sciences Numbered
reference style, matching `docs/paper/sn-bibliography.bib`. Full BibTeX
entries with URLs/DOIs live there; this list is for draft readability.)*

1. Zhan, Q., Liang, Z., Ying, Z., Kang, D. InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents. Findings of ACL, 2024.
2. Manakul, P., Liusie, A., Gales, M. SelfCheckGPT: Zero-Resource Black-Box Hallucination Detection for Generative Large Language Models. EMNLP, 2023.
3. MITRE Engenuity Center for Threat-Informed Defense. TRAM: Threat Report ATT&CK Mapper. v1 2021, LLM-based update 2023.
4. Rebedea, T., Dinu, R., et al. NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails. NVIDIA, 2023.
5. Microsoft. Presidio: An Open-Source Framework for Detecting, Redacting, Masking, and Anonymizing Sensitive Data (PII). GitHub, ongoing.
6. Min, S., Krishna, K., Lyu, X., Lewis, M., Yih, W., Koh, P.W., Iyyer, M., Zettlemoyer, L., Hajishirzi, H. FActScore: Fine-grained Atomic Evaluation of Factual Precision in Long Form Text Generation. EMNLP, 2023.
7. Wallace, E., Xiao, K., Leike, R., Weng, L., Heidecke, J., Beutel, A. The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions. arXiv (OpenAI), 2024.
8. Zheng, L., Chiang, W., Sheng, Y., et al. Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena. NeurIPS Datasets and Benchmarks Track, 2023.
9. Huang, L. et al. A Survey on Hallucination in Large Language Models: Principles, Taxonomy, Challenges, and Open Questions. arXiv, 2024.
10. [MDPI Authors — **placeholder, needs citation spot-check per `docs/ROADMAP_PLAN.md` §9**]. AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation. MDPI, 2025.
11. Shen, X., Chen, Z., Backes, M., Shen, Y., Zhang, Y. "Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models. ACM CCS, 2024.
12. deepset. prompt-injections dataset. Hugging Face, Apache-2.0, 2023.
13. Protect AI. LLM Guard. GitHub, ongoing.
14. Pytector. GitHub, ongoing.
15. Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP, 2018, pp. 108–116.
16. Goldschmidt, P., Chudá, D. Network Intrusion Datasets: A Survey, Limitations, and Recommendations. Computers & Security, 2025. DOI: 10.1016/j.cose.2025.104510.
17. MITRE ATT&CK. attack.mitre.org, ongoing.
18. NIST. National Vulnerability Database. nvd.nist.gov, ongoing.
19. Wazuh. Open Source SIEM/XDR. wazuh.com, ongoing.
20. Groq. LPU Inference Engine. groq.com, ongoing.
21. Secure_SOC_AI. engranaabubakar/Secure_SOC_AI. GitHub, ongoing.
22. LangChain-AI. LangGraph. GitHub, ongoing.

**Note on reference #10:** the author field is a placeholder inherited from
the literature review — this citation needs to be verified against the
actual MDPI listing (real author names, exact page/article number) before
this draft is submission-ready. Tracked in `docs/ROADMAP_PLAN.md` §9
("Overleaf porting + citation spot-check").

---

## Appendix: mapping this draft back to the codebase

For a reviewer or collaborator who wants to verify any claim above against
the actual implementation:

| Section | Code / data |
|---|---|
| §3.2 Input guardrail | `src/guardrails/input_guardrail.py` |
| §3.3 Evidence Pack | `src/guardrails/evidence_pack.py` |
| §3.4–3.5 Output guardrail, CVE path | `src/guardrails/output_guardrail.py` |
| §3.4–3.5 Output guardrail, ATT&CK path | `src/guardrails/attack_grounding.py` |
| Shared grounding logic | `src/guardrails/grounding_utils.py` |
| §4.2 Input guardrail comparison | `experiments/evaluation/guardrail_comparison/` |
| §4.3 CVE-bait test | `experiments/evaluation/cve_bait_alerts.py`, `experiments/results/cve_bait_results.json` |
| §4.4 ATT&CK-bait test | `experiments/evaluation/attack_bait_alerts.py`, `experiments/results/attack_bait_results.json` |
| §4.5 Secure_SOC_AI + CVE pool | `experiments/evaluation/soc_integration_test.py`, `experiments/evaluation/soc_integration/cve_pool.py`, `docs/INTEGRATION_PLAN.md` |
| §4.6 Wazuh live validation | `experiments/evaluation/wazuh_integration_test.py` |
| §4.7 Performance benchmarks | `experiments/evaluation/threading_benchmark.py`, `experiments/evaluation/multiprocessing_benchmark.py`, `experiments/evaluation/diagnose_thread_slowdown.py` |
| Full chronological experiment log | `docs/all_results.md` |
| Live priority-ordered task list | `docs/ROADMAP_PLAN.md` |
