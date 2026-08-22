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
> - LLM-judge baseline (Sect. 3 item 5) — ✅ done 2026-08-20, full 318-sample run
>   spanning an easy and a harder construct-validity tier: 100%
>   accuracy/precision/recall on every slice (Sect. 4.8). Uses the same model
>   family for judge and report generation, not an independently-recommended
>   different one — a disclosed limitation, not a silent one (Sects. 2, 4.8 and 5).
> - SelfCheckGPT comparison (Sect. 3 item 8) — ✅ done 2026-08-21, full
>   60-alert run against the same CVE pool as Sect. 4.5. Headline: it never
>   false-flags the grounded class (precision 1.0) but misses most of the
>   ungrounded class (recall 0.31) — and 18 of those 20 misses are the
>   model *consistently citing the correct real CVE* from training
>   knowledge, not a fabrication, which a consistency-only signal cannot
>   tell apart from genuine grounding (Sect. 4.9).
> - CVE-bait test set expansion (Sect. 3 item 7) — ✅ done 2026-08-12, expanded in
>   two passes (6 → 25 → 100 real, verified CVEs, Sect. 4.3). The old n=6 result
>   predated two bug fixes and has been fully superseded. The blended n=100
>   ungrounded rate is 2.0% (95% CI [0.6%, 7.0%]), but this conflates two
>   conditions: 0/97 alerts that never mention a CVE produced a spontaneous
>   citation (95% CI [0.0%, 3.8%]); both flagged hits came from 3 alerts
>   that explicitly ask for a citation, where the model was right once and
>   wrong-but-plausible once. See Sect. 4.3 for the full breakdown.
> - Significance testing on the CVE-bait comparison — still open; only 2
>   ungrounded citations occurred even at n=100 (both on the same famous
>   vulnerabilities found at n=25), which still isn't enough discordant
>   data for McNemar-style testing against a future baseline to be
>   meaningful (Sect. 8)
> - Presidio / PII redaction (T3 in the threat model) — ✅ built and
>   bait-tested 2026-08-18 (Sects. 3.6 and 4.11). n=6 positive cases (small, a first
>   real signal rather than a citable rate): 1/6 detected, 0/8 false
>   positives on clean alerts, 0 residual PII after redaction.
> - Repeated-trial latency benchmarking (current numbers are single-run and
>   flagged as such in Sect. 4.7)
> - Relevance classifier validation (Sect. 3.4 Stage 2) — ✅ done 2026-08-22
>   (Sect. 4.12): 92.5% accuracy against human judgment (n=80, 95% CI
>   [84.6%, 96.5%]), errors clustered tightly at the 0.15 decision
>   threshold rather than spread randomly. Labels are AI-suggested,
>   human-confirmed (with a blind re-check on the hardest cases), not
>   independently annotated from scratch — disclosed as such in Sect. 4.12 and 5.
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

*(target: 250 words; current draft: ~317, over budget. Restructured
2026-08-20 around one central research question per external review
feedback, rather than an itemized tour of every experiment; Sect. 4.9's
result folded in 2026-08-21. Still needs a dedicated trim pass — not done
here since that risks cutting precision, not just length, in a single
pass alongside a content change.)*

Large language models increasingly generate Security Operations Center
(SOC) threat reports, citing supporting evidence such as CVE identifiers
and MITRE ATT&CK techniques. These citations are rarely verified: models
can fabricate identifiers, misattribute real ones, or recall citations
the alert never provided — and a flat "flagged/not flagged" treatment
cannot distinguish an invented CVE from a real-but-unevidenced one,
though the two carry different risk profiles for an analyst deciding how
much to trust a report.

We ask whether such reports can be automatically checked for citations
unsupported by the evidence a model was given, and whether distinguishing
*why* a citation is unsupported — fabricated, real but irrelevant, or
real and plausible enough to look correct — provides assurance a binary
flag cannot. LLMCite answers this with a two-stage pipeline: grounding
against the source alert, then verification of ungrounded citations
against authoritative sources (NVD, the MITRE ATT&CK STIX corpus) into a
four-class taxonomy. The Real-and-Plausible class is the central
finding — a real, topically appropriate citation never actually stated in
the evidence is, by construction, the case most likely to evade naive
human review, precisely because it looks correct.

We evaluate across adversarial, third-party-generated, and live SOC data,
and separately benchmark a statistically tested input guardrail against
two open-source alternatives (McNemar's test, n=119). A same-model-family
LLM-judge baseline reproduces the pipeline's binary decision on a
controlled calibration set (n=318, 100% accuracy) — a feasibility floor,
not a bias-controlled result, since judge and generator share a model
family. A SelfCheckGPT-style consistency baseline (n=60, recall 0.31,
precision 1.0) misses most ungrounded citations — not through
inconsistent fabrication, but because 18 of 20 misses are the model
consistently recalling a correct, real identifier from training
knowledge, the same Real-and-Plausible pattern this paper centers, at far
higher volume than the pipeline's own low-temperature tests observed.
LLMCite is a domain-specialized
instance of citation-grounding verification for security-critical LLM
applications, distinct from prior work targeting scholarly references.

---

## 1 Introduction

Large language models (LLMs) are being adopted in Security Operations Centres
(SOCs) to automate alert triage, enrich threat intelligence, and generate
analyst-facing reports. This promises real efficiency gains, but it
introduces a specific, under-examined risk: when a model cites a CVE
identifier or a MITRE ATT&CK technique as supporting evidence for its
assessment, nothing in a typical deployment checks whether that citation is
real, relevant, or actually present in the alert the model was given.

This is not a hypothetical concern. Across our own adversarial testing
(Sect. 4), models given ambiguous or withheld-identifier prompts either stay
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
   types (100 CVE identifiers, 50 MITRE ATT&CK techniques), a 76-incident
   run through an independent third-party incident generator, a 60-alert
   CVE pool isolating whether the model can identify a CVE from behavior
   alone versus merely verify one it is given, 26 real alerts across four
   distinct trigger types from a live Wazuh SIEM deployment including a
   genuinely detected brute-force attack, an LLM-judge baseline showing
   full agreement with the deterministic pipeline across an easy and a
   harder construct-validity tier, a SelfCheckGPT self-consistency
   baseline showing the two approaches catch different, non-overlapping
   failure modes rather than one strictly dominating the other, a human
   validation of the relevance classifier underlying the taxonomy split
   (92.5% accuracy), and a bait test of a fourth guardrail addressing PII
   leakage — plus a statistically tested comparison of the pipeline's
   input-guardrail layer against two maintained open-source alternatives.

The remainder of this paper is organized as follows: Sect. 2 reviews related
work; Sect. 3 describes the pipeline architecture and taxonomy; Sect. 4 presents
the evaluation; Sect. 5 discusses what the results do and do not establish,
including explicit limitations; Sect. 6 concludes.

---

## 2 Related Work

**Hallucination detection and grounding.** SelfCheckGPT [2]
detects likely-hallucinated sentences by sampling multiple stochastic
responses to the same prompt and measuring consistency between them, without
requiring an external knowledge source. This is a fundamentally different
signal from what LLMCite measures: SelfCheckGPT asks "is the model
consistent about this claim," while LLMCite asks "is this claim actually
true, checked against an authoritative record." The two are complementary,
not competing, and Sect. 4.9's direct comparison makes this empirical
rather than only architectural: consistency is an accurate signal for the
grounded class, but blind to a specific failure mode — a real, correct
identifier recalled from training knowledge and repeated identically
across resamples, which is self-consistent by definition even though it
never appears in the evidence the model was actually given. FActScore
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
family. Sect. 4.8 reports an LLM-judge baseline against the same CVE/ATT&CK
citation task LLMCite's deterministic pipeline evaluates, using
`openai/gpt-oss-20b` — the same model used for report generation, not a
different family — as the judge. This is a disclosed deviation from Zheng
et al.'s own recommendation to use a different model family to control for
self-enhancement bias: a second, independently-hosted model family was not
available within this project's Groq free-tier setup. The result (Sect. 4.8)
should be read with that same-family caveat, not as a bias-controlled
comparison.

**Prompt injection and guardrail frameworks.** InjecAgent
[1] establishes the threat model this paper's input-guardrail
layer defends against — instructions hidden inside tool/log output that a
downstream agent processes as legitimate input, rather than instructions
from a trusted user. NeMo Guardrails [4] was evaluated
directly early in this project as a candidate input-guardrail framework; its
LLM-based Colang intent classification proved unreliable for injection
detection when run against a small local model, motivating a switch to
deterministic pattern matching as the first layer of this paper's own
guardrail (Sect. 3). The Instruction Hierarchy [7]
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

**PII protection.** Presidio [5] implements this project's third threat
category (PII leakage in generated reports, T3): Sect. 3.6 describes the
guardrail architecture, Sect. 4.11 its bait-test result. Unlike the CVE/ATT&CK
grounding checks (Sect. 3.4), T3 is a redaction problem, not a
citation-verification one — the concern is whether sensitive data present
in the raw alert survives unredacted into generated text, independent of
whether any accompanying citation is itself grounded.

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

## 3 Proposed Method

### 3.1 Threat model

| # | Attack type | Description | Guardrail layer |
|---|---|---|---|
| T1 | Direct prompt injection | Alert/user input contains instruction-override phrases ("ignore previous instructions") attempting to hijack agent behavior | Input |
| T2 | Indirect prompt injection | Adversarial instructions embedded inside ingested alert/log data, processed as part of normal triage | Input |
| T3 | PII leakage | Sensitive data in raw alerts (names, IPs, emails, SSNs) surfaces unredacted in the generated report | Output |
| T4 | Hallucinated citation | Agent fabricates or misattributes a CVE ID or ATT&CK technique not grounded in the source alert | Output |

T1/T2 are addressed by the input guardrail (Sect. 3.2); T4 is the paper's
headline contribution (Sects. 3.3–3.4); T3 is addressed by a dedicated redaction
guardrail (Sect. 3.6), bait-tested in Sect. 4.11 — a named threat in the original
proposal, with "PII leakage rate" a committed evaluation metric, now
implemented rather than only scoped in.

### 3.2 Input guardrail layer

The input guardrail runs deterministic substring matching against a fixed
list of known injection phrases first (near-zero latency). Text that passes
this check falls back to Pytector, a local DeBERTa-based prompt-injection
classifier, so that paraphrased or novel-strategy injection attempts not
covered by the deterministic list still have a second chance to be caught.
This ordering matters for both latency (most legitimate traffic never needs
the model call) and coverage (the deterministic layer alone has a
significant recall gap — quantified in Sect. 4.2).

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
authoritative record's own description determines relevance (validated
against human judgment in Sect. 4.12).

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

### 3.6 PII redaction guardrail

Addressing T3, `src/guardrails/pii_guardrail.py` runs Presidio's analyzer
together with spaCy's `en_core_web_sm` NER model over the generated
report's text fields (`threat_summary`, `recommended_action`, `reasoning`),
detecting PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, and CREDIT_CARD
entities and redacting each to a typed placeholder (e.g. `<PERSON>`) via
Presidio's anonymizer. This runs entirely locally, with no additional
hosted-API call beyond the report-generation call itself. Its result is
OR'd into the same `output_guardrail_flagged`/`requires_review` signals the
grounding checks (Sect. 3.4) set, rather than treated as a separate output
channel a reviewer would need to check independently. IP_ADDRESS is
deliberately excluded from the default entity set: the Evidence Pack (Sect. 3.3)
already treats source/destination IPs as operational security telemetry an
analyst needs to act on, not personal data to hide by default — redacting
it would break the report's usefulness for the overwhelming majority of
alerts, which all carry IPs.

---

## 4 Evaluation

### 4.1 Experimental setup

Report generation uses Groq's hosted inference (`openai/gpt-oss-20b`) as
the LLM backend throughout — migrated from an earlier `llama-3.1-8b-instant`
baseline; Sects. 4.8 and 4.11 below use this current model. All guardrail
components (deterministic
matching, Pytector, LLM Guard, NVD/ATT&CK verification) run locally with no
sensitive alert data sent to any hosted API beyond the report-generation
call itself. The input-guardrail comparison (Sect. 4.2) additionally reports
package versions and environment details alongside its results file
(`experiments/results/guardrail_comparison.json`) for reproducibility. The
project's core test suite currently stands at **139 passing / 1 failing**
(the one failure is a pre-existing async-fixture issue in an abandoned,
unrelated NeMo Guardrails experiment kept for historical record — not part
of the shipped pipeline), verified directly against the repository at the
time of writing.

**Reproducibility metadata.** The MITRE ATT&CK verification path (Sect. 3.4)
uses a local snapshot of the Enterprise STIX bundle
(`data/mitre_attack/enterprise_attack_techniques.json`), fetched from
MITRE's official `attack-stix-data` GitHub repository on 2026-08-04,
containing 858 techniques (SHA-256:
`3655344c1b3428392994a947cb13b04b2236a6818b9ce9e35084db98b4fbd08f`). Unlike
the ATT&CK path, the CVE verification path (Sect. 3.4) queries NVD's public
API live, per citation, at experiment run time rather than against a fixed
snapshot — each results file in `experiments/results/` carries the run
timestamp its own citations were checked against, so a citation verified as
FABRICATED or REAL_AND_PLAUSIBLE reflects NVD's state at that specific time,
not a fixed point shared across every result in this paper. This asymmetry
(one path versioned and reproducible, the other live and time-varying) is a
disclosed property of the two authoritative sources' own APIs, not a
methodological inconsistency introduced by this pipeline — restated in
Sect. 5's limitations.

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
independent draws).** All 6 pairwise comparisons this project runs share
overlapping implementations (`hybrid` appears in 4 of the 6), so testing
each at raw α=0.05 independently inflates the family-wise false-positive
rate well above 5%. Both raw and Holm-Bonferroni-corrected p-values are
reported for that reason — a correction not applied in earlier drafts of
this evaluation, and one that changes which results can actually be called
significant:

| Comparison | Raw p-value | Sig. (raw α=0.05)? | Holm-Bonferroni p-value | Sig. (corrected)? |
|---|---|---|---|---|
| Baseline vs. Hybrid | <0.001 | **Yes** | <0.001 | **Yes** |
| Hybrid vs. LLM Guard | 0.049 | Yes | 0.196 | **No** |
| Hybrid vs. Pytector | 0.250 | No | 0.500 | No |
| Hybrid+LLM-Guard-fallback vs. Hybrid | 0.049 | Yes | 0.196 | **No** |
| Hybrid+LLM-Guard-fallback vs. LLM Guard | 1.000 | No | 1.000 | No |
| Hybrid+LLM-Guard-fallback vs. Pytector | 0.012 | Yes | 0.059 | **No** |

**Only one of the six comparisons survives correction: hybrid beats the
naive deterministic-only baseline, which is the core safety claim this
guardrail layer depends on.** The other three raw-significant results —
hybrid vs. LLM Guard, and both comparisons involving the LLM-Guard-fallback
variant against hybrid and Pytector — were each sitting close to the raw
α=0.05 line (p between 0.012 and 0.049) and do not survive being tested
alongside five other comparisons on overlapping data. We do not claim these
as proven effects; the raw recall numbers (Table above) still show LLM
Guard numerically ahead, but "numerically ahead" and "statistically
distinguishable from chance once the multiple-comparisons problem is
accounted for" are different claims, and only the pipeline's actual
headline result (hybrid beats the naive baseline) is the latter.

**A follow-up trial and a methodology correction.** LLM Guard's raw recall
advantage over hybrid (0.943 vs. 0.736) was large enough to motivate
testing whether substituting it for Pytector as the hybrid's fallback
classifier would help — not, per the corrected results above, a proven
effect on its own, but still worth the (cheap) experiment. The result was a
**degenerate McNemar test — zero discordant predictions against plain LLM
Guard across all 119 samples** — meaning the two are identical, sample for
sample. The deterministic pre-filter adds value only when the model it
protects has meaningful blind spots (true for Pytector); against a
classifier already near ceiling recall, it adds a redundant fast path and
nothing else. While building this trial we also found that LLM Guard's and
Pytector's originally reported latency figures were inflated by a one-time
model-loading cost counted against their first-ever call (confirmed: the
extreme outlier in each case was always the first sample processed). This
is corrected via an explicit warmup step before timing in the current
benchmark; **we flag as an open limitation that single-run latency figures
on shared, uncontrolled hardware still vary by a similar ratio (~2.6×)
between separate runs of the identical code**, and do not present exact
millisecond figures as more than an order-of-magnitude comparison until
repeated-trial benchmarking (mean ± spread across multiple isolated runs)
is completed.

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
alerts (2.0%) produced an ungrounded CVE citation, both flagged for review
(2.0% — identical to the ungrounded rate, confirming the unconditional
`requires_review` fix is active). **This blended 2.0% figure should not be
reported on its own — it conflates two different test conditions that need
to be reported separately.** 97 of the 100 alerts never mention a CVE at
all (the pure spontaneous-citation condition); **0/97 of these produced an
ungrounded citation**, a 95% Wilson interval of **[0.0%, 3.8%]**. The
remaining 3 alerts (`BAIT-002`, `BAIT-011`, `BAIT-017`) explicitly ask the
model to cite a CVE identifier it was not given — a deliberate second test
condition, not the paper's main methodology — and both ungrounded hits
come from this subset of 3 (`BAIT-011` produced no citation and was not
flagged). So the precise claim is: **the model never spontaneously
volunteered a CVE number across 97 symptom-only alerts; when directly
asked to name one it wasn't given, it did so 2 of 3 times**, once
correctly and once with a real-but-wrong neighbor (detailed below). The
95% Wilson interval on the original blended 2/100 figure, [0.6%, 7.0%],
remains reported below for continuity with the n=25 comparison, but the
0/97 figure is the methodologically correct headline number for
"spontaneous CVE hallucination rate."

**The two ungrounded citations are the same two found at n=25** — no
citation occurred on any of the 75 newly added, CISA-KEV-sourced alerts,
none of which include an explicit citation request either, consistent
with the 0/97 finding above. Of the 2:

- The Log4Shell alert (`BAIT-002`, an explicit citation request) correctly
  produced `CVE-2021-44228`, classified `REAL_AND_PLAUSIBLE` — and,
  correctly per the current taxonomy policy, still flagged for review
  despite being accurate, since the alert text itself never stated the
  number. This flag is a policy artifact, not an error: the guardrail's
  rule is mechanical (present in the input evidence or not), and does not
  give credit for being independently correct.
- The Follina alert (`BAIT-017`, also an explicit citation request)
  produced `CVE-2022-34713` instead of the correct `CVE-2022-30190` —
  classified `REAL_BUT_IRRELEVANT`. This is not a fabrication:
  `CVE-2022-34713` ("DogWalk") is a real, separate Microsoft MSDT
  vulnerability disclosed the same year as Follina, patched around the
  same time. **This is a concrete, real instance of exactly the risk this
  paper's introduction describes** — a model citing a real identifier,
  confused with a closely related one, in a way indistinguishable from a
  correct citation without independent verification. It is also the only
  one of the 100 alerts where the model's citation was actually *wrong*,
  rather than correct-but-mechanically-flagged.

At n=100, this is now a genuinely citable estimate rather than a
qualitative-only demonstration, though the concentration finding above
means the honest framing is "the pipeline never spontaneously hallucinates
a CVE across 97 varied symptom-only alerts, and when directly pressed for
an identifier it wasn't given, it is right more often than wrong, with its
one error being a plausible neighbor rather than an invention" — not "the
pipeline has been stress-tested against obscure-vulnerability
hallucination," since the 75 newly added alerts
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
robustness (Sects. 4.3–4.4 cover that).

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
glossed over as a limitation with no concrete next step. **This finding
holds at this experiment's temperature=0.1; Sect. 4.9 finds the opposite
behavior at temperature=0.7 on the same style of alert** — worth reading
together, not in isolation.

### 4.6 Live integration demonstration: real Wazuh SIEM data

To demonstrate the pipeline against genuinely live, non-synthetic alert
data rather than only CICIDS2017 (flagged elsewhere in this project's own
records as outdated for claiming *current attack-pattern* coverage — see
Sect. 5), a local Wazuh SIEM/XDR stack was deployed via Docker Compose with
a real registered agent. Real triggering activity was generated across four
distinct trigger types, not just passively observed: File Integrity
Monitoring alerts from an actual file write to a monitored path; a genuine
SSH brute-force attempt (repeated failed logins against a throwaway local
account) that Wazuh's own correlation engine correctly recognized and
escalated to a dedicated "brute force" rule, not a canned alert; realistic
SQLi/XSS/directory-traversal request lines fed into a monitored access log,
processed by Wazuh's real web-attack ruleset; rootkit-signature file
markers detected by Wazuh's rootcheck module; and sudo/privilege-escalation
syslog activity matched against Wazuh's real sudo ruleset.

**Result:** 26 unique alerts (after deduplication, up from an initial 13
spanning only the first two trigger types) run through the full pipeline:
**0% ungrounded on ATT&CK/CVE across all 26**. Manual inspection of the raw
report JSON confirmed the model's reasoning explicitly engaged with real
MITRE technique IDs present in the alerts (**T1110** — Brute Force, on the
SSH alerts; **T1190** — Exploit Public-Facing Application, on the
web-attack alerts; **T1548.003** — Sudo and Sudo Caching, on the
privilege-escalation alerts) once an adapter bug stripping MITRE tags from
SSH-rule alerts specifically was found and fixed (Wazuh nests MITRE tags
differently for SCA/compliance rules versus SSH rules — the adapter
originally only checked one of the two shapes).

**A genuine finding from this expansion, not from the original n=13:** 5 of
the 26 alerts triggered a PII-guardrail (Sect. 3.6) detection, all of them
false positives — the small NER model misread technical strings (a URL
path, a SQL/shell command fragment, the literal text "ATT&CK", a benchmark
document name) as a `PERSON` entity, all at the same 0.85 confidence score.
Fixed with a plausibility filter rejecting `PERSON` matches containing
characters no real name uses (`/`, `(`, `)`, `&`, digits) — deliberately
not filtering on apostrophes or hyphens, which real names do use. Re-verified
against the same 26 alerts' already-generated report text (no new inference
calls needed): 0/26 after the fix, with zero regression on real-name
detection or the original PII bait-test numbers (Sect. 4.11). This is a
genuine live-data finding CICIDS2017-style synthetic benign traffic would
not have surfaced — the false-positive pattern only appears on realistic
technical/code-shaped log text.

**Honest limitation:** n=26 is still a one-time manual burst of activity
across two sessions, not sustained or repeatable — sufficient to
demonstrate the pipeline handles several real, live-detected attack
patterns correctly (and to surface a real guardrail bug CICIDS2017 could
not have), not sufficient to support a precise statistical claim. The
original SSH result also tests the "stated" condition only (T1110 was
present in the alert Wazuh generated); it does not test whether the model
can spontaneously identify a technique from raw behavior alone without the
label, which Sect. 4.5's CVE-pool finding already suggests the answer to.
A fourth planned trigger type, Wazuh's built-in vulnerability-detector
(which would have produced genuine CVE-tagged alerts from real installed
packages), was attempted but blocked by what appears to be a real
inventory-sync limitation in this single-node Docker deployment — not
resolved, and not counted among the 26.

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

**Method.** A separate judge call — using the same model as report
generation, `openai/gpt-oss-20b`, not a different family — is prompted
directly with an (alert evidence, generated report) pair and asked to
classify the report's CVE/ATT&CK citations as grounded or ungrounded,
without access to the deterministic pipeline's own verdict. This deviates
from Zheng et al.'s [8] recommendation to use a different model family for
judge and generator to control for self-enhancement bias (Sect. 2); a second,
independently-hosted model family was not available within this project's
Groq free-tier setup, so this result is a same-family comparison, not a
bias-controlled one — disclosed here rather than presented as equivalent to
what the literature recommends.

Evaluated on `experiments/evaluation/llm_judge_synthetic_test.py`'s
class-balanced calibration set, built the same way as Sect. 4.3's synthetic
extension: 106 grounded-empty samples (no CVE/ATT&CK identifier present
anywhere in report or evidence), 106 grounded-cited samples (a real
identifier present in *both* evidence and report — the harder,
construct-validity tier added per reviewer feedback on the pipeline's
earlier CVE-bait work), and 106 ungrounded samples (a real-but-foreign
identifier injected into the report only). n=318 total.

**Result** (`experiments/results/llm_judge_synthetic_results.json`): **100%
accuracy, 100% precision, 100% recall** on the full set (TP=106, FP=0,
TN=212, FN=0; 95% Wilson CI [98.8%, 100%] on accuracy), and identically
100%/100%/100% on both the easy pair (grounded-empty vs. ungrounded, n=212)
and the hard pair (grounded-cited vs. ungrounded, n=212) analyzed
separately. Zero parse errors across all 318 calls.

**What this means.** On this calibration task, the LLM judge reproduced the
deterministic pipeline's own ground-truth labels exactly, including on the
harder tier where the distractor identifier is present in both the
evidence and the report. That tier's discriminating signal, though, is
itself close to what the deterministic checker already computes — whether
an identifier-shaped token also appears in the evidence text — so a
capable model matching it is an expected feasibility floor, not evidence
of deeper semantic reasoning; labels this recoverable from the sample
construction should not be read as a strong argument against the
deterministic pipeline being necessary. The more defensible claim: an LLM
judge can reliably reproduce this specific binary grounding decision,
while the deterministic pipeline retains real deployment advantages the
judge does not share — near-zero latency, no per-call cost or rate-limit
exposure (Sect. 4.7), and no dependence on model behavior a hosted API
could change or throttle. This calibration set also tests an injected,
single, isolated foreign citation against otherwise-clean text rather than
the messier range of real model output (subtler misattributions, multiple
citations in one report, partial matches) that Sects. 4.3–4.4's
real-pipeline bait tests also check. The same-model-family caveat above
means this result cannot rule out self-enhancement bias as a contributing
factor — a second model family for the judge remains a concrete piece of
follow-up work, not a completed control.

### 4.9 SelfCheckGPT comparison

**Method.** SelfCheckGPT-style multi-sample consistency checking (3
resamples per alert at temperature=0.7 — the production pipeline's
temperature=0.1, Sect. 4.1, is deliberately near-deterministic and would
give resampling no diversity to measure) against the same 60-alert CVE
pool used in Sect. 4.5 (30 "prompted"/bait, CVE number withheld; 30
"stated", CVE number given). `sample_citations()` deliberately bypasses
the guardrail pipeline — only the raw generator's citation behavior
across resamples is measured, to make the self-consistency-vs-external-
grounding contrast from Sect. 2 empirical rather than only architectural.
Checkpointed after every alert so a Groq daily-quota interruption does
not lose completed work.

**Result** (`experiments/results/selfcheckgpt_results.json`, n=60; 4
alerts excluded where every resample declined to cite anything at all —
nothing to score consistency on, 3 from the stated class, 1 from
prompted):

| Class | n scored | SelfCheckGPT correct |
|---|---|---|
| Stated (grounded) | 27 (3 declined) | 27/27 |
| Prompted (bait, withheld) | 29 (1 declined) | 9/29 (recall 0.31) |

Overall on the 56 scored alerts: accuracy 0.643 (95% CI [0.512, 0.755]),
precision 1.0 (95% CI [0.701, 1.0]), recall 0.310 (95% CI [0.173,
0.492]). SelfCheckGPT never false-flags a grounded citation as unstable,
matching Sect. 4.5's "100% correctly reflected when given" finding for
the stated class.

**The 20 missed prompted-class alerts are not what a bare recall number
suggests.** All 20 are cases where the model cited the *same* CVE across
all 3 resamples — perfectly self-consistent, so SelfCheckGPT correctly
reports no instability. But checking each majority citation against the
alert's actual ground-truth CVE shows **18 of the 20 are the correct
identifier** — the model consistently recalled the real CVE for the
described exploit behavior from its own training knowledge, even though
that identifier was withheld from the prompt and never appears in the
alert's evidence. Only 2 of 20 are genuine misattributions, both citing
CVE-2021-31207 (a real Microsoft Exchange Server vulnerability from the
same 2021 ProxyShell disclosure cluster) in place of the two other
Exchange Server CVEs from that cluster that were the alerts' actual
ground truth (CVE-2021-34473, CVE-2021-26855).

**What this means.** This is a sharper version of the blind spot this
module's own design anticipated: SelfCheckGPT cannot distinguish
"consistently grounded" from "consistently correct but ungrounded,"
because both look identical to a consistency-only signal. Eighteen of
these twenty cases are, functionally, Real-and-Plausible citations
(Sect. 3.5) at a volume this project's low-temperature (0.1) bait tests
(Sects. 4.3, 4.5) never observed — those tests recorded exactly one such
case (Sect. 4.3's Log4Shell alert) across their combined n=106. Raising
the sampling temperature to the level SelfCheckGPT requires makes the
model volunteer a withheld-but-correct identifier far more often than
production settings do — a real, previously-undocumented boundary
condition on Sect. 4.5's "never volunteers when withheld" finding, which
should be read as holding at temperature=0.1 specifically, not as a
general property of the model, now that this section's data contradicts
it at temperature=0.7. The deterministic grounding checker still
correctly flags every one of these 20 as ungrounded, since groundedness
is about evidence presence, not real-world correctness — exactly the
distinction Sect. 5's central argument is built on. The two remaining
misattribution cases are a smaller-scale echo of Sect. 4.3's
Follina/DogWalk finding: a real identifier from the right cluster, but
the wrong specific one.

### 4.10 Significance testing on the CVE/ATT&CK grounding comparison

Sect. 4.3 (CVE-bait), Sect. 4.8 (LLM-judge), and Sect. 4.9 (SelfCheckGPT)
are all now complete, but a paired McNemar test between the deterministic
pipeline and SelfCheckGPT specifically is **not run here**, for a reason
worth stating rather than glossing over: Sect. 4.9's method
(`sample_citations()`) deliberately bypasses the guardrail pipeline, so
the deterministic checker's actual verdict was never computed on these
same 60 alerts — only the bait/stated construction's ground-truth label
was. Treating that label as a stand-in for "what the deterministic
checker would have said" would make the comparison tautological (the
label is definitionally what the deterministic checker computes on
grounded input), not a real empirical test. A meaningful paired
comparison would require re-running the actual deterministic checker on
fresh reports generated under the same temperature=0.7 sampling used in
Sect. 4.9 — the raw report text was not persisted (only the extracted
citation IDs were, Sect. 4.9), so this needs a new run rather than a
re-analysis of already-collected data. Not yet done.

Sect. 4.8's LLM-judge result showed zero disagreement with the
deterministic pipeline on its calibration set (100% both ways), which —
like Sect. 4.2's degenerate LLM-Guard-vs-hybrid trial — would itself
produce a degenerate, zero-discordant-pair McNemar test rather than a
meaningful p-value. Not run, for that reason, rather than reported as a
significant difference where none exists.

### 4.11 PII redaction guardrail — bait test (Threat T3)

**Method.** Unlike Sects. 4.3–4.4's grounding checks, T3 is a *redaction*
threat: does the model's generated report echo sensitive data present in
the raw alert, independent of whether any citation involved is "grounded."
The guardrail (Sect. 3.6) is built on Presidio [5] and spaCy's `en_core_web_sm`
for NER, running entirely locally with no additional hosted-API call beyond
the report-generation call itself.

`experiments/evaluation/pii_bait_alerts.py` built 6 alerts with synthetic
PII embedded in realistic raw evidence (DLP exfiltration, phishing
credential harvest, payment-data exposure, vishing report, database dump)
plus 8 clean alerts with zero personal data, as a false-positive regression
check. Each is run through the full guardrailed pipeline (real Groq calls),
checking both whether the model echoed something the guardrail then
caught, and whether anything survives an independent re-scan of the
already-redacted final text (residual PII — should always be zero).

**Result** (`experiments/results/pii_bait_results.json`, n=14): **1/6 PII
alerts had a detection (16.7%), 0/8 false positives on clean alerts, 0
residual PII after redaction.** Manual inspection of the 5 "nothing
detected" cases found the model (`openai/gpt-oss-20b`) consistently
summarized the presence of PII *abstractly* rather than quoting raw
values — e.g. for one alert with an SSN, email, and name in the raw
payload, the generated summary described "a CSV row with sensitive
employee PII (name, email, SSN)" without repeating any actual value. The
one detection is the reverse case: the model wrote out a real name
directly, and the guardrail caught and redacted it to `<PERSON>`.

**What this means.** Two distinct findings, not one. First, the
report-generation model's own summarization behavior is itself a
meaningful mitigation for T3 — most of the time it does not quote raw
sensitive values verbatim even when they are present in the evidence it
was given, similar in spirit to Sect. 4.5's finding that the model does not
volunteer identifiers it was not explicitly given. Second, on the one case
where it did quote a real value, the guardrail worked exactly as designed
end to end: detection, redaction, zero residual PII, zero false positives
elsewhere. n=6 positive cases is small — a first real signal that the
guardrail and its interaction with the model's own behavior both function
correctly, not yet a citable rate; a synthetic calibration set in the same
spirit as Sect. 4.3's CVE-bait extension (Sect. 4.8) would be the natural way to get
a statistically defensible number here if the paper's timeline allows it.

### 4.12 Relevance classifier validation

**Method.** The REAL_AND_PLAUSIBLE / REAL_BUT_IRRELEVANT split (Sect. 3.5)
rests entirely on Sect. 3.4's Stage 2 relevance score — a deterministic,
stemmed bag-of-words overlap between the alert's evidence text and the
authoritative record's description, thresholded at 0.15. That heuristic
had never been checked against independent judgment before this
evaluation; centering REAL_AND_PLAUSIBLE as the paper's main novelty
argument makes an unvalidated heuristic behind it a materially larger
liability than it would otherwise be.

80 (alert, candidate CVE) pairs were built from the CVE-bait alert set
(Sect. 4.3): 40 anchor alerts, each paired once with its own real,
correct CVE and once with a different real CVE drawn from the same pool
by a fixed index shift, giving a mix of clearly-matching and
mostly-unrelated pairs by construction. Real NVD descriptions were
fetched live for all 80 candidate CVEs — the same text Sect. 3.4's Stage
2 actually scores, not a paraphrase. Each pair was independently labeled
relevant/not-relevant by a human rater, blind to which CVE the
construction intended as the "correct" one and blind to row order
(shuffled). Labeling proceeded in two passes: an AI-suggested first pass
(0/80 rater overrides), followed by a fully blind re-check — suggestion
and reasoning columns removed entirely — restricted to the 3 pairs the
first-pass rater flagged as genuinely ambiguous. All 3 held on the blind
re-check, including the two closest calls. This is disclosed plainly as
AI-suggested, human-confirmed labeling, not fully independent
from-scratch annotation — a real methodological distinction, not glossed
over.

**Result** (`experiments/evaluation/relevance_classifier_validation/`,
n=80): **accuracy 92.5% (95% CI [84.6%, 96.5%]), precision 90.5% (95% CI
[77.9%, 96.2%]), recall 95.0% (95% CI [83.5%, 98.6%]), F1 92.7%**
(TP=38, FP=4, TN=36, FN=2). All 6 disagreements between the classifier
and the human labels cluster tightly around the 0.15 decision threshold
(overlap scores 0.100-0.191) rather than spreading across the full
range — the classifier's failure mode is specifically boundary cases,
not general unreliability. One disagreement is individually diagnostic:
a genuinely correct CVE citation scored only 0.100 and was
misclassified as irrelevant, because its official NVD description is
just the bare title "Windows Print Spooler Elevation of Privilege
Vulnerability" — almost no text for a word-overlap scorer to match
against. A second correct citation scored 0.148, missing the threshold
by one hundredth of a point.

**What this means.** The relevance classifier is reasonably accurate
against human judgment (92.5%), which is what makes the REAL_AND_PLAUSIBLE
/ REAL_BUT_IRRELEVANT split in Sect. 3.5 and Sect. 5's central argument
defensible rather than resting on an unchecked heuristic. But the failure
mode is concrete and worth naming precisely, not just as "some error
rate": short or generic authoritative descriptions starve a bag-of-words
scorer of anything to match, producing false negatives on genuinely
correct citations independent of whether the citation is actually right.
This is a real, disclosed limitation of the current relevance scorer, not
a hypothetical one — Sect. 5 restates it as such.

---

## 5 Discussion

**What REAL_AND_PLAUSIBLE means for trust.** The central practical argument
of this paper is that a citation which is real and topically plausible is
the *hardest* case for a human reviewer to catch, not the easiest — it looks
correct. Sect. 3.5's classification taxonomy and its unconditional review-flag
policy exist specifically because an earlier version of this pipeline got
this wrong (treating REAL_AND_PLAUSIBLE as self-evidently safe), and the
fix is documented as a deliberate correction, not presented as though the
pipeline always worked this way.

**What the CVE-pool finding (Sect. 4.5) means.** The 0%-fabrication /
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
- Sect. 4.9 (SelfCheckGPT) is complete, but the significance test it was
  meant to unblock (Sect. 4.10) is not run — a paired comparison against
  the deterministic pipeline would need a fresh run under the same
  sampling temperature, not a re-analysis of what was already collected;
  see Sect. 4.10 for why. Sect. 4.8 (LLM-judge baseline) is complete, but
  used the same model family for judge and generator rather than the
  independently-recommended different family (Sect. 2) — a disclosed, not
  a silently-assumed, limitation.
- Sect. 4.9's result directly contradicts Sect. 4.5's "never volunteers a
  withheld CVE" finding at higher sampling temperature (0.7 vs. 0.1): the
  same model, on the same style of alert, volunteers a
  withheld-but-correct identifier in most bait-class trials once sampled
  at the temperature SelfCheckGPT requires. Sect. 4.5's finding should be
  read as holding at production temperature specifically, not as a
  general property of the model — stated here rather than left as an
  unaddressed inconsistency between two sections.
- Sect. 4.8's 100% LLM-judge agreement should not be read as strong evidence
  on its own: the hard tier's discriminating signal (whether an
  identifier-shaped token also appears in the evidence) is close to what
  the deterministic checker already computes, so the labels are largely
  recoverable from how the calibration set was constructed rather than
  requiring deep semantic reasoning to solve. We treat this as a
  feasibility floor for the judge approach, not as evidence against the
  deterministic pipeline's necessity.
- The CVE-bait result (Sect. 4.3) is now current and at n=100 gives a
  legitimately citable 95% CI ([0.6%, 7.0%]), but both observed ungrounded
  citations occurred on the same two extremely famous vulnerabilities
  (Log4Shell, Follina) — the 75 newly added, less-famous CVEs produced
  zero citations to analyze. The honest claim is "rarely induces
  spontaneous citation, catches it correctly when it does happen on
  famous cases," not "stress-tested against obscure-CVE hallucination."
- Latency figures (Sects. 4.2, 4.7) are single-run and demonstrably variable
  run-to-run on shared, uncontrolled hardware; only order-of-magnitude
  comparisons should be drawn from them until repeated-trial benchmarking
  is complete.
- The Wazuh live integration demonstration (Sect. 4.6) is n=26 across two
  manual sessions, spanning four trigger types — a real-world sanity check
  and a genuine bug-finding exercise (Sect. 4.6's PII false-positive
  finding), not a statistically powered claim.
- The ATT&CK verification path relies on a periodically refreshed local
  snapshot (fetched 2026-08-04, 858 techniques, hash in Sect. 4.1) rather
  than a live per-ID lookup (no such endpoint exists publicly), which can
  lag MITRE's published data between refreshes — a disclosed asymmetry
  with the CVE path's live, per-citation NVD lookups, not treated as
  equivalent.
- CICIDS2017, used for realistic benign-traffic text in Sect. 4.2, has been
  independently flagged (by this project's own supervisor, corroborated
  against Goldschmidt & Chudá's 2025 survey [16])
  as no longer representative of *current attack patterns*. We used it here
  only for its `BENIGN`-labeled rows, as generic non-injection text to
  measure false-positive behavior — a different and, we argue, still valid
  use — while relying on the live Wazuh integration (Sect. 4.6) for any claim
  about current, real attack data. This distinction is stated explicitly so
  it is not mistaken for an oversight.
- T3 (PII leakage) is now addressed (Sect. 3.6, bait-tested Sect. 4.11), but only at
  n=6 positive cases — a first real signal that the guardrail and the
  model's own summarization behavior both function correctly, not yet a
  citable detection rate. A synthetic calibration set in the same spirit as
  Sect. 4.3's CVE-bait extension would be the natural way to get a statistically
  defensible number here.
- The report-generation backend is a single small model
  (`openai/gpt-oss-20b` via Groq); generalization to larger or
  differently-trained models is untested.
- The relevance classifier behind REAL_AND_PLAUSIBLE/REAL_BUT_IRRELEVANT
  (Sect. 3.4, validated Sect. 4.12) is 92.5% accurate against human
  judgment, not perfect — its 6 disagreements (n=80) all cluster at the
  0.15 decision threshold, and its specific known failure mode is
  short/generic authoritative descriptions producing false negatives on
  citations that are actually correct. Labels behind that validation are
  AI-suggested and human-confirmed (with a blind re-check on the hardest
  cases), not independently annotated from scratch — disclosed as such,
  not presented as a fully independent human benchmark.

**Threats to validity.** The input-guardrail comparison (Sect. 4.2) uses a
dataset partly adapted from public sources rather than fully independent
attacker data, which could inflate apparent recall if those sources overlap
with data the compared tools were themselves validated against — provenance
is tracked per-sample specifically so this can be audited. The CVE-bait set
(Sect. 4.3, n=100) now supports a legitimate confidence interval on the
ungrounded rate, but the vulnerability *selection* is not a random sample
of all CVEs — it's biased toward well-documented, high-profile, actively
exploited vulnerabilities (25 individually chosen for fame, 75 drawn from
CISA's KEV catalog, which itself only lists confirmed actively-exploited
vulnerabilities). This is deliberate — an obscure CVE with no public
writeup isn't a meaningful test of spontaneous citation either way — but
it means the estimated rate should not be read as generalizing to
citation behavior on arbitrary, less-documented CVEs. The ATT&CK-bait set
(Sect. 4.4) remains hand-authored at small scale (n=6); only qualitative claims
are drawn from it.

---

## 6 Conclusion

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
open-source alternatives, and against a SelfCheckGPT-style self-consistency
baseline. We were explicit throughout about what remains unproven or
bounded: the LLM-judge baseline (Sect. 4.8) is complete but uses the same
model family for judge and generator, a disclosed limitation rather than a
silent one; a paired significance test between the deterministic pipeline
and SelfCheckGPT (Sect. 4.10) needs a fresh run the existing data cannot
support, for reasons stated there; one adversarial result needs
re-verification against a bug fix made after it was recorded; and T3 (PII
leakage) is implemented and bait-tested (Sect. 4.11) at a small,
n=6-positive-case scale not yet citable on its own.

The SelfCheckGPT comparison (Sect. 4.9) is complete, and adds concrete
weight to this paper's central claim rather than merely rounding out the
evaluation: at the sampling temperature self-consistency checking
requires, the model volunteers real, correct-but-uncited identifiers it
stays silent on at production temperature (Sect. 4.5) — and does so
consistently enough, across independent resamples, that a
self-consistency signal alone cannot tell these eighteen cases apart from
a genuinely grounded citation. External grounding can, because it checks
the evidence the model was actually given rather than the model's
confidence in its own answer. That distinction — not raw accuracy against
a baseline — is what this paper argues a citation-grounding pipeline
contributes that self-consistency checking alone does not.

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
10. Srinivas, S., Kirk, B., Zendejas, J., Espino, M., Boskovich, M., Bari, A., Dajani, K., Alzahrani, N. AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation. Journal of Cybersecurity and Privacy, 5(4), 95, 2025. DOI: 10.3390/jcp5040095.
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

**Note on reference #10:** verified 2026-08-22 against Crossref's DOI
registration record (the authoritative source for this metadata, not the
publisher's own page, which blocks automated fetches) — real author names,
journal (Journal of Cybersecurity and Privacy, not "MDPI" itself, which is
the publisher), volume/issue/article number, and DOI now reflect the actual
listing rather than the placeholder inherited from the literature review.

---

## Appendix: mapping this draft back to the codebase

For a reviewer or collaborator who wants to verify any claim above against
the actual implementation:

| Section | Code / data |
|---|---|
| Sect. 3.2 Input guardrail | `src/guardrails/input_guardrail.py` |
| Sect. 3.3 Evidence Pack | `src/guardrails/evidence_pack.py` |
| Sects. 3.4–3.5 Output guardrail, CVE path | `src/guardrails/output_guardrail.py` |
| Sects. 3.4–3.5 Output guardrail, ATT&CK path | `src/guardrails/attack_grounding.py` |
| Sect. 3.6 PII redaction guardrail | `src/guardrails/pii_guardrail.py` |
| Shared grounding logic | `src/guardrails/grounding_utils.py` |
| Sect. 4.2 Input guardrail comparison | `experiments/evaluation/guardrail_comparison/` |
| Sect. 4.3 CVE-bait test | `experiments/evaluation/cve_bait_alerts.py`, `experiments/results/cve_bait_results.json` |
| Sect. 4.4 ATT&CK-bait test | `experiments/evaluation/attack_bait_alerts.py`, `experiments/results/attack_bait_results.json` |
| Sect. 4.5 Secure_SOC_AI + CVE pool | `experiments/evaluation/soc_integration_test.py`, `experiments/evaluation/soc_integration/cve_pool.py`, `docs/INTEGRATION_PLAN.md` |
| Sect. 4.6 Wazuh live validation | `experiments/evaluation/wazuh_integration_test.py` |
| Sect. 4.7 Performance benchmarks | `experiments/evaluation/threading_benchmark.py`, `experiments/evaluation/multiprocessing_benchmark.py`, `experiments/evaluation/diagnose_thread_slowdown.py` |
| Sect. 4.8 LLM-judge baseline | `experiments/evaluation/llm_judge_synthetic_test.py`, `experiments/results/llm_judge_synthetic_results.json` |
| Sect. 4.9 SelfCheckGPT comparison | `experiments/evaluation/selfcheckgpt_test.py`, `experiments/results/selfcheckgpt_results.json` |
| Sect. 4.11 PII redaction bait test | `experiments/evaluation/pii_bait_alerts.py`, `experiments/results/pii_bait_results.json` |
| Sect. 4.12 Relevance classifier validation | `experiments/evaluation/relevance_classifier_validation/` |
| Full chronological experiment log | `docs/all_results.md` |
| Live priority-ordered task list | `docs/ROADMAP_PLAN.md` |
