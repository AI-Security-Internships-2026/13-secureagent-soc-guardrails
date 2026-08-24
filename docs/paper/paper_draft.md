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
> - LLM-judge baseline (Sect. 3 item 5) — ✅ done 2026-08-20, full 318-sample
>   same-family run spanning an easy and a harder construct-validity tier:
>   100% accuracy/precision/recall on every slice (Sect. 4.8). **Cross-family
>   follow-up added 2026-08-23** (`qwen/qwen3.6-27b`, a genuinely different
>   model family, addressing the self-enhancement-bias gap directly rather
>   than leaving it disclosed-but-unaddressed): 441/450 (98%) complete,
>   quota-gated on Groq's free tier — same 100% accuracy/precision/recall
>   on every scored sample. The 9 unscored samples are reported as
>   incomplete, not rounded into the total (Sects. 2, 4.8 and 5).
> - SelfCheckGPT comparison (Sect. 3 item 8) — ✅ done 2026-08-21, full
>   60-alert run against the same CVE pool as Sect. 4.5. Headline: it never
>   false-flags the grounded class (precision 1.0) but misses most of the
>   ungrounded class (recall 0.31) — and 18 of those 20 misses are the
>   model *consistently citing the correct real CVE* from training
>   knowledge, not a fabrication, which a consistency-only signal cannot
>   tell apart from genuine grounding (Sect. 4.9). Its paired significance
>   test against the deterministic pipeline — ✅ done 2026-08-22 (Sect. 4.10):
>   the deterministic checker is significantly more accurate (McNemar
>   p=0.0118, n=56) — the one comparison in this paper where a performance
>   gap is both large and statistically confirmed, not just architecturally
>   argued.
> - CVE-bait and ATT&CK-bait test set expansion (Sect. 3 items 6-7) — ✅ done,
>   expanded in three and two passes respectively, most recently
>   **2026-08-25 to n=150 each** (Sects. 4.3-4.4). CVE-bait: blended n=150
>   ungrounded rate 1.3% (95% CI [0.4%, 4.7%]); 0/147 symptom-only alerts
>   ever produced a spontaneous citation (95% CI [0.0%, 2.6%]), both hits
>   came from the 3 alerts that explicitly ask for a citation, where the
>   model was right once and wrong-but-plausible once. ATT&CK-bait: blended
>   n=150 rate 4.0% (95% CI [1.8%, 8.5%]); 4/148 symptom-only (2.7%), 2/2
>   explicit-ask; includes one new finding — a citation to a real but
>   `revoked` (deprecated) technique ID, the ATT&CK equivalent of citing a
>   withdrawn CVE. The n=150 expansion also surfaced and fixed a real
>   metric-definition bug in the CVE-bait evaluation script that had been
>   silently counting PII-only review flags as CVE hallucinations
>   (`docs/all_results.md` #44). See Sects. 4.3-4.4 for full breakdown.
> - Full multi-source grounding benchmark (README Aug 23 milestone) — ✅ done
>   2026-08-24, updated 2026-08-25 (Sect. 4.13): pools every already-run
>   grounding source (575 alerts total) into cross-source rates — CVE-checker
>   sources 2/425 (0.47%), ATT&CK-checker sources 6/365 (1.64%) — with the
>   three non-adversarial sources (Wazuh, Secure_SOC_AI rule engine,
>   Secure_SOC_AI CVE pool) contributing zero ungrounded citations between
>   them.
> - Significance testing on the CVE-bait / ATT&CK-bait comparisons — still
>   open; only 2 and 6 ungrounded citations respectively even at n=150 each,
>   which still isn't enough discordant data for McNemar-style testing
>   against a future baseline to be meaningful (Sect. 8)
> - Presidio / PII redaction (T3 in the threat model) — ✅ built
>   2026-08-18, expanded and re-run 2026-08-22 (Sects. 3.6 and 4.11).
>   n=60 (up from 14): 5/40 PII alerts detected (12.5%, 95% CI [5.5%,
>   26.1%]), 0/20 false positives, 0 residual PII after redaction —
>   consistent with the original n=6 rate, now a citable number. Two of
>   the initial 7 raw detections were false positives (a small-model NER
>   gap, not real names) caught by checking against known sourced values
>   and corrected before this number was reported.
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

*(target: ~250 words. Restructured 2026-08-20 around one central research
question per external review feedback, rather than an itemized tour of
every experiment; trimmed to budget 2026-08-25 after folding in Sect.
4.9/4.10's SelfCheckGPT results and the cross-family LLM-judge result.)*

Large language models increasingly generate Security Operations Center
(SOC) threat reports citing CVE identifiers and MITRE ATT&CK techniques
as supporting evidence. These citations are rarely verified: models can
fabricate identifiers, misattribute real ones, or recall citations the
alert never provided, and a flat "flagged/not flagged" treatment cannot
distinguish an invented CVE from a real-but-unevidenced one, though the
two pose different risks to an analyst's trust.

We ask whether such reports can be automatically checked for citations
unsupported by the evidence given, and whether distinguishing *why* —
fabricated, irrelevant, or plausible enough to look correct — provides
assurance a binary flag cannot. LLMCite answers with a two-stage
pipeline: grounding against the source alert, then verification against
authoritative sources (NVD, the MITRE ATT&CK STIX corpus) into a
four-class taxonomy (plus a fifth for withdrawn identifiers). The central
finding is the Real-and-Plausible class: a real, topically appropriate
citation never stated in the evidence, the case most likely to evade
human review because it looks correct.

We evaluate across adversarial bait tests, third-party and live SOC data,
and a pooled cross-source summary, against two alternative verification
strategies. An LLM-judge baseline reproduces the pipeline's decisions at
100% accuracy — a feasibility floor, not evidence it is unnecessary. A
SelfCheckGPT-style consistency check misses most ungrounded citations
because most misses are the model consistently recalling a correct
identifier from training knowledge, the same Real-and-Plausible pattern
this paper centers; the deterministic checker is significantly more
accurate on the same alerts (McNemar p=0.012). LLMCite is a
domain-specialized citation-grounding verifier for security-critical LLM
applications, distinct from prior work on scholarly references.

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
threat reports, with a four-class taxonomy (plus a fifth label for
formally withdrawn identifiers) in place of the binary
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
   types (150 CVE identifiers, 150 MITRE ATT&CK techniques), a 76-incident
   run through an independent third-party incident generator, a 60-alert
   CVE pool isolating whether the model can identify a CVE from behavior
   alone versus merely verify one it is given, 139 real alerts across five
   distinct trigger types from a live Wazuh SIEM deployment including a
   genuinely detected brute-force attack, an LLM-judge baseline (both
   same- and cross-model-family) showing full agreement with the
   deterministic pipeline across an easy and a harder construct-validity
   tier, a SelfCheckGPT self-consistency baseline showing the two
   approaches catch different, non-overlapping failure modes rather than
   one strictly dominating the other — statistically confirmed as a real,
   significant gap (McNemar p=0.0118) rather than argued architecturally
   alone, a human
   validation of the relevance classifier underlying the taxonomy split
   (92.5% accuracy), and a bait test of a fourth guardrail addressing PII
   leakage (n=60, 12.5% detection rate) — plus a statistically tested
   comparison of the pipeline's input-guardrail layer against two
   maintained open-source alternatives.

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
family. Sect. 4.8 reports two LLM-judge baselines against the same
CVE/ATT&CK citation task LLMCite's deterministic pipeline evaluates: a
same-family judge (`openai/gpt-oss-20b`, the same model used for report
generation) and, addressing Zheng et al.'s own recommendation directly
rather than leaving it as a disclosed gap, a second, independently-hosted
model family (`qwen/qwen3.6-27b`) as judge over the identical calibration
set. Both are reported; the cross-family run had not fully finished at
the time of writing (441/450, Sect. 4.8) but the completed portion is
included rather than withheld pending full completion.

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

**Table 1** Threat model: attack types addressed by this pipeline's input and output guardrail layers

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

**Table 2** The four-class outcome taxonomy applied to every ungrounded citation (plus REJECTED/REVOKED for formally withdrawn identifiers)

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

**Table 3** Input guardrail comparison: precision/recall/latency/throughput across four implementations on the 119-sample eval set

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

**Table 4** McNemar significance testing across all 6 pairwise guardrail comparisons, raw and Holm-Bonferroni-corrected

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

**Re-run and expanded in three passes** (superseding the earlier n=6
result, which predated the `requires_review` unconditional-flag fix and
could no longer be trusted as current). First pass, 2026-08-12: 6 → 25
real CVEs, individually verified via web search before inclusion. Second
pass, 2026-08-12: 25 → 100, sourcing the additional 75 directly from
CISA's official Known Exploited Vulnerabilities (KEV) catalog — a real,
government-maintained feed — with each alert's behavior description
derived from that CVE's own CISA-published description (paraphrased to
remove the vendor/product name and CVE framing, keeping only the exploit
mechanism, so the bait alert still tests spontaneous citation rather than
pattern-matching a restated product name). Third pass, 2026-08-25: 100 →
150, sourcing 50 more from the same live KEV catalog (1,675 entries as of
that date). Using an authoritative bulk source across all three passes is
what made individually verifying 125 more real CVE numbers tractable at
this quality bar. Every one of the 150 CVE numbers is real and checked
against a source; a wrong "ground truth" in the test set itself would have
undermined the entire point of the exercise. 3 of the 150 alerts
additionally ask the model to name a specific identifier, rather than
staying purely symptom-only.

**Result** (`experiments/results/cve_bait_results.json`, n=150): 2/150
alerts (1.3%, 95% Wilson CI [0.4%, 4.7%]) produced an ungrounded CVE
citation. **This blended figure should not be reported on its own — it
conflates two different test conditions that need to be reported
separately.** 147 of the 150 alerts never mention a CVE at all (the pure
spontaneous-citation condition); **0/147 of these produced an ungrounded
citation**, a 95% Wilson interval of **[0.0%, 2.6%]**. The remaining 3
alerts (`BAIT-002`, `BAIT-011`, `BAIT-017`) explicitly ask the model to
cite a CVE identifier it was not given — a deliberate second test
condition, not the paper's main methodology — and both ungrounded hits
come from this subset of 3 (`BAIT-011` produced no citation and was not
flagged). So the precise claim is: **the model never spontaneously
volunteered a CVE number across 147 symptom-only alerts; when directly
asked to name one it wasn't given, it did so 2 of 3 times**, once
correctly and once with a real-but-wrong neighbor (detailed below). The
0/147 figure is the methodologically correct headline number for
"spontaneous CVE hallucination rate."

**`requires_review` for this set is not identical to the ungrounded rate**
(5/150, 3.3%) — 3 of those 5 are the PII redaction guardrail firing on a
single-word product name (`Zimbra`, `Ray`, `Joomla`) misread as a PERSON
by the small NER model, the same false-positive class documented in
Sect. 3.6 and Sect. 4.11, not a CVE-grounding error. An earlier version of
the evaluation script conflated the two by computing "ungrounded" from the
same blended flag the pipeline uses for `requires_review`; this coincided
with the true CVE-only count at n=100 (no product name in the first 100
alerts happened to trip the false positive) but diverged once 50 more
varied product names were added, and is corrected in the n=150 numbers
reported here — see `docs/all_results.md` #44 for the full account.

**The two ungrounded citations are the same two found at n=25 and n=100**
— no citation occurred on any of the 125 newly added, CISA-KEV-sourced
alerts, none of which include an explicit citation request either,
consistent with the 0/147 finding above. Of the 2:

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
  one of the 150 alerts where the model's citation was actually *wrong*,
  rather than correct-but-mechanically-flagged.

At n=150, this is now a genuinely citable estimate rather than a
qualitative-only demonstration, though the concentration finding above
means the honest framing is "the pipeline never spontaneously hallucinates
a CVE across 147 varied symptom-only alerts, and when directly pressed for
an identifier it wasn't given, it is right more often than wrong, with its
one error being a plausible neighbor rather than an invention" — not "the
pipeline has been stress-tested against obscure-vulnerability
hallucination," since the 125 newly added alerts (across the second and
third expansion passes) produced zero citations to analyze in the first
place.

### 4.4 Output guardrail: ATT&CK-bait adversarial test

A parallel bait set was built for MITRE ATT&CK technique citations,
expanded in two passes: 2026-08-21, 6 → 50 real techniques, individually
selected and cross-checked against the project's local MITRE ATT&CK
Enterprise STIX snapshot (858 techniques, official descriptions);
2026-08-25, 50 → 150, sourcing 100 more top-level techniques from the same
snapshot. Every technique paraphrases that technique's real, official
MITRE description into symptom-only EDR/log-style telemetry, never stating
the technique name or ID, with an automated check confirming no
technique-ID-shaped token or the technique's own name leaks into any
alert's text. 3 of the 150 alerts explicitly ask the model to name a
specific technique ID, mirroring CVE-bait's own explicit-citation-request
ratio.

**Result** (`experiments/results/attack_bait_results.json`, n=150): 6/150
alerts (4.0%, 95% Wilson CI [1.8%, 8.5%]) produced an ungrounded ATT&CK
citation. As with CVE-bait, the blended figure conflates two conditions:
148 alerts are symptom-only, of which **4/148 (2.7%, 95% CI [1.1%, 6.7%])**
produced an ungrounded citation; the remaining 2 alerts explicitly ask for
a technique ID, and both produced one (2/2). Of all 6 ungrounded
citations, 2 named the actual expected technique exactly
(`ATTACK-BAIT-023`, `ATTACK-BAIT-081`, both `REAL_AND_PLAUSIBLE`); the
other 4 did not. One of those 4 is a new, notable finding beyond anything
CVE-bait produced: `ATTACK-BAIT-005` cited `T1076`, a technique ID that
exists in the STIX snapshot but is marked `revoked` — MITRE's own record
of a deprecated/superseded ID — classified `REVOKED` rather than
`REAL_BUT_IRRELEVANT`. This is a citation that is neither fabricated nor
current: a real identifier that no longer represents an active part of
the framework, the ATT&CK equivalent of citing a withdrawn CVE. The
remaining 3 (`ATTACK-BAIT-006`, `-078`, `-116`) are `REAL_AND_PLAUSIBLE` /
`REAL_BUT_IRRELEVANT` wrong-neighbor citations in the same shape as
CVE-bait's Follina/DogWalk case — `ATTACK-BAIT-006` is a particularly
close miss, citing sub-technique `T1542.003` when the expected parent
technique was `T1542`.

**What this shows:** the same grounding-and-classify pattern generalizes to
a second, structurally different claim type (technique IDs verified against
a static STIX snapshot rather than a live per-ID API), which is the
concrete evidence behind Contribution 2's generalization claim, and at
n=150 the rate estimate is now genuinely citable rather than a
qualitative-only demonstration. The `REVOKED` case additionally shows the
classification taxonomy (Sect. 3.5) earning its keep on a case CVE-bait's
own test set never produced: a real-but-deprecated identifier, which is a
materially different risk from either a correct citation or an outright
fabrication.

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

**Table 5** CVE pool bait-vs-stated comparison: whether the model identifies a withheld CVE from behavior alone, or only verifies one it is given

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
a real registered agent. Real triggering activity was generated across five
distinct trigger types, not just passively observed: File Integrity
Monitoring alerts from an actual file write to a monitored path; a genuine
SSH brute-force attempt (repeated failed logins against a throwaway local
account) that Wazuh's own correlation engine correctly recognized and
escalated to a dedicated "brute force" rule, not a canned alert; realistic
SQLi/XSS/directory-traversal request lines fed into a monitored access log,
processed by Wazuh's real web-attack ruleset; rootkit-signature file
markers detected by Wazuh's rootcheck module; and sudo/privilege-escalation
syslog activity matched against Wazuh's real sudo ruleset.

**Result:** 139 unique alerts (after deduplication, expanded from an
original 26 via a later bulk-fire pass across the same five trigger types)
run through the full pipeline: **0% ungrounded on ATT&CK/CVE across all
139**. Manual inspection of the raw report JSON confirmed the model's
reasoning explicitly engaged with real MITRE technique IDs present in the
alerts (**T1110** — Brute Force, on the SSH alerts; **T1190** — Exploit
Public-Facing Application, on the web-attack alerts; **T1548.003** — Sudo
and Sudo Caching, on the privilege-escalation alerts) once an adapter bug
stripping MITRE tags from SSH-rule alerts specifically was found and fixed
(Wazuh nests MITRE tags differently for SCA/compliance rules versus SSH
rules — the adapter originally only checked one of the two shapes).

**Two genuine PII-guardrail findings surfaced by this live data, neither
visible on synthetic benchmarks:** First, at n=26, 5 alerts triggered a
`PERSON` false positive — the small NER model misread technical strings (a
URL path, a SQL/shell command fragment, the literal text "ATT&CK", a
benchmark document name) as a person's name, all at the same 0.85
confidence score. Fixed with a plausibility filter rejecting `PERSON`
matches containing characters no real name uses (`/`, `(`, `)`, `&`,
digits). Second, and far larger by volume, the bulk expansion to n=139
raised `requires_review` to 27.3% (38/139) before correction — checking
individual detections rather than trusting the aggregate rate found that
~35 of the 38 were Presidio's `PHONE_NUMBER` recognizer misreading bare IP
addresses (e.g. `203.0.113.138`) as phone numbers. This one is not
threshold-fixable: a real IP and a real phone number score the *identical*
0.4 confidence, so no score cutoff can separate them. Fixed instead with a
structural check — reject any `PHONE_NUMBER` match that parses as a valid
IPv4 address. Both fixes were re-verified against the already-generated
report text with no new inference calls needed; the corrected result is
**`requires_review` at 4/139 (2.9%)**, with zero regression on real-name or
real-phone-number detection (Sect. 4.11's bait-test numbers unaffected).
The 4 remaining flags are a disclosed, unresolved residual: single
capitalized words ("Mithra", "Maniac", "Bash", "Benchmark") that the
model's own report text uses as a rootkit or benchmark *name* directly
beside "rootkit" or "CIS ... score" — genuinely ambiguous for the NER
model, since malware-family names are deliberately styled like proper
nouns, unlike the earlier two bugs. A context-based fix here would be
overfit to these four exact strings rather than a general rule, so it is
reported as a known limitation instead of forced.

**Honest limitation:** n=139 is still manual, burst-fired activity across
several sessions rather than continuous production traffic — sufficient to
demonstrate the pipeline handles many real, live-detected attack patterns
correctly (and to surface two real guardrail bugs neither CICIDS2017 nor
the hand-authored bait sets could have), not sufficient to support a
precise statistical claim on its own. The original SSH result also tests
the "stated" condition only (T1110 was present in the alert Wazuh
generated); it does not test whether the model can spontaneously identify a
technique from raw behavior alone without the label, which Sect. 4.5's
CVE-pool finding already suggests the answer to. A sixth planned trigger
type, Wazuh's built-in vulnerability-detector (which would have produced
genuine CVE-tagged alerts from real installed packages), was attempted but
blocked by what appears to be a real inventory-sync limitation in this
single-node Docker deployment — not resolved, and not counted among the
139. A separate, lower-interval alert-generation loop is also run
alongside this dataset purely to keep the project's live dashboard visibly
active during demonstrations; it does not feed this or any other citable
result in this paper.

### 4.7 Performance benchmarks

**Original benchmark (superseded below).** Threading and multiprocessing
were first compared across 1/2/4 workers with repeats looped inside one
long-running process (3 repeats per configuration). That run showed
threading's full pipeline improving from 1 to 2 workers (3.20 → 5.16
alerts/sec) but collapsing sharply at 4 (0.67 alerts/sec, mean elapsed
8.99s, reproducible across repeats with low stdev) — traced via a
per-request timestamp diagnostic to one request among several fired
simultaneously occasionally stalling 5-10x longer than its peers, with no
client-side limit reached and no exception raised, consistent with (but
not definitively proven to be) Groq server-side per-key throttling under
load. Multiprocessing was worse than threading at every worker count
(1 process: 4.99s mean; 4 processes: 18.19s mean).

**Redone 2026-08-25** to close two gaps this original run left open
(docs/ROADMAP_PLAN.md Sect. 5): repeats looping inside one long-running
process can let OS scheduler state and memory-allocator warm-up carry
over between them, and there was no way to separate our own
guardrail/scheduling overhead from live Groq network variance. Two
changes: (1) each repeat now runs as a genuinely independent
`python -m ...` subprocess (`--single-run` mode on both benchmark
scripts, orchestrated by a new `fresh_process_benchmark.py`); (2) a
mocked-LLM variant runs the real input guardrail, CVE/ATT&CK grounding,
and PII redaction, but replaces only the Groq network call with a fixed
0.3s delay (calibrated from the original real run's mean) — free of API
cost and rate limits, so it runs at n=30 instead of n=6.

Fresh-process isolation immediately surfaced a real bug: full-pipeline
runs with more than one thread crashed deep inside torch, traced to an
unlocked lazy-singleton race in
`src/guardrails/input_guardrail.py`'s pytector loader — two threads
racing on the very first concurrent call both saw the singleton as
unset and both started constructing the DeBERTa model at once. The
original benchmark never hit this because thread-count=1 always ran
first in the same long-running process, accidentally warming the
singleton before any concurrent access. Fixed with double-checked
locking; this is a real production risk, not just a benchmark artifact,
since two concurrent requests could hit the live pipeline before the
model warms up.

**Table 6** Concurrency benchmark, fresh-process repeats (n=3 repeats per configuration; guardrail-only n=2000, mocked-pipeline n=30, real-pipeline n=6)

| Workload | Workers | Threading (alerts/sec) | Multiprocessing (alerts/sec) |
|---|---|---|---|
| Guardrail-only | 1 | 850,323 ± 115,672 | 648,379 ± 41,175 |
| Guardrail-only | 2 | 108,456 ± 9,380 | 309 ± 2 |
| Guardrail-only | 4 | 97,063 ± 14,474 | 230 ± 1 |
| Full pipeline, mocked LLM | 1 | 1.973 ± 0.032 | 2.031 ± 0.018 |
| Full pipeline, mocked LLM | 2 | 2.660 ± 0.140 | 1.380 ± 0.006 |
| Full pipeline, mocked LLM | 4 | 3.284 ± 0.415 | 1.328 ± 0.010 |
| Full pipeline, real Groq | 1 | 0.839 ± 0.019 | 0.896 ± 0.037 |
| Full pipeline, real Groq | 2 | 1.196 ± 0.174 | 0.333 ± 0.006 |
| Full pipeline, real Groq | 4 | 1.243 ± 0.170 | 0.273 ± 0.017 |

**What this shows.** The mocked and real-API columns agree in direction
at every worker count, which validates the mocked variant as a genuine
stand-in rather than an artifact of its specific delay value. Threading's
full-pipeline throughput climbs with more workers (real: +48% from 1 to 4
threads) because the GIL releases during the network wait, letting
threads overlap I/O. Multiprocessing's full-pipeline throughput falls
with more workers (real: -70% from 1 to 4 processes) because each
additional process pays its own model-load and process-creation cost with
no offsetting I/O-overlap benefit — the original "process overhead
dominates" finding, now with a concrete measured mechanism (the pytector
cold-start specifically) behind it rather than a general appeal to
"overhead." Guardrail-only numbers reproduce the original qualitative
pattern (more workers hurts a CPU-bound, microsecond-scale task; hurts it
far more for multiprocessing, since pool-management overhead swamps work
this cheap), though the 2/4-worker absolute figures are noisier than the
means alone suggest — `psutil.cpu_percent()`'s 0.1s sampling interval is
coarse relative to a sub-millisecond total runtime, a measurement-
resolution limitation disclosed rather than smoothed over.

**Honest discrepancy, not resolved.** The redone real-API run does *not*
reproduce the original benchmark's sharp 4-thread collapse — 4-thread
throughput here is the *best* of the three worker counts, not the worst.
Both runs are n=6, 3 repeats — modest statistical power either way — so
this could mean the original throttling event was a real but
non-reproduced instance of live server-side behavior that happened not to
recur in this run, or that some of the original in-process design's
cross-run interference (e.g. cumulative rate-limit-window state
persisting across the sequential 1→2→4 tests within one long process)
contributed to what looked like a thread-count effect. Both explanations
are plausible; neither is confirmed. We report both results rather than
quietly replacing one with the other.

### 4.8 LLM-judge baseline

**Method.** A separate judge call is prompted directly with an (alert
evidence, generated report) pair and asked to classify the report's
CVE/ATT&CK citations as grounded or ungrounded, without access to the
deterministic pipeline's own verdict. Run twice, over the identical
calibration set, with two different judges: `openai/gpt-oss-20b` (the same
model used for report generation — a same-family comparison) and
`qwen/qwen3.6-27b` (a different, independently-hosted model family),
addressing Zheng et al.'s [8] recommendation to control for self-enhancement
bias with a genuinely different judge rather than leaving it a disclosed
gap.

Evaluated on `experiments/evaluation/llm_judge_synthetic_test.py`'s
class-balanced calibration set, built the same way as Sect. 4.3's synthetic
extension: grounded-empty samples (no CVE/ATT&CK identifier present
anywhere in report or evidence), grounded-cited samples (a real
identifier present in *both* evidence and report — the harder,
construct-validity tier added per reviewer feedback on the pipeline's
earlier CVE-bait work), and ungrounded samples (a real-but-foreign
identifier injected into the report only). n=318 for the same-family
judge (all bait-set alerts available at the time it was run); n=450 for
the cross-family judge, run after Sect. 4.4's ATT&CK-bait set expanded
from 6 to 50, since this script rebuilds its sample set from the current
bait-set results.

**Result, same-family** (`experiments/results/llm_judge_synthetic_results.json`,
n=318, complete): **100% accuracy, 100% precision, 100% recall** (TP=106,
FP=0, TN=212, FN=0; 95% Wilson CI [98.8%, 100%] on accuracy), identically
100%/100%/100% on both the easy pair (grounded-empty vs. ungrounded, n=212)
and the hard pair (grounded-cited vs. ungrounded, n=212) analyzed
separately. Zero parse errors across all 318 calls.

**Result, cross-family**
(`experiments/results/llm_judge_synthetic_results_qwen_qwen3_6_27b.json`,
n=450, **441/450 completed (98%) — quota-gated on Groq's free tier, the
completed portion reported rather than withheld pending full completion**):
**100% accuracy, 100% precision, 100% recall** on the 439 scored samples
(2 parse errors; TP=147, FP=0, TN=292, FN=0; 95% Wilson CI [99.1%, 100%]
on accuracy), identically 100%/100%/100% on both the easy and hard pairs
(n=293 each) analyzed separately. Full agreement with the deterministic
pipeline's verdict on every single sample scored, matching the same-family
result exactly.

**What this means.** On this calibration task, both judges — same-family
and cross-family — reproduced the deterministic pipeline's own
ground-truth labels exactly, including on the harder tier where the
distractor identifier is present in both the evidence and the report.
That tier's discriminating signal, though, is itself close to what the
deterministic checker already computes — whether an identifier-shaped
token also appears in the evidence text — so a capable model matching it
is an expected feasibility floor, not evidence of deeper semantic
reasoning; labels this recoverable from the sample construction should
not be read as a strong argument against the deterministic pipeline
being necessary. The more defensible claim: an LLM judge can reliably
reproduce this specific binary grounding decision — regardless of model
family, per the cross-family result — while the deterministic pipeline
retains real deployment advantages neither judge shares — near-zero
latency, no per-call cost or rate-limit exposure (Sect. 4.7), and no
dependence on model behavior a hosted API could change or throttle. This
calibration set also tests an injected, single, isolated foreign citation
against otherwise-clean text rather than the messier range of real model
output (subtler misattributions, multiple citations in one report,
partial matches) that Sects. 4.3–4.4's real-pipeline bait tests also
check. The cross-family result addresses the self-enhancement-bias gap
directly: since a genuinely different model family reproduces the
identical verdict, the same-family result's 100% agreement is not
plausibly an artifact of judge-generator kinship — though the cross-family
run's 9 unscored samples (quota-gated, not yet run) are a real, disclosed
incompleteness, not rounded away.

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

**Table 7** SelfCheckGPT self-consistency baseline: correctness by grounded/prompted class (n=60, 4 excluded)

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
are all complete. A paired McNemar test between the deterministic pipeline
and SelfCheckGPT specifically needed a separate run rather than reusing
Sect. 4.9's own data: `sample_citations()` deliberately bypasses the
guardrail pipeline, so the deterministic checker's actual verdict was
never computed on those 60 alerts — only the bait/stated construction's
ground-truth label was, and treating that label as a stand-in for "what
the deterministic checker would have said" would make the comparison
tautological rather than a real empirical test. Generated one fresh
report per alert (not Sect. 4.9's three — the deterministic checker needs
no resampling, only something to check) at the same temperature=0.7
sampling, over the identical 60-alert set, and ran the real deterministic
checker against each (`experiments/evaluation/selfcheckgpt_significance_test.py`).

**Result** (`experiments/results/selfcheckgpt_vs_deterministic_mcnemar.json`,
n=56 after excluding the same "declined every sample" alerts Sect. 4.9's
own scoring excludes): **both correct in 32 cases, the deterministic
checker uniquely correct in 16, SelfCheckGPT uniquely correct in 4, both
wrong in 4 — exact binomial McNemar p=0.0118, significant at α=0.05.**
This is the one comparison in this paper where a raw performance
difference is both large and statistically confirmed rather than resting
on argument alone: the deterministic checker was right 4× more often than
SelfCheckGPT was, on the exact same alerts, and that asymmetry is not
plausibly due to chance at this sample size. The deterministic checker's
own accuracy across all 60 was 52/60 (100% on the stated/grounded class,
73.3% on the prompted/ungrounded class — some of that gap is alerts where
the model declined to cite anything at all under resampling temperature,
correctly leaving nothing to flag, not a genuine grounding-logic error).

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

`experiments/evaluation/pii_bait_alerts.py` built 40 alerts with synthetic
PII embedded in realistic raw evidence, spanning 10 scenario types (DLP
exfiltration, phishing credential harvest, payment-data exposure, vishing
report, database dump, cloud-storage misconfiguration, backup exposure,
misdirected email, lost device, third-party vendor leak), plus 20 clean
alerts with zero personal data as a false-positive regression check. The
original 6 PII / 8 clean alerts are hand-authored; the 34 / 12 added in
this expansion instead embed real synthetic entity *values* — never real
individuals' data — sourced from two verified, actively maintained,
explicitly-synthetic external datasets (Gretel's `gretel-pii-masking-en-v1`,
Apache-2.0, and ai4privacy's `pii-masking-openpii-1m`, CC-BY-4.0), wrapped
in hand-written SOC-alert scenarios — the same paraphrase-real-data-into-
alert-text method Sect. 4.3's CVE-bait set uses. Every added alert was
verified via the guardrail's own detector to actually trigger its stated
entity type in the raw text before being included, and card numbers were
reformatted with a computed valid Luhn check digit first, since Presidio's
`CREDIT_CARD` recognizer requires Luhn validity to fire at all and the
source datasets do not guarantee it. Each is run through the full
guardrailed pipeline (real Groq calls), checking both whether the model
echoed something the guardrail then caught, and whether anything survives
an independent re-scan of the already-redacted final text (residual
PII — should always be zero).

**Result** (`experiments/results/pii_bait_results.json`, n=60): **5/40 PII
alerts had a genuine detection (12.5%, 95% CI [5.5%, 26.1%]), 0/20 false
positives on clean alerts, 0 residual PII after redaction.** The rate is
consistent with the original n=6 result (16.7%), now with a real
confidence interval instead of an unreportable one. Inspecting all 5:
each caught only *one* of the alert's two expected entity types (e.g. the
person's name but not their phone number, or the card number but not the
cardholder's name), never both — the model quotes some part of a record
verbatim but still paraphrases the rest. Manual inspection of several
"nothing detected" cases confirms the pattern from the original n=6 result
still holds at scale: the model (`openai/gpt-oss-20b`) consistently
summarizes PII *abstractly* rather than quoting raw values — e.g.
describing "a CSV row with sensitive employee PII" without repeating the
actual SSN or email.

**A real false-positive finding surfaced and fixed while checking this
result, not after publishing it.** Two of the initial 7 raw detections
were not genuine: the guardrail's small NER model flagged the bare word
"PII" and the ordinary two-word phrase "enforce bucket" as `PERSON`
entities — neither is a real name, and the pipeline's own scoring (which
only checks "was an entity of the expected *type* detected," not "was the
*correct* value detected") silently counted both as hits. Caught by
manually inspecting every positive detection against its known sourced
value rather than trusting the aggregate rate at face value. Extended the
plausibility filter already built for a prior false-positive round
(Sect. 4.6): real names are Title Case in normal prose, so a match is now
rejected if any word starts lowercase, or if the whole span is a short,
fully-uppercase acronym-shaped string — catching "enforce bucket" and
"PII" respectively while leaving every real sourced name (including
hyphenated and apostrophe'd ones) undisturbed. Corrected the two affected
rows and the aggregate rate from an inflated 17.5% (7/40) down to the
verified 12.5% (5/40) reported above.

**What this means.** Three distinct findings, not one, now on a real
sample size. First, the report-generation model's own summarization
behavior is itself a meaningful mitigation for T3 — most of the time it
does not quote raw sensitive values verbatim even when they are present
in the evidence it was given, similar in spirit to Sect. 4.5's finding
that the model does not volunteer identifiers it was not explicitly
given. Second, on the 5 cases where it did quote something verbatim, the
guardrail worked exactly as designed end to end: detection, redaction,
zero residual PII, zero false positives elsewhere across all 60 alerts.
Third — and the one this expansion actually surfaced rather than
confirmed — checking a guardrail's *aggregate rate* is not the same as
checking that every individual hit is genuine; a type-level pass/fail
check can silently absorb false positives that happen to land on the
right label. The corrected number is smaller than the first pass reported,
which is the point: a smaller, verified number is worth more than a
larger, unverified one.

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

### 4.13 Cross-source grounding summary

Sects. 4.3-4.6 each report a grounding rate on one alert source in
isolation. This section pools them into a single cross-source view, using
only results already reported above — no new alerts were generated and no
new LLM calls were made; `experiments/evaluation/grounding_benchmark_summary.py`
reads the five existing result files and computes pooled rates with Wilson
95% confidence intervals.

**Result** (`experiments/results/grounding_benchmark_summary.json`, 575
alerts total, updated 2026-08-25 after Sects. 4.3-4.4's bait sets both grew
to n=150): pooling every source that exercises the CVE checker (CVE-bait,
Wazuh, Secure_SOC_AI rule engine, Secure_SOC_AI CVE pool; n=425) gives an
ungrounded rate of **2/425 (0.47%, 95% CI [0.1%, 1.7%])**. Pooling every
source that exercises the ATT&CK checker (ATT&CK-bait, Wazuh, Secure_SOC_AI
rule engine; n=365) gives **6/365 (1.64%, 95% CI [0.8%, 3.5%])**. Both
non-zero contributions come entirely from the two sources purpose-built to
bait an ungrounded citation (Sects. 4.3, 4.4); the three non-adversarial
sources — real Wazuh SIEM alerts, the Secure_SOC_AI rule engine, and the
Secure_SOC_AI CVE pool — contribute zero ungrounded citations between
them.

**Honest limitation.** This pooled figure is not a single random sample —
it is five heterogeneous samples with different construction methods
(hand-authored bait, real SIEM output, an external rule engine) combined
by simple addition, which is why per-source rates are reported alongside
the pooled ones rather than in place of them. It also inherits each
source's own caveats: Wazuh's pooled contribution reflects only the alert
types this single-node deployment actually produces, not a general claim
about live-SIEM CVE traffic (Sect. 4.6's vulnerability-detector limitation
still applies), and formal significance testing between sources was not
attempted — CVE-bait's 2 positives and ATT&CK-bait's 6 are both too few
discordant cases for McNemar to say anything meaningful even at n=150
each (the same caveat already on record in Sect. 4.3 and Sect. 4.10). A
metric-definition bug in the CVE-bait evaluation script (conflating
CVE-grounding flags with PII-only review flags) was found and fixed while
expanding to n=150 — the CVE-bait numbers reported in Sect. 4.3 and pooled
here are the corrected ones (see Sect. 4.3's own note and
`docs/all_results.md` #44 for the full account).

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
- Sect. 4.9 (SelfCheckGPT) and its paired significance test against the
  deterministic pipeline (Sect. 4.10) are both complete: the deterministic
  checker is significantly more accurate (p=0.0118, n=56). Sect. 4.8
  (LLM-judge baseline) now includes a cross-model-family judge alongside
  the original same-family one, addressing the previously-disclosed
  self-enhancement-bias gap directly — 441/450 (98%) complete, quota-gated
  on Groq's free tier rather than a design limitation; the completed
  portion is reported rather than withheld, and stated as partial rather
  than rounded up.
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
- The CVE-bait result (Sect. 4.3) is now current and at n=150 gives a
  legitimately citable 95% CI ([0.4%, 4.7%]), but both observed ungrounded
  citations occurred on the same two extremely famous vulnerabilities
  (Log4Shell, Follina) — the 125 newly added, less-famous CVEs produced
  zero citations to analyze. The honest claim is "rarely induces
  spontaneous citation, catches it correctly when it does happen on
  famous cases," not "stress-tested against obscure-CVE hallucination."
  The ATT&CK-bait result (Sect. 4.4) shows a similar but not identical
  pattern at n=150: 4 of its 6 ungrounded citations are wrong-neighbor or
  revoked-technique cases on less prominent techniques, not concentrated
  on famous ones the way CVE-bait's are.
- Sect. 4.7's concurrency benchmark now uses fresh-process repeats
  (n=3, mean ± stdev, 2026-08-25), closing that specific gap. Sect. 4.2's
  input-guardrail latency comparison has not had the same treatment —
  it still runs once per invocation with no repeat/aggregation step, on
  shared, uncontrolled hardware; only order-of-magnitude comparisons
  should be drawn from those figures specifically until it is.
- The Wazuh live integration demonstration (Sect. 4.6) is n=139 across
  several manual sessions, spanning five trigger types — a real-world
  sanity check and a genuine bug-finding exercise (Sect. 4.6's two
  PII false-positive findings), not a statistically powered claim.
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
- T3 (PII leakage) is addressed (Sect. 3.6, bait-tested Sect. 4.11) at
  n=60 (expanded from an initial n=14): 5/40 detected (12.5%, 95% CI
  [5.5%, 26.1%]), a now-citable rate, though the interval is still wide
  enough that a further expansion would tighten it meaningfully if the
  paper's timeline allows it. This number was corrected down from an
  initial 7/40 after 2 false positives (a small-model NER gap) were
  caught by checking detections against known sourced values rather than
  trusting the type-level aggregate.
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
(Sect. 4.3, n=150) now supports a legitimate confidence interval on the
ungrounded rate, but the vulnerability *selection* is not a random sample
of all CVEs — it's biased toward well-documented, high-profile, actively
exploited vulnerabilities (25 individually chosen for fame, 125 drawn from
CISA's KEV catalog, which itself only lists confirmed actively-exploited
vulnerabilities). This is deliberate — an obscure CVE with no public
writeup isn't a meaningful test of spontaneous citation either way — but
it means the estimated rate should not be read as generalizing to
citation behavior on arbitrary, less-documented CVEs. The ATT&CK-bait set
(Sect. 4.4, n=150) has the analogous bias in the other direction: technique
selection is drawn from the local MITRE snapshot itself rather than from
any real-world prevalence signal, so the rate should be read as "how often
the model reaches for a specific technique ID given a symptom description
resembling *some* real technique," not as representative of attacker
behavior frequency.

---

## 6 Conclusion

We presented LLMCite, a domain-specialized citation-grounding verification
pipeline for LLM-generated SOC reports, built around a four-class outcome
taxonomy (plus a fifth label for formally withdrawn identifiers) rather
than a binary flagged/not-flagged label. We showed this
taxonomy and its underlying grounding pattern generalize across two
distinct claim types (CVE identifiers via live NVD lookup, MITRE ATT&CK
techniques via a local STIX snapshot), and evaluated the pipeline across
adversarial bait tests at n=150 for each claim type, an independent
third-party incident generator, a CVE pool isolating identification from
verification, live SIEM data including a genuinely detected attack, a
pooled cross-source grounding summary spanning 575 alerts across every
evaluated source (Sect. 4.13), and a statistically tested
comparison of the pipeline's input-guardrail layer against maintained
open-source alternatives, and against a SelfCheckGPT-style self-consistency
baseline, statistically confirmed against it (Sect. 4.10, p=0.0118) rather
than argued architecturally alone. We were explicit throughout about what
remains unproven or bounded: the LLM-judge baseline (Sect. 4.8) now spans
both a same-family and a cross-family judge, the latter 441/450 (98%)
complete and quota-gated rather than left as an unaddressed limitation.
T3 (PII leakage) is implemented and bait-tested at n=60 (Sect. 4.11), a
citable rate (12.5%, 95% CI [5.5%, 26.1%]) though the interval still has
room to tighten.

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

**Table A1** Mapping from each paper section/claim to its supporting code and result files

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
| Sect. 4.8 LLM-judge baseline (same-family) | `experiments/evaluation/llm_judge_synthetic_test.py`, `experiments/results/llm_judge_synthetic_results.json` |
| Sect. 4.8 LLM-judge baseline (cross-family) | `experiments/evaluation/llm_judge_synthetic_test.py` (`LLM_JUDGE_MODEL=qwen/qwen3.6-27b`), `experiments/results/llm_judge_synthetic_results_qwen_qwen3_6_27b.json` |
| Sect. 4.9 SelfCheckGPT comparison | `experiments/evaluation/selfcheckgpt_test.py`, `experiments/results/selfcheckgpt_results.json` |
| Sect. 4.10 deterministic-vs-SelfCheckGPT McNemar test | `experiments/evaluation/selfcheckgpt_significance_test.py`, `experiments/results/selfcheckgpt_vs_deterministic_mcnemar.json` |
| Sect. 4.11 PII redaction bait test | `experiments/evaluation/pii_bait_alerts.py`, `experiments/results/pii_bait_results.json` |
| Sect. 4.12 Relevance classifier validation | `experiments/evaluation/relevance_classifier_validation/` |
| Full chronological experiment log | `docs/all_results.md` |
| Live priority-ordered task list | `docs/ROADMAP_PLAN.md` |
