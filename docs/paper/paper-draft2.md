# LLMCite-CVE: A Grounded Taxonomy for Detecting Hallucinated CVE Citations in LLM-Generated SOC Reports

**Author:** Emaan Afroz Khuram
**Affiliation:** CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna
**Target venue:** SN Computer Science (Springer). Backup: International Journal of Information Security.

---

## Abstract

Security Operations Center (SOC) analysts increasingly rely on large language models (LLMs) to triage alerts and draft incident reports, which often cite CVE identifiers as supporting evidence. Nothing in a typical deployment checks whether a cited CVE is real, relevant, or even present in the evidence the model was given. A flat "flagged/not flagged" label is not enough: a fabricated identifier, a real-but-unrelated one, and a real, plausible-looking one never actually stated in the alert carry different risks for an analyst deciding how much to trust a report.

This paper presents a two-stage output guardrail that grounds every CVE citation against the alert's own evidence before verifying ungrounded ones live against the National Vulnerability Database (NVD), classifying the result into four categories — FABRICATED, REAL_BUT_IRRELEVANT, REAL_AND_PLAUSIBLE, and UNVERIFIED — instead of a single binary flag. REAL_AND_PLAUSIBLE is the central contribution: a real, topically appropriate CVE the alert never mentioned, the case most likely to be trusted precisely because it looks correct.

We evaluate the guardrail on a 150-alert adversarial CVE-bait set, benchmark the input-guardrail layer against two open-source alternatives (LLM Guard, Pytector), and measure the pipeline's throughput under multiprocessing. The guardrail never spontaneously fabricates a citation across 147 symptom-only alerts, and correctly classifies both observed ungrounded citations, including one real CVE substituted for a closely related one. We discuss the taxonomy's value for analyst trust, its limitations, and how it could generalize beyond CVE identifiers to other fabricatable technical claims.

---

## I. Introduction

Large language models are being folded into Security Operations Center workflows [8] to summarize alerts, draft incident reports, and recommend remediation steps — one instance of a broader pattern of LLM hallucination that remains an open problem across applications generally [7], not unique to this domain. Part of what makes these reports useful is that they cite evidence — most concretely, CVE identifiers that ground a claimed vulnerability in a specific, publicly documented record. An analyst reading "this behavior is consistent with CVE-2021-44228" is meant to trust that citation the way they would trust a citation in any technical document: as a pointer to something real and checkable.

The problem is that nothing in a typical LLM-assisted SOC pipeline actually checks it. A model can invent a CVE number that does not exist, cite a real CVE that has nothing to do with the alert in front of it, or — the case this paper is specifically built around — cite a real, topically appropriate CVE that the alert itself never mentioned, recalled instead from the model's training data. That last case is the most dangerous of the three, not because it is factually wrong, but because it is not: a real, plausible-sounding CVE number is exactly the kind of citation a human reviewer has no practical reason to double-check.

Most existing guardrail tooling treats this as a binary problem: a claim is either flagged for review or it is not. That framing collapses three genuinely different situations into one signal. An analyst who sees "flagged" for a fabricated CVE and an analyst who sees "flagged" for a real-but-unstated one are being told the same thing, even though the second case demands a different kind of scrutiny — not "is this real," but "does the evidence actually say this." A taxonomy that keeps those cases distinct gives an analyst (and a downstream automated triage system) something more actionable than a single bit.

This paper describes and evaluates a two-stage output guardrail built around that distinction. The first stage checks whether a cited CVE identifier is literally present in the alert's own evidence. The second stage, run only on citations that fail the first check, verifies the identifier live against NVD and classifies the result into one of four outcomes describing *why* it is ungrounded, not just *that* it is.

### Contributions

1. **A four-class grounding taxonomy for CVE citations** — FABRICATED, REAL_BUT_IRRELEVANT, REAL_AND_PLAUSIBLE, and UNVERIFIED — that replaces a single flagged/not-flagged label with a distinction an analyst can act on differently. REAL_AND_PLAUSIBLE is the taxonomy's central case: a real, on-topic CVE the alert never actually supplied, which is both the hardest case to catch by eye and, empirically, a real failure mode this paper's adversarial testing observed directly.
2. **A working two-stage implementation** — deterministic evidence grounding followed by live NVD verification — that runs with no additional hosted-model call and adds negligible latency to the guardrail layer itself, evaluated against a purpose-built adversarial test set of 150 real CVE identifiers.
3. **Supporting evaluation of the surrounding pipeline**, establishing that the taxonomy sits inside a system that also holds up under two independent stress tests: a benchmarked comparison of the input-guardrail layer against two maintained open-source alternatives, and a concurrency benchmark measuring how the full pipeline's throughput scales — or fails to scale — under multiprocessing.

The remainder of this paper is organized as follows. Section II reviews related hallucination-detection and guardrail work. Section III describes the two-stage output guardrail and its taxonomy. Section IV presents the evaluation. Section V discusses limitations and future work. Section VI concludes.

---

## II. Related Work

**Hallucination detection and grounding.** SelfCheckGPT [2] detects likely-hallucinated sentences without an external knowledge source, by sampling a model multiple times and measuring how consistent its answers are with each other. This is a fundamentally different signal from the one this paper relies on: consistency tells you whether a model keeps saying the same thing, not whether the thing it keeps saying is actually supported by the evidence it was given. A model can recall a real, correct CVE identifier from training data with perfect consistency across repeated samples, while that identifier is still absent from the specific alert being analyzed — consistency alone cannot distinguish the two cases. FActScore [3] is methodologically closer: it decomposes long-form text into atomic factual claims and verifies each against a reference corpus, reporting that even strong commercial models achieve only around 58% atomic-fact precision on open-domain biographical text. This paper specializes that same decompose-ground-verify pattern to a domain where the reference corpus is a structured, versioned technical database — NVD — rather than free-text prose, and where the ground truth for a claim is unambiguous in a way an open-domain factual claim rarely is. A third strategy, prompting a separate LLM to judge whether a claim is grounded [6], avoids building a deterministic checker at all, at the cost of depending on a second model call and inheriting that model's own documented judgment biases — a tradeoff this paper's deterministic approach is built to avoid.

**Guardrail frameworks.** NeMo Guardrails [4] provides a general-purpose toolkit for defining programmable input/output rails via its Colang language. We evaluated it directly as a candidate for this project's input-guardrail layer; its LLM-based intent classification proved unreliable for injection detection when run against a small local model, which motivated the deterministic-first design used in this paper's own input guardrail (Section III, and benchmarked in Section IV). Guardrails AI [13] takes a schema-validation approach to constraining LLM output structure, but its relevant hub validator for this project's threat model required a hosted-API call, which was outside this project's local-only constraint. LLM Guard [11] and Pytector [12] are both maintained, locally-runnable prompt-injection classifiers; we use them directly as comparison baselines in Section IV rather than only discussing them, since both are realistic alternatives a practitioner might reach for instead of building a custom guardrail. None of NeMo Guardrails, Guardrails AI, LLM Guard, or Pytector verify a technical citation's factual grounding against an authoritative external source — they operate on the input side of the pipeline, deciding whether a prompt is safe to process, not on whether a generated claim is true.

**Grounding structured security artifacts.** TRAM [22], MITRE Engenuity's Threat Report ATT&CK Mapper, extracts MITRE ATT&CK technique mentions from trusted, analyst-authored threat intelligence reports. It solves a related but distinct problem — mapping technique mentions that are already assumed to be honest — rather than the adversarial case this paper addresses, where the citation itself may be fabricated or misapplied. TRAM's own domain, ATT&CK technique identifiers, is also the most natural direction for generalizing the taxonomy in this paper beyond CVEs, discussed further in Section V.

**Comparable commercial systems.** Deployed LLM-assisted SOC products — Microsoft Security Copilot [19], Google's Gemini for Security / Chronicle [20], and IBM QRadar Advisor with Watson [21] among others — produce analyst-facing triage summaries, but none of their public technical documentation describes verifying an individual technical citation against an authoritative source, or exposes a reviewer-auditable classification of why a given citation should or should not be trusted. This is the practical motivation behind treating grounding as a first-class, inspectable pipeline stage rather than an internal model behavior.

---

## III. Proposed Method

### A. Threat model

A generated SOC report can cite a CVE identifier in one of four ways relative to the alert it was built from: correctly, grounded in evidence the alert actually contains; fabricated outright; real but unrelated to the alert; or real, plausible, and simply never stated in the alert's evidence — recalled instead from the model's training knowledge. Only the first case is safe to trust without further checking. This paper's output guardrail exists specifically to catch and distinguish the remaining three.

### B. Evidence Pack

Before any citation is checked, an explicit **Evidence Pack** is built for the alert, separating its structured fields (source/destination IP, host, user, file hash, port) from the free-text description and payload fields that are the actual surface a CVE citation could plausibly be grounded in. Grounding checks run only against this text field. This makes the grounding surface an auditable object attached to the report, rather than an implicit property of however the alert happened to be formatted into a prompt.

### C. Two-stage output guardrail

**Stage 1 — grounding.** Every CVE-shaped identifier (`CVE-YYYY-NNNNN`) is extracted from the generated report's text fields via regular expression. Each extracted identifier is checked against the Evidence Pack's text field: if the identifier is literally present there, it is grounded, and no further check is needed. If it is absent, the identifier proceeds to Stage 2.

**Stage 2 — authoritative verification.** Ungrounded identifiers are looked up live against NVD's [16] public API — no hosted-LLM call, no API key required. The identifier's official description is then compared against the alert's evidence text using a deterministic, stemmed bag-of-words topical-overlap score, which determines whether a real CVE is actually relevant to this specific alert or merely real and unrelated.

### D. Classification taxonomy

The result of Stage 2 is one of four classes:

**Table I.** The four-class outcome taxonomy applied to every ungrounded CVE citation

| Class | Meaning |
|---|---|
| **FABRICATED** | The identifier does not exist in NVD at all. |
| **REAL_BUT_IRRELEVANT** | The identifier is real, but its NVD description does not topically match the alert. |
| **REAL_AND_PLAUSIBLE** | The identifier is real and topically matches the alert — a plausible correct recall the model made without being given the number, but still unverified as actually grounded in this specific alert's evidence. |
| **UNVERIFIED** | NVD could not confirm or deny the identifier (network failure, rate limiting, or no description available for comparison). |

The implementation also recognizes a fifth, rarer outcome — REJECTED — for identifiers NVD's own records mark as formally withdrawn or duplicate. This paper's evaluation set did not surface a REJECTED case, so the discussion below focuses on the four classes above, which is what the evaluation actually exercises.

Every ungrounded citation, regardless of which of these classes it falls into, sets a `requires_review` flag unconditionally. This is a deliberate choice: an earlier version of this pipeline treated REAL_AND_PLAUSIBLE as self-evidently safe and did not flag it, on the reasoning that a real, on-topic CVE is unlikely to be harmful even if unverified. We changed this after recognizing the opposite is true — REAL_AND_PLAUSIBLE is precisely the class a human reviewer is *least* likely to catch by inspection, since it looks correct, which makes it the highest-risk case for silent, unearned trust rather than the lowest.

### E. Pipeline architecture

**Figure 1.** Output guardrail pipeline (text schematic — see repository for the implementing code)

```
 Generated SOC report
          |
          v
 Evidence Pack built (structured fields separated
 from free-text description/payload)
          |
          v
 Stage 1 -- Grounding check
 Is the CVE identifier present in the evidence text?
          |
   +------+------+
   | yes         | no
   v             v
 Grounded    Stage 2 -- NVD verification (live lookup)
 (no flag)        |
                  v
          Classification:
          FABRICATED / REAL_BUT_IRRELEVANT /
          REAL_AND_PLAUSIBLE / UNVERIFIED
                  |
                  v
          requires_review = True
```

### F. Input guardrail (supporting layer)

Ahead of the output guardrail described above, an input guardrail screens the alert text itself for prompt-injection attempts before it reaches the model — the threat model established by InjecAgent [1], where the injected instruction arrives hidden inside tool or log data the agent processes as legitimate input, rather than from a trusted user. A training-level fix to the same underlying problem exists [5], but is not available when the report-generation model is a third-party hosted API rather than one this project can fine-tune, which is why this guardrail is a runtime, deployment-side control instead. It runs deterministic substring matching against a fixed list of known injection phrases first, near-zero latency; text that passes falls back to Pytector, a local classifier, so that paraphrased or novel injection attempts not covered by the deterministic list get a second chance to be caught. This layer is orthogonal to the CVE-grounding contribution above — it exists to keep the alert data itself trustworthy before the model ever generates a citation to check — and is benchmarked against alternatives in Section IV as supporting evidence that the surrounding pipeline is sound, not as this paper's headline result.

---

## IV. Evaluation

### A. Experimental setup

Report generation uses Groq's [17] hosted inference (`openai/gpt-oss-20b`) as the LLM backend throughout. All guardrail components — deterministic matching, Pytector, NVD verification — run locally, with no sensitive alert data sent to any hosted API beyond the report-generation call itself.

### B. CVE-bait adversarial test

To test whether the output guardrail's own pipeline induces spontaneous fabrication, we built a 150-alert adversarial test set from real, individually verified CVE identifiers, a subset sourced in bulk from CISA's Known Exploited Vulnerabilities catalog. Each alert describes the corresponding exploit's behavior in symptom-only language, with the vendor name, product name, and CVE framing stripped from the description, so the test measures spontaneous citation rather than pattern-matching a restated product name. Three of the 150 alerts additionally, explicitly ask the model to name a CVE identifier it was not given, isolating that as a separate condition from the 147 purely symptom-only alerts.

**Table II.** CVE-bait results by test condition (n = 150)

| Condition | n | Ungrounded citations | Rate (95% Wilson CI) |
|---|---|---|---|
| Symptom-only (no citation requested) | 147 | 0 | 0.0% [0.0%, 2.6%] |
| Explicit citation request | 3 | 2 | — |
| **Overall** | **150** | **2** | **1.3% [0.4%, 4.7%]** |

The headline result is the symptom-only condition: across 147 alerts that never ask the model to name a CVE, it never spontaneously volunteers an ungrounded one. The two ungrounded citations that did occur both came from the three alerts that explicitly requested one, and both illustrate the taxonomy directly. The first, in response to a Log4Shell-describing alert, correctly produced `CVE-2021-44228` — a real, exactly correct identifier, classified REAL_AND_PLAUSIBLE and still flagged for review, since the alert text itself never stated the number. This is the taxonomy's central case occurring in practice, not just in principle: a citation that is factually right but not evidentially grounded, and the guardrail's rule is mechanical enough that it does not give the model credit for being independently correct. The second, in response to a Follina-describing alert, produced `CVE-2022-34713` ("DogWalk") instead of the correct `CVE-2022-30190` — a real, separate Microsoft MSDT vulnerability disclosed around the same time, classified REAL_BUT_IRRELEVANT. This is a concrete instance of the exact risk this paper's introduction describes: a real identifier, confused with a closely related one, indistinguishable from a correct citation without independent verification.

### C. Input guardrail comparison

We benchmarked the input guardrail (Section III-F) against two maintained open-source alternatives — LLM Guard and Pytector — on a 119-sample held-out evaluation set: 53 injection attempts spanning exact-pattern, paraphrase, and novel-strategy categories, a portion adapted from two real, licensed public sources (`deepset/prompt-injections` [10] and the in-the-wild jailbreak corpus behind [9], with attacker-authored phrasing preserved and payloads rewritten to fit a SOC-alert context); and 66 benign samples including real network-flow text from CICIDS2017 [14], used here only for its non-injection traffic and not as a claim about current attack-pattern realism, since that dataset has since been noted as dated for that purpose [15].

**Table III.** Input guardrail comparison across four implementations (n = 119)

| Implementation | Precision | Recall | F1 | False positives |
|---|---|---|---|---|
| Baseline (deterministic only) | 1.00 | 0.264 | 0.418 | 0 |
| LLM Guard | 0.962 | 0.943 | 0.952 | 2 |
| Pytector | 1.00 | 0.679 | 0.809 | 0 |
| Hybrid (deterministic + Pytector fallback) | 1.00 | 0.736 | 0.848 | 0 |

The deterministic-only baseline has perfect precision but weak recall — it catches only what is already on its known-phrase list. Layering Pytector as a fallback classifier raises recall from 0.264 to 0.736 with zero false positives, a difference confirmed statistically significant by a paired McNemar test (p < 0.001) and the only one of six pairwise comparisons run on this data that survives Holm-Bonferroni correction for testing multiple comparisons on overlapping predictions. LLM Guard shows a numerically higher raw recall, but that difference does not survive the same correction, so we do not claim it as a proven advantage.

### D. Concurrency benchmark: multiprocessing

To characterize how the full pipeline's throughput behaves under concurrent load, we benchmarked multiprocessing across 1, 2, and 4 worker processes, each repeat run as a genuinely independent subprocess (rather than looped inside one long-running process, which can let OS scheduler and allocator state carry over between repeats and mask the true per-process cost).

**Table IV.** Multiprocessing throughput, fresh-process repeats (n = 3 repeats per configuration)

| Workload | Workers | Throughput (alerts/sec, mean ± stdev) |
|---|---|---|
| Guardrail-only | 1 | 648,379 ± 41,175 |
| Guardrail-only | 2 | 309 ± 2 |
| Guardrail-only | 4 | 230 ± 1 |
| Full pipeline (real Groq calls) | 1 | 0.896 ± 0.037 |
| Full pipeline (real Groq calls) | 2 | 0.333 ± 0.006 |
| Full pipeline (real Groq calls) | 4 | 0.273 ± 0.017 |

Multiprocessing throughput falls as worker count increases at every scale tested — a 70% drop on the full pipeline from one worker to four. This is not I/O contention; it is the structural cost of multiprocessing itself: each additional process must reload the guardrail's local models from scratch and re-establish its own network client, a fixed per-process cost that has no offsetting benefit when the workload's actual bottleneck is a single network round-trip per alert, not CPU work that could be spread across cores. The guardrail-only workload shows the same direction even more sharply, since pool-management and process-startup overhead dominates completely once the work being parallelized is microsecond-scale. For contrast, the same full-pipeline workload under threading instead of multiprocessing improves with more workers (measured separately, not the focus of this paper), because threads share one process and one network client and the GIL releases during the network wait — the opposite structural situation from multiprocessing. The practical implication for deployment is direct: this guardrail pipeline should be scaled with threads or async I/O, not worker processes.

---

## V. Discussion

**What REAL_AND_PLAUSIBLE means in practice.** The central argument of this paper is that a citation which is real and topically plausible is the hardest case for a human reviewer to catch, not the easiest, because it looks correct. Section IV-B is not a hypothetical illustration of this — the Log4Shell case is a real, observed instance of the model producing an accurate CVE number that the alert itself never supplied, caught only because the guardrail checks evidence rather than trusting confidence. The taxonomy's unconditional review-flag policy (Section III-D) exists specifically because an earlier version of this pipeline got this wrong, treating a real, correct-looking citation as self-evidently safe.

**Limitations.** The CVE-bait test set, at n = 150, is large enough to support a legitimate confidence interval on the ungrounded rate, but both observed ungrounded citations occurred on two of the most famous vulnerabilities in the set (Log4Shell, Follina); the 125 less-prominent CVEs added in later expansions of the test set produced no citations to analyze at all. The honest claim this evaluation supports is "rarely induces spontaneous citation, and correctly classifies it on famous cases when it does happen," not "stress-tested against obscure-CVE hallucination" — a claim this test set cannot make. The report-generation backend throughout this evaluation is a single, relatively small model (`openai/gpt-oss-20b`); whether the same near-zero spontaneous-fabrication rate holds for larger or differently-trained models is untested here. Finally, Stage 2 verification depends on NVD's public API being reachable and responsive at evaluation time; a citation that cannot be verified is classified UNVERIFIED rather than assumed safe, but this makes the pipeline's Stage 2 behavior a function of a live external dependency rather than a fixed, offline-reproducible lookup, unlike Stage 1's grounding check.

**Future work.** The taxonomy and two-stage pattern in this paper are not intrinsically specific to CVE identifiers — the same grounding-then-verify structure applies to any technical claim type with a structured, authoritative source to verify against, most directly MITRE ATT&CK [18] technique identifiers, and less directly other fabricatable claims such as named threat actors or malware family names, where authoritative sources are more heterogeneous. Extending the taxonomy to a second claim type would also test whether the REAL_AND_PLAUSIBLE failure mode observed here for CVEs is a general property of how LLMs recall real technical identifiers from training data, or specific to the CVE domain's particular density of public documentation. A second natural extension is retrieval-based CVE *identification* — matching a described exploit behavior against a corpus of real CVEs to suggest an identifier the model was never given, rather than only verifying identifiers the model already produced on its own.

---

## VI. Conclusion

This paper presented a two-stage output guardrail that grounds CVE citations in LLM-generated SOC reports against the alert's own evidence, verifying ungrounded citations live against NVD and classifying each into one of four outcomes rather than a single flagged/not-flagged label. The taxonomy's central case, REAL_AND_PLAUSIBLE, names a real, specific risk: a citation that is factually correct and topically appropriate but was never actually supported by the alert's evidence, which is precisely the citation a human reviewer is least likely to question. Adversarial testing on a 150-alert set confirmed the guardrail never spontaneously fabricates a citation on symptom-only alerts, and correctly classified both ungrounded citations observed when the model was explicitly pressed for an identifier it was not given — including one factually correct-but-ungrounded case and one real-but-wrong-neighbor case, the two failure modes this taxonomy exists to distinguish. Supporting evaluation showed the surrounding pipeline holds up under two further, independent tests: a statistically significant improvement in the input guardrail's recall from adding a local classifier fallback, and a concurrency benchmark showing the full pipeline should be scaled with threads rather than worker processes. Generalizing this taxonomy beyond CVE identifiers to other structured, verifiable technical claims is the most direct next step.

---

## References

1. Zhan, Q., Liang, Z., Ying, Z., Kang, D. InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents. Findings of the Association for Computational Linguistics: ACL 2024.
2. Manakul, P., Liusie, A., Gales, M. SelfCheckGPT: Zero-Resource Black-Box Hallucination Detection for Generative Large Language Models. EMNLP, 2023.
3. Min, S., Krishna, K., Lyu, X., Lewis, M., Yih, W., Koh, P.W., Iyyer, M., Zettlemoyer, L., Hajishirzi, H. FActScore: Fine-grained Atomic Evaluation of Factual Precision in Long Form Text Generation. EMNLP, 2023.
4. Rebedea, T., Dinu, R., et al. NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails. NVIDIA, 2023.
5. Wallace, E., Xiao, K., Leike, R., Weng, L., Heidecke, J., Beutel, A. The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions. arXiv preprint (OpenAI), 2024.
6. Zheng, L., Chiang, W., Sheng, Y., Zhuang, S., Wu, Z., Zhuang, Y., Lin, Z., Li, Z., Li, D., Xing, E.P., Zhang, H., Gonzalez, J.E., Stoica, I. Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena. NeurIPS Datasets and Benchmarks Track, 2023.
7. Huang, L. et al. A Survey on Hallucination in Large Language Models: Principles, Taxonomy, Challenges, and Open Questions. arXiv, 2024.
8. Srinivas, S., Kirk, B., Zendejas, J., Espino, M., Boskovich, M., Bari, A., Dajani, K., Alzahrani, N. AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation. Journal of Cybersecurity and Privacy, 5(4), 95, 2025.
9. Shen, X., Chen, Z., Backes, M., Shen, Y., Zhang, Y. "Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models. ACM CCS, 2024.
10. deepset. prompt-injections dataset. Hugging Face, Apache-2.0, 2023.
11. Protect AI. LLM Guard. GitHub, ongoing.
12. Pytector. GitHub, ongoing.
13. Guardrails AI. Guardrails: an open-source Python package for specifying structure and validating the outputs of LLMs. GitHub, ongoing.
14. Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP, 2018, pp. 108-116.
15. Goldschmidt, P., Chudá, D. Network Intrusion Datasets: A Survey, Limitations, and Recommendations. Computers & Security, 156, 2025.
16. NIST. National Vulnerability Database. nvd.nist.gov, ongoing.
17. Groq. LPU Inference Engine. groq.com, ongoing.
18. MITRE ATT&CK. attack.mitre.org, ongoing.
19. Microsoft. Security Copilot. microsoft.com, ongoing.
20. Google Cloud. Gemini for Security / Chronicle. cloud.google.com, ongoing.
21. IBM. QRadar Advisor with Watson. ibm.com, ongoing.
22. MITRE Engenuity Center for Threat-Informed Defense. TRAM: Threat Report ATT&CK Mapper. v1 2021, LLM-based update 2023.

---

## Appendix: mapping this draft back to the codebase

| Section | Code / data |
|---|---|
| III-B Evidence Pack | `src/guardrails/evidence_pack.py` |
| III-C, III-D Output guardrail, CVE grounding + taxonomy | `src/guardrails/output_guardrail.py` |
| III-F Input guardrail | `src/guardrails/input_guardrail.py` |
| IV-B CVE-bait test | `experiments/evaluation/cve_bait_alerts.py`, `experiments/results/cve_bait_results.json` |
| IV-C Input guardrail comparison | `experiments/evaluation/guardrail_comparison/`, `experiments/results/guardrail_comparison.json`, `experiments/results/guardrail_comparison_significance.json` |
| IV-D Multiprocessing benchmark | `experiments/evaluation/fresh_process_benchmark.py`, `experiments/results/fresh_process_benchmark_results.json` |
