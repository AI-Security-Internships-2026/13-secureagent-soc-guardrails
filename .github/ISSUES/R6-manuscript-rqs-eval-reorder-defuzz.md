# R6 · Manuscript Restructure: Explicit RQs + Evaluation Reordering + De-fluff
- **Labels:** manuscript, priority:P2, figures/tables
- **Milestone:** M5 — Manuscript Polish & Submission
- **Acceptance items:** 6

---

## Summary
IJIS/SNCS reviewers look for **(a) explicit research questions** and **(b) a clear separation of headline scientific findings from supporting engineering validations**. The current draft mixes these: §4.10 is "Supporting evaluation" (already correct grouping) but the ordering within §4 is suboptimal, and no explicit RQ list appears in §1. 

---

## Task 1 — Add 4 Explicit Research Questions after §1 Contributions
In `docs/paper/sn-article.tex`, right AFTER the enumerated Contribution list (usually §1, ~line 100 of draft), add a `\subsection{Research Questions}` subsubsection with exactly these four RQs (only wording polish allowed, do NOT add RQ5 unless a new central finding exists at the time you do this):

> **RQ1.** Can authoritative evidence-grounding — anchored to per-identifier domain ontologies rather than general factuality — distinguish between grounded, fabricated, irrelevant-to-alert, and real-but-unsupported CVE and MITRE ATT&CK citations in LLM-generated SOC analyst reports?
>
> **RQ2.** Does grounded-verification (LLMCite) detect unsupported citations more reliably than sampling-based self-consistency (SelfCheckGPT) on the same paired examples?
>
> **RQ3.** Does any observed performance gap between grounded-verification and self-consistency generalize **both** across LLM generator families (openai/gpt-oss-20b vs qwen/qwen3.6-27b) **and** across citation families (CVE vs MITRE ATT&CK)? — *Note: ATT&CK side depends on completing Issue R1. If R1 is still open at manuscript-polish time, split RQ3 into two sentences and state honestly: "LLM-family generalization is fully tested; citation-family generalization on ATT&CK is tested via bait-eval implementation."*
>
> **RQ4.** How do individual pipeline stages (input guardrail, CVE checker, ATT&CK checker, PII redaction) individually affect detection outcomes and operational latency? — *Note: depends on Issue R3 (ablation) being complete. If R3 is pending, write: "Ablation supports this RQ via the 6-config decomposition; Phase 2 schema parity is complete, Phase 3 evaluation is [pending / complete]."*

Then, in EVERY evaluation subsection (§4.2 through §4.10), add a **first sentence** that reads:
> *"This subsection addresses RQx."*

Example §4.4 first line: "This subsection addresses RQ2."

- [ ] **AC1:** 4 RQs appear verbatim (or near-verbatim with status annotations for open issues) in §1 after Contributions.
- [ ] **AC2:** Every §4 subsection opens with an explicit "This subsection addresses RQx." sentence.

---

## Task 2 — Reorder §4 Evaluation Subsections
### CURRENT ORDER (in paper draft)
4.1 Setup
4.2 CVE bait (150)
4.3 ATT&CK bait (150)
4.4 SelfCheckGPT (56)
4.5 McNemar + cross-family p=0.0118 / p≈2e-7
4.6 Relevance classifier (80 pairs)
4.7 CVE pool (60)
4.8 Wazuh (139)
4.9 Cross-source pooled (575)
4.10 Supporting (input rail / LLM-judge / PII / concurrency)

### PROPOSED NEW ORDER
4.1 Setup
4.2 CVE bait eval (150) — RQ1
4.3 ATT&CK bait eval (150) — RQ1
4.4 SelfCheckGPT comparison — RQ2
4.5 McNemar significance + cross-family generalization (including ATT&CK-side from R1 if completed) — RQ2 + RQ3
4.6 Relevance classifier validation — RQ1 (topical-relevance component)
4.7 **Third-party (Secure_SOC_AI 76) + Wazuh SIEM real-world (139)** merged into ONE combined §4.7 "Real-world Deployment Validation" subsection
4.8 Ablation (Table T6 + Figure F3 + F4) — RQ4
4.9 **Pooled cross-source summary (575)** as §4.9 — synthesizes everything into the headline 0% non-adversarial + X% adversarial cumulative number
4.10 Supporting Engineering Evaluations
  - 4.10.1 Input Guardrail (Table 5 + 6 Holm-Bonf)
  - 4.10.2 LLM-as-judge feasibility
  - 4.10.3 PII redaction evaluation
  - 4.10.4 Concurrency benchmark + honest discrepancy (Table 7)

**Why this reorder?** It follows RQ-logic: RQ1 (bait + relevance) → RQ2 (selfcheck) → RQ3 (generalize) → deployment realism → RQ4 (ablation) → pooled summary, and THEN supporting engineering.

### Merge §4.7 (CVE pool 60) INTO either §4.2 or §4.6
CVE pool 60 is a supporting experiment, not a scientific-heading one. It fits better under §4.2 CVE bait (extension) OR §4.6 relevance (threshold sanity check). Move Table 4 with it. Keep §4.9 for the 575 true-pooled cross-source number which is the cumulative synthesis.

- [ ] **AC3:** Evaluation reorder matches PROPOSED above. Section numbering in TOC in PDF is correct. No floating references broke (if they did, recompile with `\ref{}` correct).
- [ ] **AC4:** §4.7 now has both Secure_SOC_AI 76 + Wazuh 139 merged. Table 4 moved with CVE pool to its new home.

---

## Task 3 — Delete ALL remaining `[NOT YET RUN]` / `TODO` / `ablation pending` markers
Do NOT leave vague placeholder text in a submitted manuscript. Either:
- The experiment completed → replace with real numbers.
- The experiment is still running → describe status as of the paper-v1.0 tag HONESTLY, e.g.:
  > *"Ablation schema-parity smoke-tests (2 alerts × 6 configs) are complete as of paper-v1.0; Phase 3 evaluation over the full 479-alert pool was ongoing at submission time and committed result JSONs with their timestamp will be linked from the GitHub repository tag."*


- [ ] **AC5:** Grep of `sn-article.tex` for keywords: `NOT YET RUN`, `TODO`, `FIXME`, `PENDING` — returns **zero lines**. (Case-insensitive grep.)

---

## Task 4 — (if R2 already completed the novelty sharpening)
Verify that R2's sharpened novelty paragraph still reads correctly AFTER this restructure — you may need to adjust one sentence in §1 to make the RQ list reference it smoothly. Do not re-sharpen the paragraph here (it belongs in R2).

- [ ] **AC6:** RQ list references Contribution #1 / #2 / #3 cleanly. No duplicated text.

---
