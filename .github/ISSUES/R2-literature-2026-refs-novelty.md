# R2 · Literature 2026 Pass + Resolve Dangling `[?]` Refs + Sharpen Novelty Paragraph
- **Labels:** manuscript, research, priority:P0
- **Milestone:** M1 — Freeze Desk-Reject Risks
- **Acceptance criteria:** 8 items, all must pass

---

## Summary
The rendered PDF contains **two unresolved `[?]` BibTeX placeholders** in §2 Related Work. Any IJIS/SNCS editor does a first-pass triage and will **desk-reject on the spot** if any reference fails to resolve to a numbered citation. Separately, the literature coverage stops at 2025; two 2026 conference publications directly on the topic of hallucination detection exist and must be cited + carefully distinguished (not merely added to bibliography). The novelty paragraph in §1 must be sharpened so the manuscript's precise claim does not accidentally conflate "factual existence in an ontology" with "evidential grounding in the specific alert evidence" — a distinction a careful reviewer will attack if muddy.

---

## Task 1 — RESOLVE DANGLING `[?]` CITATIONS


### Verification

- [ ] **AC1:** Zero `[?]` markers anywhere in rendered PDF; new entries present numerically in references list with valid DOIs.

---

## Task 2 — ADD THREE NEW 2026 REFERENCES (cite + distinguish)
Add these three **new BibTeX entries** (you must find and verify actual papers):

### 2a. 2026 IEEE Conference — general cyber hallucination cross/self-verification
Search paper title: **Empirical Evaluation of Self and Cross-Model Verification for LLM Hallucination Detection in Cybersecurity** (≈ 736 human labels, Fleiss κ = 0.79 reported, cross-model outperforms self-model judges).
- Add `@inproceedings{ieee_2026_cross_self_verif_cyber ...}` BibTeX entry.
- Distinguish in Related Work §2, 1 paragraph:
  > *"Closely related is IEEE-2026's cross/self-verification benchmark [ieee_2026_cross_self_verif_cyber] on 736 human-annotated general cybersecurity LLM outputs. LLMCite differs in three key ways: (1) it targets structured CVE/MITRE ATT&CK identifier hallucinations rather than free-form factual claims; (2) its verification anchors to authoritative per-identifier ontologies (NVD + MITRE STIX Enterprise) rather than a generic human-verified-corpus; and (3) it defines and empirically measures the REAL_AND_PLAUSIBLE ungrounded-citation class [refs to §3.3 taxonomy] which prior cross-verification benchmarks collapse with general hallucinations."*

### 2b. Findings of ACL 2026 — Evidence-Aligned Entity Verification for Hallucination in RAG
Find the actual 2026 Findings ACL paper on entity-verification-in-RAG. BibTeX entry key `acl_findings_2026_entity_verif_rag`.
- Distinguish §2 paragraph:
  > *"Evidence-aligned entity verification in retrieval-augmented generation (Findings ACL 2026 [acl_findings_2026_entity_verif_rag]) provides a general method for grounding entities to retrieved documents. LLMCite does not operate over retrieved corpus-snippets; it verifies two specific citation-shape identifiers (CVE, ATT&CK technique) against domain-authoritative ontology APIs, and its FABRICATED vs REAL_AND_PLAUSIBLE distinction (§3.3) does not arise in generic RAG entity-grounding because REAL_AND_PLAUSIBLE requires the cited entity to genuinely exist *outside* the supplied evidence."*

### 2c. 2026 Systematic Review of 300+ LLM-in-Cybersecurity Works
Locate a 2026 survey with DOI. Entry key `survey_2026_300_llm_cyber`.
- One short positioning paragraph in §1 Introduction:
  > *"A 2026 systematic review of 300+ LLM-applied-to-cybersecurity works [survey_2026_300_llm_cyber] finds less than 4% of published manuscripts include grounded verification of the factual provenance of LLM outputs; LLMCite directly addresses this gap."*

- [ ] **AC3:** Three new BibTeX entries present, all with real, verifiable DOIs.
- [ ] **AC4:** Two explicit distinction paragraphs written in §2 (IEEE + ACL) + one positioning sentence in §1 (survey).

---

## Task 3 — SHARPEN THE NOVELTY PARAGRAPH in §1
In `sn-article.tex`, find the current 66–87 line novelty/contribution paragraph that begins roughly with the "We present LLMCite …" sentences. **REPLACE the muddy novelty sentence block with the exact following wording** (adjust references only):

> *"Our claim to contribution is not that we invented citation-grounded verification as a general principle — FActScore [Min+ EMNLP 2023], InjecAgent [ACL Findings 2024], and others have established that domain [ieee_2026_cross_self_verif_cyber, acl_findings_2026_entity_verif_rag]. LLMCite's contribution is domain-specialized for cybersecurity SOC analyst reports and empirically precise: we separate (i) evidential support within the supplied alert evidence, (ii) authoritative existence in per-identifier reference ontologies, (iii) topical relevance between the alert's evidence-text and the ontology's description of the cited identifier, and (iv) withdrawn/deprecated status (CVE REJECTED / ATT&CK REVOKED), into a 5-tier cascaded classification that is amenable to statistical test, and demonstrate across two independent LLM families that REAL_AND_PLAUSIBLE citations — genuine, relevant, ontology-confirmed identifiers that were never stated in the specific alert — form a reproducible failure mode for self-consistency hallucination detection."*

Then ensure that Contribution #1 through Contribution #3 in the enumerated contribution list are hierarchically organized with Contribution #1 (empirical finding = SelfCheckGPT blind spot) FIRST, then Contribution #2 (pipeline), then Contribution #3 (5 tier + releases). Do NOT list "ablation" as a standalone contribution; ablation supports #2.

- [ ] **AC5:** Novelties paragraph matches sharpening wording above; contributions list ordered empirical-first.
- [ ] **AC6:** No sentence in manuscript now reads as if LLMCite invented external factual verification (FActScore precedence is stated).
- [ ] **AC7:** No sentence conflates "exists in NVD/MITRE" with "grounded in this specific alert's evidence" — the distinction is explicit.

---

## Final Acceptance (8 boxes total)
- [ ] AC1: 0 `[?]` placeholders in rendered PDF
- [ ] AC2: 0 undefined-citation warnings in BibTeX log
- [ ] AC3: 3 new 2026 BibTeX entries with real DOIs
- [ ] AC4: Distinction paragraphs written (2 in §2, 1 positioning in §1)
- [ ] AC5: Novelty paragraph sharpened, contributions list ordered
- [ ] AC6: FActScore precedence explicitly credited (no overclaim)
- [ ] AC7: Existence vs evidence-grounding distinction is textually unambiguous everywhere in §1, §3, §4.4, §5
- [ ] AC8: Rendered full PDF post-update has no broken formatting introduced by the edits (section headings correct, references numbered [1]-[24], tables captions still aligned).

---