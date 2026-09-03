# R4 · Human Validation: 2-Annotator Cohen's κ + ATT&CK Relevance Classifier
- **Labels:** research, priority:P1, figures/tables, blocked:annotator-time
- **Milestone:** M3 — Methodological Credibility
- **Acceptance items:** 10

---

## Summary
The manuscript's §4.6 reports **92.5% accuracy of the relevance classifier** on 80 human-labeled (alert evidence, NVD CVE description) pairs. The manuscript's own **Threats-to-Validity (lines 987–993)** honestly flags this as a single-annotator dataset with no inter-rater agreement statistic. **Any reviewer who checks the methodology will write a comment like: "How do we know these labels are not the single annotator's bias?"** 

Additionally, the manuscript's BoW-stem relevance classifier is used identically for ATT&CK technique descriptions (not just CVE NVD descriptions), but zero standalone ATT&CK validation of that threshold exists. This issue adds that.

---

## Part A · CVE Relevance Set (expand 80 → ≥ 100; double-annotate 100% of them)
### Task A.1 — Expand if needed (optional if annotator budget is abundant)
File: `experiments/evaluation/relevance_classifier_validation/build_cve_pairs.py`
- Current: 80 (alert-evidence, NVD-text) pairs, balanced 40:40 relevant/irrelevant.
- Expand to 100 pairs (20 new pairs: 10 relevant / 10 irrelevant) if time allows. If annotator time is tight, **keep 80 and double-annotate 80/80**. Do not go below 80.
- Every pair: supply BOTH the alert evidence (raw text snippet OR payload) AND the NVD description. **Anonymize the CVE-ID so the annotator does not see the actual identifier headline (e.g. "Follina"), only the description prose.** This prevents lexical leakage via the famous-name shortcut.

### Task A.2 — CSV format
Columns:
```
pair_id, alert_id, evidence_snippet_anonymized, nvd_description_text, [TIE_BREAK COLUMN HIDDEN FROM ANNOTATORS], annotator1_label, annotator2_label, resolved_final_label
```
- `annotator1_label` and `annotator2_label` are filled by the two people INDEPENDENTLY on separate CSV copies.
- DO NOT share one annotator's work with the other during blind annotation pass.
- Disagreements: supervisor or third-person tie-breaker → `resolved_final_label`. Document disagreements: save `disagreements_cve.csv` listing pair_id, annotator1, annotator2, reason (one sentence) for qualitative discussion.

### Task A.3 — Compute stats
- Run `compute_cohen_kappa.py` (write one simple file using `sklearn.metrics.cohen_kappa_score` + 95% CI bootstrap implementation — 1000 bootstrap resamples.)
  - Report: **% observed agreement**, **Cohen's κ**, **95% CI (bootstrap)**.
  - Report 3 sub-κ if ≥ 20 disagreements: split by (relevant-class / irrelevant-class / mixed threshold). Usually not needed with n<20 disagreements.
- Compute pipeline's relevance classifier performance **against `resolved_final_label` NOT annotator1** — this matters. Report: accuracy, P, R, F1, Wilson 95% CI.

- [ ] **AC1:** 80–100 CVE pairs double-annotated; 2 independent CSV files committed.
- [ ] **AC2:** Disagreement file `disagreements_cve.csv` committed.
- [ ] **AC3:** Cohen's κ + 95% CI reported in results JSON AND manuscript §4.6.
- [ ] **AC4:** Pipeline P/R/F1 vs resolved-final-label reported (new, replaces current raw 92.5% if they differ; keep old number in prose if close).

---

## Part B · NEW — ATT&CK Relevance Validation (80–120 pairs)
### Task B.1 — Build ATT&CK pair set
File: `experiments/evaluation/relevance_classifier_validation/build_attack_pairs.py`

MITRE ATT&CK descriptions are structurally **shorter, more terse, and more code-name-rich (e.g., "Pass the Ticket", "Golden Ticket")** than NVD prose. It is plausible the same 0.15 BoW threshold that works for 200–600-word NVD CVEs will be too low for 30–100-word ATT&CK technique text.

Build 80–120 pairs:
- Columns same as CVE above, but replace nvd_description → `mitre_attack_technique_description` (from the versioned STIX snapshot SHA already in paper §4.1).
- Balance 40 relevant / 40 irrelevant minimum (80 total). Add 20 edge-case borderline pairs if budget allows:
  - Edge case 1: Alert mentions "Kerberos ticket" vs technique T1558.001 Golden Ticket description mentions "Kerberos ticket-granting-ticket".
  - Edge case 2: Alert mentions "Microsoft Office malicious document" vs technique T1204.002 User Execution Malicious File.
  - Edge case 3: Technique description is a short revoked ID (REVOKED branch → pairs are trivially irrelevant on taxonomy grounds, but the relevance classifier runs BEFORE revocation check — test this.)
- Anonymize: do NOT include technique name/ID string in evidence snippet for withheld cases (same leakage rule).

### Task B.2 — Double-Annotate + Stats on ATT&CK
Exact same workflow as A.2–A.3.

- [ ] **AC5:** 80–120 ATT&CK (alert-evidence, technique-description) pairs built & committed.
- [ ] **AC6:** Double-annotated blind; disagreements ≤ 15% tie-broken; disagreement CSV committed.
- [ ] **AC7:** Cohen's κ for ATT&CK side reported with 95% CI.
- [ ] **AC8:** Pipeline relevance classifier performance on ATT&CK at current 0.15 threshold reported (accuracy, F1, Wilson 95% CI). If F1 drops below 0.80 **DO NOT RETUNE the threshold to optimize this dataset — that's dataset leakage.** Instead write honestly in §5 Limitations: "ATT&CK relevance F1=0.XX at the CVE-calibrated threshold; retuning on ATT&CK-specific corpus (separate set) is future work." or you can try it now if time permits.

---

## Part C · Manuscript updates
### §4.6 (currently single-rater) rewrite
Template wording:
> *"Relevance judgements were produced by two independent human annotators working blind to each other's labels on n = XX CVE (alert, CVE-description) pairs and n = YY ATT&CK (alert, technique-description) pairs. Inter-rater agreement was Cohen's κ = 0.XX, 95% CI [0.YY, 0.ZZ] on the CVE set, and κ = 0.AA, 95% CI [0.BB, 0.CC] on the ATT&CK set. Disagreements were resolved by a third rater tie-breaker; final resolved labels were used for evaluation of the pipeline's bag-of-words stemmed overlap classifier at its CVE-calibrated threshold of t = 0.15. Disagreement analysis is provided in the supplement: disagreements clustered at the boundary overlap score 0.10–0.20 consistent with threshold-ambiguity noise rather than systematic annotator drift."*

### §5 Threats-to-Validity UPDATE
- **DELETE the current bullet that says "Single annotator, no κ."** Replace it with the new honest limitation:
  > *"Relevance annotation was performed by two raters. We cannot rule out residual shared-bias drift between the two annotators; a fully independent 3-labeller cross-site replication would strengthen this. Additionally, the 0.15 threshold for the classifier was calibrated only on CVE pairs, so ATT&CK performance is measured on a held-out test of the same calibrated threshold, not re-tuned."*

- [ ] **AC9:** §4.6 rewritten with actual numbers from A + B.
- [ ] **AC10:** §5 Threats-to-Validity updated → old single-rater limitation DELETED, replaced with calibrated-threshold + shared-bias honesty.

---

## Risks & Mitigations
- **Annotator time unavailable (you can't find 2nd annotator):** Degrade to "single annotator + 20% blind cross-check by supervisor". Report κ with n=0.2×N bootstrap. This is weaker than true 2-annotator but still better than nothing.
- **ATT&CK κ low (<0.65):** Do not rush to expand dataset. Add honestly to §5: "Inter-rater agreement on ATT&CK pairs was κ = 0.XX < CVE κ = 0.YY, consistent with the terse technique descriptions increasing classification ambiguity for humans as well." This is a defensible finding, not a bug.

---