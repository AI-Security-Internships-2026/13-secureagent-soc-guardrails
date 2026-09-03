# R1 · ATT&CK SelfCheckGPT + McNemar Replication (Both Families)
- **Labels:** research, priority:P0
- **Milestone:** M2 — Close the Central Scientific Gap
- **Acceptance tests in code:** [ ] 6, [ ] 5 total

---

## Summary
The paper's **one central finding** (SelfCheckGPT self-consistency checking is structurally blind to REAL_AND_PLAUSIBLE citations) is currently validated **only on CVE identifiers** (§4.4–4.5). The manuscript's own Limitations section explicitly flags this asymmetry. The taxonomy and pipeline claim to generalize across two citation families — CVE **and** MITRE ATT&CK. The bait evaluation and the deterministic checker do, but the headline SelfCheckGPT vs Deterministic comparison does not. This issue closes that gap by mirroring the existing CVE-pool experimental design on ATT&CK.

---

## Motivation (cited from 3 independent reviews)
- **After-reading-draft-paper review §8:** *"ATT&CK is a pipeline-implemented equal, yet headline-stat comparison is CVE-only — must replicate."*
- **Eman.docx external review §43 Limitation #5:** *"Statistically significant SelfCheckGPT gap is … per paper's own text, CVE-side only."*
- **Supervisor analysis D4 / N2:** ATT&CK revoked-T1076 example is a genuine 5th-tier case the taxonomy catches; headline test should include it.

---

## Concrete Tasks

### Task 1 — Build 60-item ATT&CK pool
- File: `experiments/evaluation/attack_bait_pool.py`
- Mirror layout of the CVE 60 pool exactly:
  - 30 **STATED** items: MITRE ATT&CK technique ID (e.g. T1110.001) **genuinely appears** in the supplied alert evidence snippet.
  - 30 **WITHHELD** items: alert evidence is about a well-known technique (e.g. pass-the-hash → T1550.002) but **the technique ID string is never spelled out** anywhere in the alert/payload text.
- **Leakage guard:** Double-check no prompt string contains the withheld technique ID or its human name as a string literal (case-insensitive) outside of the LLM-only answer field.
- **Deprecation coverage:** Include ≥ 3 **REVOKED technique IDs** (per T1076 case paper already flags as a 5th-tier classification) to exercise the REVOKED branch end-to-end.
- Commit result as `experiments/results/attack_bait_pool_60.json`.

### Task 2 — openai/gpt-oss-20b paired run
- Run on the same 60 ATT&CK items:
  - (a) `selfcheckgpt_test.py` → t=0.7, 3 resamples per item. Produces hallucination verdicts per SelfCheckGPT.
  - (b) Fresh deterministic checker run via `selfcheckgpt_significance_test.py` (do NOT reuse bait-test ground-truth labels as a proxy for the checker's verdict — run the actual pipeline; paper §4.5 explicitly warns against label-leakage on CVE side and the same warning applies here).
- Produces 4-cell discordant matrix: **(both correct, LLMCite-only, SelfCheck-only, both wrong)** on 60 pairs.
- Commit: `experiments/results/selfcheckgpt_vs_deterministic_mcnemar_ATTACK_gpt-oss-20b.json`

### Task 3 — qwen/qwen3.6-27b paired run
- Repeat Task 2 **on exactly the same 60 ATT&CK items** (item order preserved, no new examples) with `GENERATOR_MODEL=qwen/qwen3.6-27b`.
- Commit: `experiments/results/selfcheckgpt_vs_deterministic_mcnemar_ATTACK_qwen3.6-27b.json`

### Task 4 — McNemar statistics
- Reuse existing `selfcheckgpt_significance_test.py` McNemar implementation (exact binomial already implemented) to produce p-value per family.
- Add two new columns to the result JSONs (existing CVE-side runs will also get these in R6a):
  - `cohens_g`  = (b − c) / (b + c)
  - `odds_ratio_95ci_low`, `odds_ratio_point`, `odds_ratio_95ci_high` = Wilson-score CI around b/c.
- Commit stats outputs.

### Task 5 — Incorporate into manuscript
**Manuscript edits (in `docs/paper/sn-article.tex`):**
- **Table 3** (SelfCheckGPT by class): Add ATT&CK-side rows below existing CVE rows — two blocks (gpt-oss-20b ATT&CK, qwen ATT&CK), each with the same 5-tier column layout.
- **Table McNemar §4.5** (Holm-Bonferroni corrected p): Add 2 rows for ATT&CK per model-family.
- **Fig. 1** (class-bar stacked): Add a 3rd panel "ATT&CK — gpt-oss-20b" (add qwen as 4th panel if space permits; move qwen-side to supplement under page budget).
- **Abstract / §1 contributions:** If the ATT&CK p-value is significant (p < 0.05 after Holm-Bonf 4-way: CVE×2 + ATT&CK×2), change wording from "across two generator families" to "across two generator families **and two citation families**". If not significant, keep wording as-is and discuss why in §5 Limitations / Threats to Validity.
- **§5 Limitations line 929–935:** STRIKETHROUGH/DELETE that limitation bullet if ATT&CK replication is significant. Keep and strengthen with "ATT&CK side now also …" if only directional.

---

## Acceptance Criteria

- [ ] 60-item ATT&CK pool (30 stated / 30 withheld) committed. Leakage audit passed (grep for technique-ID literals in prompt yields only expected STATED matches).
- [ ] ≥ 3 REVOKED technique IDs represented in the pool.
- [ ] openai/gpt-oss-20b: 3-resample SelfCheckGPT + fresh deterministic verdict on all 60 ATT&CK items. JSON committed.
- [ ] qwen/qwen3.6-27b: Same paired run on same 60 items. JSON committed.
- [ ] McNemar p-values, Cohen's g, Odds Ratio + 95% CI reported for both families. JSON stats + numbers in prose.
- [ ] Table 3 expanded with ATT&CK rows. Fig. 1 expanded with ATT&CK panel(s).
- [ ] Manuscript limitation about CVE-only statistically-confirmed gap either DELETED (if sig) or UPDATED with ATT&CK directional finding (if not).

---

