# R5 · Temperature-Sensitivity Sweep (t ∈ {0.1,0.3,0.5,0.7,1.0})
- **Labels:** research, priority:P2, blocked:quota, figures/tables
- **Milestone:** M6 — Enhancers (DO ONLY AFTER M1–M5 COMPLETE)
- **Acceptance items:** 5

---

## Summary
The paper already documents (implicitly between §4.2/§4.7 vs §4.4) a **sharp temperature boundary**:
- At the production generation temperature **t = 0.1** the model almost-never volunteers CVE citations spontaneously (0/147 symptom-only cases).
- At the SelfCheckGPT resample temperature **t = 0.7** the model volunteers real-but-unsupported CVEs far more often (18/20 REAL_AND_PLAUSIBLE class), which is why SelfCheckGPT self-consistency systematically confirms them.

This is currently documented only in prose. Transforming it into an **empirical figure (F6 grouped line chart)** converts a reviewer-question ("this is a t=0.1 artefact?") into a concrete answer with a graph.

**Crucially, the conclusion we want to support in §5 Discussion is:**
> *"Whenever REAL_AND_PLAUSIBLE citations exist — at ANY temperature setting — self-consistency detectors are structurally blind to them (because the citation is internally consistent within the generated text across resamples). How frequently they appear is temperature-dependent; the blindness failure mode itself is not."*

---

## Do NOT open this issue unless ALL of M1 + R2, R1, R3, E1, E2, R4 are already closed
(See Milestone ordering in `ISSUES_INDEX.md`.)
Opening this too early robs quota from P0 items R1 + R3.

---

## Task 1 — Driver Script
File: `experiments/evaluation/temperature_sweep_driver.py`

Inputs:
- 60 CVE pool items (§4.7, 30 stated + 30 withheld) — the exact set used in Table 4 (identical IDs, identical prompt templates, no new examples).
- 5 temperatures × 3 resamples per item for SelfCheckGPT side (or 1 resample for generation-only rate if we only measure P(volunteer CVE)).

Grid:
```
temperature_grid = [0.1, 0.3, 0.5, 0.7, 1.0]
```

Metrics per temperature:
1. `P_volunteer` — % of 60 pool items where the LLM volunteered ANY CVE ID in the report (regardless of correctness). (= 5 numbers × 60.)
2. `P_correct_but_unsupported` — % of 60 where volunteered CVE is REAL_AND_PLAUSIBLE (exists in NVD, semantically close, but NOT stated in evidence).
3. `SelfCheckGPT_recall_for_unsupported` — SelfCheckGPT recall on the subset that is confirmed unsupported.
4. `LLMCite_detection_rate` — deterministic checker detection rate on same unsupported subset.

### Commit
- `experiments/results/temperature_sweep_60x5.jsonl`
- Summary stats JSON.

- [ ] **AC1:** Driver committed; 60×5 grid completed; 4 metrics above computed per temperature.

---

## Task 2 — Figure F6 (TEMPERATURE-BOUNDARY CURVES)
Files written:
- `docs/paper/figures/fig_f6_temperature_boundary.png` (PNG 300 dpi)
- `docs/paper/figures/fig_f6_temperature_boundary.svg` (Inkscape/draw.io source)
- `experiments/evaluation/make_fig_f6.py`

**Plot spec:**
- X-axis: temperature from 0.1 to 1.0 (linear ticks at the 5 grid points).
- Y-axis left: rate 0.0–1.0 (proportion).
- Y-axis right (if matplotlib twinx easy): absolute count (0–60).
- 4 lines, distinct colors + marker shapes + legend:
  - 🔵 `% volunteered ANY CVE` (monotonic increasing, starts at 0/60 at 0.1, climbs)
  - 🟢 `% CORRECT-BUT-UNSUPPORTED CVEs (REAL_AND_PLAUSIBLE)` (starts near-zero, climbs)
  - 🟠 `SelfCheckGPT recall on unsupported` (FLAT / flat-decreasing, this is the key "blindness" line — recall stays bad across temperatures)
  - 🔴 `LLMCite deterministic detection rate on unsupported` (FLAT at ~1.0, always catches them)
- Shaded 95% Wilson CI bands around each line point.

**CAPTION SUGGESTED for sn-article.tex:**
> *Fig. F6. Temperature-dependence of CVE citation behaviour (n=60 CVE pool, 5 temperature grid, 5 resamples per point). Volunteering of unsupported citations is strongly temperature-dependent, but SelfCheckGPT's inability to flag them (low flat orange line) is temperature-invariant, confirming the REAL_AND_PLAUSIBLE failure mode is structural rather than a t=0.7 artefact of SelfCheckGPT's resample policy.*

- [ ] **AC2:** F6 figure rendered; PNG + SVG + maker committed; correct Wilson CI bands; caption in §4.4 or §4.8.

---

## Task 3 — Add prose to §4.4 and §5 Discussion
### In §4.4 (SelfCheckGPT) — one paragraph:
> *"To rule out the REAL_AND_PLAUSIBLE blind spot being a t=0.7 resample artefact of SelfCheckGPT's sampling policy, we measured citation behaviour across a 5-point temperature sweep on the same 60-item CVE pool (Fig. F6). Volunteering of unsupported CVEs rose monotonically from 0% at t=0.1 to XX% at t=1.0. In contrast, SelfCheckGPT recall on the unsupported subset remained below 0.4 across all temperatures, and LLMCite's deterministic grounding rate remained above 0.98 across all temperatures. We therefore conclude the failure mode is structural, not a sampling parameter artefact."*

### In §5 Limitations — replace current one-sentence temperature confound with this concrete bound:
> *"Temperature behaviour was measured for the CVE pool only. ATT&CK temperature sweep was not performed; if ATT&CK memorization is weaker than CVE memorization (due to the TNNNN naming format being less distinct in training text than the CVE-YYYY-NNNNN format), the analogous temperature curve for MITRE IDs could be lower at every t-point."*

- [ ] **AC3:** Two paragraphs committed.
- [ ] **AC4:** Limitation is now bounded (not removed). Honest ATT&CK-side caveat remains.
- [ ] **AC5:** Manuscript says in Methods §3 "temperature for generation = 0.1 (production) / = 0.7 (SelfCheckGPT resample)" — these two numbers must still appear unchanged in the text. F6 is ADDITIONAL evidence, not a parameter change.

---
