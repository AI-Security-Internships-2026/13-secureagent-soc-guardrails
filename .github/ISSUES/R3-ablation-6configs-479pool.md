# R3 · Ablation Study (6 Configs × Alert Pool) → Table T6 + UpSet/Venn
- **Labels:** research, engineering, priority:P0, blocked:quota, figures/tables
- **Milestone:** M2 — Close the Central Scientific Gap
- **Acceptance items:** 10

---

## Summary
Week‑13 already added four boolean signature toggles to [soc_agent.py](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/src/agent/soc_agent.py):
```python
def analyse_alert(alert,
                  input_guardrail_enabled=True,
                  cve_guardrail_enabled=True,
                  attack_guardrail_enabled=True,
                  pii_guardrail_enabled=True):
```

The **ablation study must be run**. This is a hard requirement at top-tier venues: "how much does each component contribute individually to the empirical performance?" Currently the toggles are in code but zero experiment has been executed. The manuscript currently says "ablation pending"; this must be closed.

### 6 Configs (standard disable-one + full + none)
| Config ID | input | cve | attack | pii | Name |
|---|---|---|---|---|---|
| C0 | **ON** | **ON** | **ON** | **ON** | Full pipeline (baseline inside ablation) |
| C1 | **OFF** | ON | ON | ON | −Input (−I) |
| C2 | ON | **OFF** | ON | ON | −CVE (−C) |
| C3 | ON | ON | **OFF** | ON | −ATT&CK (−A) |
| C4 | ON | ON | ON | **OFF** | −PII (−P) |
| C5 | OFF | OFF | OFF | OFF | None (LLM-only output, no guardrails) |

Pool to run on: **479-alert pooled cross-source set** (identical to the one that produced §4.9 numbers) — this way results are directly comparable to baseline numbers already in the paper.

---

## Task 1 — Phase 2 SMOKE TEST
File: `experiments/evaluation/ablation_smoke_test.py`
Pool: 2 hand-picked representative alerts → ALERT-001 (SSH brute) + ALERT-003 (port scan)
Outputs: 2 × 6 configs = **12 JSON reports** under `experiments/results/ablation_smoke/`.

**Manual INSPECTION checklist per report:**
- Every output JSON has **exactly the same top-level keys** regardless of config toggles used.
- Disabled stages fill **schema-compatible defaults** (`nothing-found`, `[]`, `False`, 0.0, etc.), NOT:
  - `null`/`None`
  - Missing keys (KeyError on reader)
  - NaN or non-serializable floats
  - Empty strings where structured list is expected

**Document the inspection:** Create `experiments/results/ablation_smoke/INSPECTION.md` with a 6-row × 5-column checkbox table. You tick everything per config. 

- [ ] **AC1:** 12 JSON reports committed under `ablation_smoke/`.
- [ ] **AC2:** Schema-parity inspection `INSPECTION.md` table fully ticked.

---

## Task 2 — Phase 3 FULL DRIVER (Resume-Mode Batch)
File: `experiments/evaluation/ablation_driver.py`
Behaviour:
1. Loads `479_pool.json` alert pool.
2. Loops (config × alert) in deterministic order.
3. For each (config_id, alert_id) pair:
   - Skips IFF key already present in `experiments/results/ablation_full.jsonl` (**RESUME MODE, append-only** — critical for multi-day interrupted Groq runs).
   - Calls `analyse_alert(alert, toggle_state_per_config)` with retry + backoff on 429 / 5xx.
   - Writes one complete row `{config_id, alert_id, runtime_ms, output_report}` to the JSONL file, **fsync every row** so no data loss on crash.
4. On completion, computes summary aggregate over 2874 rows.

- [ ] **AC3:** `ablation_driver.py` runs. `ablation_full.jsonl` has EXACTLY 2874 lines on successful completion; driver's `--validate` flag (you add this) prints "2874 rows, all 6 configs present for each of 479 alerts".
- [ ] **AC4:** Resume mode verified: interrupt driver with Ctrl-C at 50% → re-run → resumes from row 1437, no duplicate rows, final count still 2874.

---

## Task 3 — Build Table T6 (main manuscript) and Figures F3 + F4
### T6 Summary Table (in §4.9 / §4.8 — place right after Wazuh/Secure_SOC_AI real-world numbers)
6 rows × 8 columns:

| Config | #Ungrounded detections | #Requires-review flags | #PII-TP (FPR) | #Input rail FP | Median latency ms (IQR) | Unique alerts caught | Alerts lost vs Full |
|---|---|---|---|---|---|---|---|
| Full (C0) | | | 0 | | | — | — |
| −I (C1) | | | 0 | | | ↓ Δ from C0 | ↑ Δ |
| −C (C2) | | | 0 | | | ↓ Δ | ↑ Δ |
| −A (C3) | | | 0 | | | ↓ Δ | ↑ Δ |
| −P (C4) | | | 0 | | | ↓ Δ | ↑ Δ |
| None (C5) | | | 0 | | | ↓ Δ | ↑ Δ |

- [ ] **AC5:** Table T6 typeset in `sn-article.tex` with correct numbers. Per-config numbers that differ from Full by ≥ 10% **bolded**.

### F3 — Stacked Bar Taxonomy-Class × Config (F3 DETECTOR-STACKED)
Per config, show stacked counts across 5 taxonomy tiers: FAB, R&I, R&P, UNV, REJ/REV.
Commit `docs/paper/figures/ablation_taxonomy_stacked.png` (PNG 300 dpi) + `docs/paper/figures/ablation_taxonomy_stacked.svg` (source).

- [ ] **AC6:** F3 figure rendered, captioned in §4.9.

### F4 — UpSet Plot (Unique-Detection Overlap)
Answer: "Which alerts would NOT have been flagged, if we had removed stage X?"
Better than a 4-circle Venn. Use Python `matplotlib-venn` / `upsetplot` library.
6 groups: Full, -I, -C, -A, -P, None; intersection set sizes of "alerts requiring-review=true".
Commit `docs/paper/figures/ablation_upset_unique_alerts.png` + `.svg`.

- [ ] **AC7:** F4 UpSet plot rendered + captioned.

---

## Task 4 — UPDATE MANUSCRIPT CONSISTENCY
### DO:
- Write one paragraph in §4.9 explaining the ablation headline result. Expected finding (review consensus, NOT guaranteed to match your numbers): **Full pipeline ≫ C5 None (baseline) by ≫10%; −C and −A individually lose the most detection; −I has modest FNR cost but lowers FP. −P has negligible effect on citations (expected, PII is an orthogonal feature).**
- Delete any remaining `[ABLATION NOT YET RUN]` / `TODO` markers anywhere in `sn-article.tex` text.

### DO NOT:
- ❌ Do NOT add "Ablation" as a separate enumerated contribution (i.e., Contribution #4 or #5). The ablation **supports** Contribution #2 (pipeline decomposition). It is not a standalone scientific finding.
- ❌ Do NOT make claims like "every component is essential" unless Table T6 genuinely shows ≥ 10% drop-off for every single disable-one config. If e.g., −P shows < 2% detection delta vs Full, HONESTLY say so in text.

- [ ] **AC8:** Ablation paragraph written with honest qualifiers.
- [ ] **AC9:** No remaining `TODO` / `NOT YET RUN` markers in manuscript ablation-related text.

---

## Task 5 — CONTRIBUTIONS LIST INTEGRITY
Manually verify that Contributions list still has the same 3 contributions it had before this issue was opened, with the ONLY change being possible wording improvement that references ablation as a supporting experiment for #2.

- [ ] **AC10:** Contributions count unchanged (still hierarchical #1 empirical, #2 pipeline + taxonomy, #3 auxiliary evaluations or whatever the pre-issue list was — no new bullet added for "ablation").

---

