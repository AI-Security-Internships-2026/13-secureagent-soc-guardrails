# E6 · Two Figures: System Architecture (SYS1) + Taxonomy Decision Tree (TAX1)
- **Labels:** engineering, figures/tables, priority:P3
- **Milestone:** M6 — Enhancers (DO ONLY IF M1–M5 ALREADY COMPLETED EARLY)
- **Acceptance items:** 4

---

## Summary
The paper draft and PDF have only 2 rendered figures (Fig. 1 class-stacked bar, Fig. 2 concurrency 3-panel). IJIS-style reviewers expect at minimum:
- **ONE system architecture figure** — how the alert flows through the pipeline (§3 Method anchor)
- **ONE taxonomy/classification flowchart figure** — the 5-tier cascaded classification (§3.3 Taxonomy anchor)

Without these, reviewers have to reverse-engineer the method from text; adding them is a small high-polish upgrade. This issue is explicitly **last on the stack** — it should never be opened before R1, R2, R3, R4, R6, E1–E5 are all Closed or Done.

---

## Task 1 — Figure SYS1: System Architecture (Half-page Landscape, PNG+SVG)
Draw in Inkscape / draw.io / Figma. Save:
- Source vector: `docs/paper/figures/fig_sys1_architecture.svg`
- Rendered PNG: `docs/paper/figures/fig_sys1_architecture.png` (300 dpi, ≥ 2400 px wide landscape for two-column IJIS)

### Suggested Layout (left → right flow, read top-bottom within layers):
```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  INPUT LAYER (ALERT SCHEMA)                                                                   │
│  SecurityAlert dataclass                                                                      │
│  ├ alert_id, timestamp, severity, source_ip, dest_ip, sport, dport, protocol,                │
│  │   event_type, description, payload_snippet, raw_log                                        │
│  └ [ALERT-001/ALERT-002/ALERT-003 sample fixtures / Wazuh live ingestion]                    │
└──────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  STAGE 0 — INPUT GUARDRAIL (§3.1)                                                            │
│  ├ 19-PHRASE DETERMINISTIC LIST first (119 prompt-injection patterns, 0 FP if matched)       │
│  ├ CLEAN PASS ─► next stage                                                                  │
│  └ FLAG PASS ─► PYTECTOR DeBERTa ML fallback ─► final verdict (CONTINUE / BLOCK / HUMAN)    │
│     └ (RACE FIX: Pytector lazy loader double-checked locking)                                │
└──────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — EVIDENCE PACK BUCKETING (§3.2)                                                    │
│  ├ Structured split: IPs [src+dst] / Hostnames / Users / File hashes / Ports / Text-snippet   │
│  └ ──► GROUNDING ONLY SCANS TEXT BUCKET for ID substring matches                             │
│         (prevents IPv4 → phone-number / hash → CVE collisions)                               │
└──────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  STAGE 2 — LLM REPORT GENERATION (§3.4)                                                      │
│  Groq ChatGroq(model=openai/gpt-oss-20b, t=0.1) OR qwen/qwen3.6-27b                          │
│  └ SOC Report JSON: severity_score, requires_review flag, citations[] (CVE IDs / ATT&CK IDs), │
│      analyst summary, recommendations, evidence_pack echoed                                   │
└──────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — TWO-STAGE GROUNDING & 5-TIER VERIFICATION (§3.3, §3.5)                           │
│                                                                                              │
│  [EXTRACT] CVE regex CVE-YYYY-NNNNN(NN)?  +  ATT&CK regex T\d{4}(\.\d{3})?                   │
│          │                                                                                   │
│          ▼                                                                                   │
│  STEP A: Appeared in ALERT EVIDENCE? ─► NO → UNGROUNDED → proceed to Step B                  │
│          │                        ─► YES → GROUNDED → skip Step B                            │
│          ▼                                                                                   │
│  STEP B: Against Authoritative Ontologies                                                    │
│          ├ NVD REST v2 + IN-PROCESS CACHE / E3 --use-snapshot ─► CVE existence + REJECTED?   │
│          └ MITRE STIX ENTERPRISE SNAPSHOT (SHA: §4.1) ─► ATT&CK existence + REVOKED?         │
│          │                                                                                   │
│          ▼                                                                                   │
│  5-TIER TAXONOMY CASCADE (see Figure TAX1) → FAB / R&I / R&P / UNV / REJ-REVOKED             │
└──────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  STAGE 4 — PII REDACTION + OUTPUT DELIVERY (§3.6)                                            │
│  ├ Presidio + en_core_web_sm NER + post-structural IPv4→phone-FP fix (27.3% → 2.9% FPR)     │
│  └ ──► Final Report JSON to Streamlit dashboard / stdout / log                               │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```
- Color-coded: INPUT/Stage0 = red-ish (defense outer), Stage1 = blue (structuring), Stage2 = green (LLM generation), Stage3 = purple (verification), Stage4 = teal (redaction).
- Add dashed line "Optional Ablation Stage Disable (week-13 toggles)" with arrow pointing at all 4 rectangles (C0 through C5 per R3 configs).
- Add footnote anchor: `* Pytector DeBERTa lazy-singleton loader — double-checked locking race fix documented in code.`

- [ ] **AC1:** `fig_sys1_architecture.svg` + `.png` committed at 300 dpi. Layout above faithfully reproduced (colors optional, boxes + flow required).

---

## Task 2 — Figure TAX1: 5-Tier Taxonomy Decision Tree
File: `docs/paper/figures/fig_tax1_5tier_decision.{svg,png}`

Layout: diamond-decision flowchart. Exactly reproduces §3.3 cascaded classification rules in the manuscript.

### Flowchart:
```
START
  │
  ▼
┌──────────────────────────────────────────────────┐
│ Identifier found in:  ALERT EVIDENCE-PACK TEXT?  │  (structural substring match, case-insensitive)
└──────────────┬───────────────────────┬───────────┘
               │ YES                   │ NO
               ▼                       ▼
        [GROUNDED]              ID flagged UNGROUNDED
        Report + exit               │
                                    ▼
                          ┌────────────────────────────────┐
                          │ EXISTS IN AUTHORITATIVE ONTOLOGY? │
                          │  CVE → NVD live / --use-snapshot │
                          │  ATT&CK → MITRE STIX snapshot    │
                          └──────┬──────────────┬────────────┘
                                 │ NO           │ YES
                                 ▼              ▼
                          [FABRICATED]   ┌──────────────────────────────┐
                          Exit           │  MARKED REJECTED / REVOKED?  │
                                         └───┬────────────┬───────────────┘
                                             │ YES        │ NO
                                             ▼            ▼
                                   [REJECTED / REVOKED]  ┌─────────────────────────────────────┐
                                   Exit                  │ RELEVANT TO ALERT? (BoW overlap ≥0.15)│
                                                         └──────┬───────────────┬────────────────┘
                                                                │ NO            │ YES
                                                                ▼               ▼
                                                        [REAL_BUT_IRRELEVANT]  [REAL_AND_PLAUSIBLE]
                                                        Exit                    Exit (← SelfCheck blind spot)
```

Key annotation: draw a red BOLD BOX around the bottom-right `[REAL_AND_PLAUSIBLE]` leaf with side-annotation:
> ⚠️ **Central empirical finding (§4.4–§4.5):** SelfCheckGPT at t=0.7 with 3 resamples consistently MISCLASSIFIES this leaf as "Grounded / Self-consistent" because the ID is semantically plausible AND internally consistent across resamples → SelfCheckGPT cannot see the "never appeared in evidence" condition, which is a purely external check.

- [ ] **AC2:** Decision tree drawn correctly; leaves labeled FAB / R&I / R&P / UNV / REJ-REVOKED matching the 5-tier taxonomy in Table 2 of manuscript; red annotation around REAL_AND_PLAUSIBLE.

---

## Task 3 — Caption both figures in sn-article.tex
Place both inside §3 Method (F1 SYS1 → §3 intro, F2 TAX1 → §3.3 Taxonomy):

```latex
\begin{figure}[t]
\centering
\includegraphics[width=\textwidth]{figures/fig_sys1_architecture}
\caption{LLMCite system architecture. A SecurityAlert (Stage 0) passes through a hybrid input guardrail, then is split into a structured Evidence Pack (Stage 1), fed to the LLM for report generation (Stage 2), each claimed citation is grounded against the supplied evidence and then against authoritative per-identifier ontologies with a 5-tier cascaded classification (Stage 3, see Fig. TAX1), and finally PII is redacted before report delivery (Stage 4). Week-13 ablation toggles (§4.8) can disable Stages 0, 3a, 3b, and 4 independently for the 6-config decomposition.}
\label{fig:sys1}
\end{figure}
```

```latex
\begin{figure}[t]
\centering
\includegraphics[width=0.95\textwidth]{figures/fig_tax1_5tier_decision}
\caption{Five-tier cascaded classification for each ungrounded identifier. The central blind spot (highlighted) — REAL\_AND\_PLAUSIBLE — is ontology-genuine and alert-topically-relevant yet never present in the specific evidence, which makes it indistinguishable from grounded citation by self-consistency-based detectors such as SelfCheckGPT. REJECTED (CVE) and REVOKED (ATT\&CK) are structurally asymmetric deprecated-ID catch-all tiers; see Table 2 for the full taxonomy definitions.}
\label{fig:tax1}
\end{figure}
```

Then ensure anywhere in §3 that references these figures says `see \Cref{fig:sys1}` / `see \Cref{fig:tax1}` (or whatever `cleveref` variant the sn-jnl class supports — check with `latexmk` log for `Reference fig:sys1 on page * undefined`).

- [ ] **AC3:** Both figures captioned; no `??`/undefined refs in rendered PDF.

---

## Task 4 — Verify rendering at IJIS-page-like format (two-column, ≈7in textwidth)
Open `sn-article.pdf` after recompilation; zoom to 100%:
- Figure SYS1 text labels are still legible at two-column width.
- No caption overflow into second column.
- Figure TAX1's "REAL_AND_PLAUSIBLE" annotation is readable, not cut off by page boundary.
- If they don't fit two-column, place with `[t!]` + `\onecolumn` placement or move to supplement; main text must reference them correctly.

- [ ] **AC4:** Both figures fit in two-column layout with legible labels; or if moved to supplement, supplement reference marker is present in main text.

---

## Definition of Done
All 4 acceptance items ticked. 2 SVG sources + 2 PNGs committed, both captioned and correctly cross-referenced with no undefined-reference warnings in compilation log.
