# 📋 ISSUES INDEX — Consolidated Plan
### Supervisee: Eman (LLMCite, IJIS/SNCS Springer Nature submission)

---

## 🏷️ GitHub Labels (create these FIRST on the repo before opening issues)
| Label | Color | Meaning |
|---|---|---|
| `research` 🔬 | #1f6feb | Scientific/statistical/manuscript work |
| `engineering` 🔧 | #6f42c1 | Code/infrastructure work |
| `manuscript` 📄 | #d73a4a | LaTeX/BibTeX/paper-specific edits |
| `reproducibility` 🔒 | #0e8a16 | Dependency/data/reviewer-run-ability |
| `figures/tables` 📊 | #fbca04 | Tables/figures rendering/LaTeX |
| `priority:P0` 🔴 | #b60205 | Desk-reject risk or blocks main finding |
| `priority:P1` 🟠 | #d93f0b | Major methodological credibility gap |
| `priority:P2` 🟡 | #e99695 | Important polish/methodology |
| `priority:P3` 🟢 | #0e8a16 | Best-effort optional enhancer |
| `blocked:quota` ⏳ | #5319e7 | Needs Groq research quota or top-up |
| `blocked:annotator-time` 👤 | #bfd4f2 | Needs supervisor / 2nd human rater time |
| `do-not-build` ❌ | #8b8b8b | Explicit scope-stop — permanently closed issue |

**Create these first in GitHub → Settings → Labels.** Click "New label", copy name, paste HEX color.

---

## 🗓️ Milestones (create these 6)

| # | Name | Target Date | Goal | Open Issues to attach |
|---|---|---|---|---|
| M1 | **Freeze Desk-Reject Risks** | Days 1–2 | No `[?]` refs, deps OK, tests green | R2, E1, E2 |
| M2 | **Close the Central Scientific Gap** | Days 3–5 | ATT&CK headline stat + ablation done | R1 (⏳), R3 (⏳) |
| M3 | **Methodological Credibility** | Days 6–7 | 2-annotator κ + ATT&CK relevance | R4 (👤) |
| M4 | **Reproducibility & Release** | Days 8–9 | Snapshot, Docker, REPRODUCIBILITY.md, tag | E3, E4, E5 |
| M5 | **Manuscript Polish & Submission** | Days 10–12 | RQs, eval reorder, 0 TODO | R6 |
| M6 | **Optional Enhancers** | No target | Do only if M1–M5 completed EARLY | R5 (⏳), E6 |

---

## 🧪 RESEARCH ISSUES (R1–R6) · Open these in order

### P0 🔴 — open immediately

| ID | Title | Labels | Milestone | Blocker | Issue File |
|---|---|---|---|---|---|
| **R1** | ATT&CK SelfCheckGPT + McNemar Replication (Both Families) | `research`, `priority:P0`, `blocked:quota` | M2 | ⏳ | [R1-attack-selfcheckgpt-mcnemar.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R1-attack-selfcheckgpt-mcnemar.md) |
| **R2** | Literature 2026 Pass + Resolve `[?]` Dangling Refs + Sharpen Novelty | `manuscript`, `research`, `priority:P0` | M1 | — | [R2-literature-2026-refs-novelty.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R2-literature-2026-refs-novelty.md) |
| **R3** | Ablation Study (6 Configs × 479 Alert Pool) → Table T6 + UpSet | `research`, `engineering`, `priority:P0`, `blocked:quota`, `figures/tables` | M2 | ⏳ | [R3-ablation-6configs-479pool.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R3-ablation-6configs-479pool.md) |

### P1 🟠 — open right after M1 closes

| ID | Title | Labels | Milestone | Blocker | Issue File |
|---|---|---|---|---|---|
| **R4** | Human Annotation: 2-Annotator Cohen's κ + ATT&CK Relevance Validation | `research`, `priority:P1`, `blocked:annotator-time`, `figures/tables` | M3 | 👤 | [R4-human-cohen-kappa-attack-relevance.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R4-human-cohen-kappa-attack-relevance.md) |

### P2 🟡 — open during M4

| ID | Title | Labels | Milestone | Issue File |
|---|---|---|---|---|
| **R6** | Manuscript Restructure: 4 RQs + Evaluation Reorder + Delete-TODOs | `manuscript`, `priority:P2`, `figures/tables` | M5 | [R6-manuscript-rqs-eval-reorder-defuzz.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R6-manuscript-rqs-eval-reorder-defuzz.md) |

### P3 🟢 OPTIONAL STOP — DO NOT OPEN UNLESS M1–M5 ARE CLOSED EARLY

| ID | Title | Labels | Milestone | Blocker | Issue File |
|---|---|---|---|---|---|
| **R5** | OPTIONAL: Temperature-Sensitivity Sweep → F6 Figure | `research`, `priority:P2`, `blocked:quota`, `figures/tables` | M6 (only if M1-5 closed early) | ⏳ | [R5-optional-temperature-sweep-f6.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/R5-optional-temperature-sweep-f6.md) |

---

## 🔧 ENGINEERING ISSUES (E1–E6) · Open in order

### P0 🔴 — open immediately (with M1)

| ID | Title | Labels | Milestone | Issue File |
|---|---|---|---|---|
| **E1** | Dep Freeze: requirements.txt + lock file (add langchain-groq, remove unused) | `engineering`, `reproducibility`, `priority:P0` | M1 | [E1-deps-freeze-langchain-groq-lockfile.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E1-deps-freeze-langchain-groq-lockfile.md) |
| **E2** | Week-13 Regression Green + Schema-Parity Integration Test | `engineering`, `priority:P0` | M1 | [E2-regression-suite-green-schema-parity.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E2-regression-suite-green-schema-parity.md) |

### P1 🟠 — open during M2

| ID | Title | Labels | Milestone | Depends on | Issue File |
|---|---|---|---|---|---|
| **E3** | NVD Snapshot Mode + Frozen Cached Responses + SHA-256 Manifest | `engineering`, `reproducibility`, `priority:P1` | M4 | — | [E3-nvd-snapshot-mode-sha-manifest.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E3-nvd-snapshot-mode-sha-manifest.md) |
| **E4** | Top-Level Dockerfile (Reproducible Runtime, mocked-L1 smoke test) | `engineering`, `reproducibility`, `priority:P1` | M4 | E1 | [E4-dockerfile-repro-runtime.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E4-dockerfile-repro-runtime.md) |

### P2 🟡 — open during M4

| ID | Title | Labels | Milestone | Depends on | Issue File |
|---|---|---|---|---|---|
| **E5** | REPRODUCIBILITY.md Canonical File + paper-v1.0 Git Tag | `engineering`, `reproducibility`, `manuscript`, `priority:P2` | M4 | E1,E2,E3,E4 | [E5-reproducibility-md-paper-v1-tag.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E5-reproducibility-md-paper-v1-tag.md) |

### P3 🟢 OPTIONAL

| ID | Title | Labels | Milestone | Issue File |
|---|---|---|---|---|
| **E6** | OPTIONAL: System Architecture (SYS1) + 5-Tier Taxonomy (TAX1) Figures | `engineering`, `figures/tables`, `priority:P3` | M6 (only if M1–M5 closed) | [E6-optional-figures-sys1-architecture-tax1.md](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/.github/ISSUES/E6-optional-figures-sys1-architecture-tax1.md) |

---

## 🎯 FIVE-BOX FINAL SUBMISSION PRE-FLIGHT (from 3rd-tool review §29)
Before IJIS submission, **ALL FIVE MUST be green:**

| Box | Issue ID(s) | Status Check |
|---|---|---|
| 1 | E2 | Week-13 regression tested & frozen (145+ passed / 0 failed / 1 NeMo skipped) |
| 2 | R3 | Ablation 6 × 479 executed & tabled in T6 |
| 3 | R1 | SelfCheckGPT replicated across ATT&CK (stat sig or honest Clopper-Pearson bound) |
| 4 | R4 | Relevance ground truth: 2 independent annotators, Cohen's κ reported, ATT&CK side validation done |
| 5 | R2 | 2026 literature + 2 `[?]` refs fixed, novelty paragraph sharpened |

Cross all 5 = Paper potential **4/5**. Optionally add R6 + E6 if days left in submission window.
