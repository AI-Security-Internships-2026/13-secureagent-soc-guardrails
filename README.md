# SecureAgent-SOC: Guardrails and SOC Copilot for Trustworthy AI Agents

> **CNIT/PNTLab Pisa · TECIP · Scuola Superiore Sant'Anna — AI Security Internship 2026**

---

## Research Problem

AI agents are increasingly deployed in high-stakes security workflows — threat triage, alert
enrichment, incident response — yet they lack principled safety boundaries. Without guardrails,
an LLM-based SOC co-pilot can hallucinate threat verdicts, leak sensitive alert data, or be
manipulated via prompt injection from malicious log entries.

This project designs and implements **SecureAgent-SOC**: a guardrail framework wrapped around
an LLM-powered SOC co-pilot that enforces output safety, access control, and auditability at
every agent reasoning step.

---

## Objectives

1. Survey existing LLM guardrail frameworks (NeMo Guardrails, Guardrails AI, custom filters).
2. Model the SOC co-pilot agent architecture (alert intake → reasoning → analyst report).
3. Design guardrail layers: input sanitisation, output validation, hallucination detection, PII redaction.
4. Implement a working prototype integrating guardrails with a LangChain/LangGraph agent.
5. Evaluate guardrail effectiveness against a threat-injection and data-leakage benchmark.
6. Document findings for publication or technical report.

---

## Expected Deliverables

| Deliverable | Due |
|---|---|
| Literature review (`docs/literature-review.md`) | Week 2 |
| System architecture & proposal (`docs/proposal.md`) | Week 3 |
| Guardrail prototype (`src/`) | Week 5 |
| Benchmark / evaluation (`experiments/results/`) | Week 7 |
| Final report (`docs/final-report.md`) | Week 8 |

---

## Recommended Technology Stack

```
Python 3.11+
LangChain / LangGraph          — agent orchestration
NeMo Guardrails / Guardrails AI — guardrail framework
OpenAI API / Ollama            — LLM backend
FastAPI + Uvicorn              — REST interface
Streamlit                      — demo dashboard
Presidio                       — PII detection & redaction
Pytest                         — unit & integration tests
Docker                         — containerised deployment
```

---

## System Architecture (Overview)

```
[Security Alert / Log]
        │
        ▼
┌─────────────────────┐
│  Input Guardrail    │  ← sanitise, detect prompt injection, classify sensitivity
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  SOC Copilot Agent  │  ← LLM reasoning, tool calls (threat intel, CVE lookup)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Output Guardrail   │  ← hallucination check, PII redaction, confidence scoring
└────────┬────────────┘
         │
         ▼
[Analyst Report + Audit Log]
```

---

## Weekly Workflow

```
Monday     – Review tasks/week-XX.md
Tue–Thu    – Implementation / experiments
Friday     – Update docs/weekly-progress.md and open weekly PR → dev
```

---

## Branching Policy

| Branch | Purpose |
|---|---|
| `main` | Stable, supervisor-reviewed code only |
| `dev` | Integration branch |
| `emaan-week-XX` | Your weekly working branch |

**Never push directly to `main` or `dev`.**

---

## Pull Request Policy

- One PR per week, targeting `dev`.
- Title format: `[Week XX] Brief description`
- PR body must reference the weekly task file and summarise progress.

---

## Getting Started

```bash
git clone https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails.git
cd 13-secureagent-soc-guardrails
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm  # required by the PII-redaction guardrail (Presidio's NER)
python src/main.py

# Create your Week 1 branch
git checkout dev && git pull origin dev
git checkout -b emaan-week-01
```

---

## Roadmap to September 8, 2026

**Current state:** NVD-verified output guardrail merged (PR #18) — classifying CVE citations as FABRICATED/REAL_BUT_IRRELEVANT/REAL_AND_PLAUSIBLE/UNVERIFIED, plus a multiprocessing-vs-threading benchmark. Strongest guardrail stack in the cohort (NeMo Guardrails + Guardrails AI + Presidio + LangGraph). Previously only had generic undated weekly checkboxes — this replaces those with real milestones.

**Novel contribution target:** the "verify against an authoritative external database" pattern used for CVEs (issue #16) generalizes — apply the same grounding technique to other citation types (CWE, MITRE ATT&CK technique IDs) rather than treating CVE-verification as a one-off feature.

| Date | Milestone |
|---|---|
| Aug 2 | Finalize NVD-verification edge cases from PR #18 |
| Aug 9 | Compare NeMo Guardrails vs. Guardrails AI vs. the custom NVD-grounded approach (issue #16) — latency, false-positive rate, coverage |
| Aug 16 | Extend the grounding technique to a second citation type (CWE or MITRE ATT&CK technique IDs) |
| Aug 23 | Full multi-source grounding benchmark |
| Aug 30 | Write-up |
| Sep 6 | Paper draft |
| **Sep 8** | **Final submission** |

---

## Supervisor Note

Repository managed by **CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna**.
Do not commit API keys, model weights, or raw alert datasets. See `.gitignore`.
