# Literature Review: SecureAgent-SOC

**Student:** Emaan Afroz Khuram
**Updated:** 13/06/2026

---

## Key Search Terms

- LLM guardrails security agents
- Prompt injection detection LLM
- SOC automation large language models
- Agentic AI safety alignment
- Hallucination detection NLP
- PII redaction transformer models
- NeMo Guardrails / Guardrails AI framework

---

## Suggested Starting Papers

| # | Title | Venue | Why Relevant |
|---|---|---|---|
| 1 | "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" | arXiv 2023 | Core threat model for agent injection |
| 2 | "Tensor Trust: Interpretable Prompt Injection Attacks from an Online Game" | NeurIPS 2023 | Injection taxonomy and benchmarks |
| 3 | "Constitutional AI: Harmlessness from AI Feedback" | Anthropic 2022 | Principled output safety framework |
| 4 | "LLM-based SOC Analyst" — search arXiv for recent SOC + LLM | arXiv 2024 | Direct domain application |
| 5 | NeMo Guardrails documentation and paper | NVIDIA 2023 | Primary framework to evaluate |

---

## Chosen papers for literature review:

1. InjecAgent
Authors: Zhan, Liang, Ying, Kang
Relevance: threat model for malicious log entries


2. Survey on Hallucination in LLMs
Authors: Huang et al.
Relevance: output guardrail hallucination check


3. AI-Augmented SOC Survey
Authors: (MDPI authors)
Relevance: background baseline agent design


4. NeMo Guardrails
Authors: Rebedea et al.
Relevance: guardrail architecture & latency


5. Presidio
Authors: Microsoft
Relevance: PII redaction, leakage metric

## Paper Summary Template

### Paper 1 — [Short Title]

| Field | Content |
|---|---|
| **Full title** | |
| **Authors** | |
| **Year** | |
| **Venue** | |
| **URL / DOI** | |
| **Method** | |
| **Dataset** | |
| **Key result** | |
| **Limitation** | |
| **Relevance** | |

**Notes:**
>

---

## Reference Table

| # | Title (short) | Authors | Year | Method | Dataset | Relevance |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |

---

## Tools and Frameworks

| Name | Type | URL | Notes |
|---|---|---|---|
| NeMo Guardrails | Framework | https://github.com/NVIDIA/NeMo-Guardrails | Primary guardrail library |
| Guardrails AI | Framework | https://github.com/guardrails-ai/guardrails | Alternative framework |
| LangGraph | Orchestration | https://github.com/langchain-ai/langgraph | Agent state machine |
| Presidio | PII detection | https://github.com/microsoft/presidio | PII redaction layer |
| MITRE ATT&CK | Threat intel | https://attack.mitre.org | Adversary TTP taxonomy |

