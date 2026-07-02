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

## Chosen Papers for Literature Review

| # | Title (short) | Authors | Relevance |
|---|---|---|---|
| 1 | InjecAgent | Zhan, Liang, Ying, Kang | Threat model for malicious log entries |
| 2 | Survey on Hallucination in LLMs | Huang et al. | Output guardrail hallucination check |
| 3 | AI-Augmented SOC Survey | (MDPI authors) | Background — baseline agent design |
| 4 | NeMo Guardrails | Rebedea et al. | Guardrail architecture & latency |
| 5 | Presidio | Microsoft | PII redaction, leakage metric |

---

## Paper Summaries

### Paper 1 — InjecAgent

| Field | Content |
|---|---|
| **Full title** | InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents |
| **Authors** | Zhan, Q., Liang, Z., Ying, Z., Kang, D. |
| **Year** | 2024 |
| **Venue** | Findings of ACL 2024 |
| **URL / DOI** | https://arxiv.org/abs/2403.02691 |
| **Method** | Benchmark of 1,054 test cases evaluating tool-integrated LLM agents against indirect prompt injection embedded in tool outputs (e.g. emails, web content, logs) |
| **Dataset** | Synthetic tool-use scenarios across multiple agent tasks |
| **Key result** | Reinforcing attacker instructions with a "hacking prompt" nearly doubles the attack success rate against ReAct-prompted GPT-4 |
| **Limitation** | Synthetic benchmark; does not cover real-world SOC log formats or domain-specific injection patterns |
| **Relevance** | Directly models the threat in this project's input guardrail layer — malicious instructions hidden inside alert/log data that the SOC agent ingests (maps to RQ3) |

**Notes:**
> Most directly applicable paper for the "Input Guardrail" box in the architecture diagram. Useful as a template for building our own injection benchmark in `experiments/`.

---

### Paper 2 — Survey on Hallucination in LLMs

| Field | Content |
|---|---|
| **Full title** | A Survey on Hallucination in Large Language Models: Principles, Taxonomy, Challenges, and Open Questions |
| **Authors** | Huang, L., Yu, W., Ma, W., Zhong, W., Feng, Z., Wang, H., Chen, Q., Peng, W., Feng, X., Qin, B., Liu, T. |
| **Year** | 2024 |
| **Venue** | ACM Transactions on Information Systems |
| **URL / DOI** | https://arxiv.org/abs/2311.05232 |
| **Method** | Survey establishing a taxonomy of hallucination causes and categorising detection methods (uncertainty-based, self-consistency, retrieval-based) |
| **Dataset** | N/A (survey) |
| **Key result** | Covers SelfCheckGPT, a zero-resource black-box method that flags hallucination by checking consistency across multiple sampled responses on the same topic |
| **Limitation** | Detection methods generally trade off cost (multiple samples / external knowledge) against reliability; no single method dominates |
| **Relevance** | Foundation for the output guardrail's hallucination-detection component — informs how to flag fabricated CVEs/threat verdicts without ground-truth labels (RQ4) |

**Notes:**
> SelfCheckGPT-style consistency checking looks like the most practical starting point for a prototype, since it needs no external dataset.

---

### Paper 3 — AI-Augmented SOC Survey

| Field | Content |
|---|---|
| **Full title** | AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation |
| **Authors** | (MDPI authors) |
| **Year** | 2025 |
| **Venue** | MDPI |
| **URL / DOI** | https://www.mdpi.com/2624-800X/5/4/95 |
| **Method** | Survey of LLM/agent applications across eight SOC tasks: log summarisation, alert triage, threat intelligence, incident response, report generation, asset discovery, and vulnerability management |
| **Dataset** | N/A (survey; references industry case studies) |
| **Key result** | One cited deployment cut false positives from 70% to 35% and reduced mean time to respond from 8 hours to 90 minutes using AI-driven triage |
| **Limitation** | Notes ongoing concerns about accuracy/reliability of automatically generated reports — the exact problem this project addresses |
| **Relevance** | Grounds the background/motivation section and gives concrete baseline metrics (MTTR, false-positive rate) to compare against in evaluation |

**Notes:**
> Good source for justifying *why* SOC automation matters before discussing the risks guardrails address.

---

### Paper 4 — NeMo Guardrails

| Field | Content |
|---|---|
| **Full title** | NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails |
| **Authors** | Rebedea, T., Dinu, R., et al. |
| **Year** | 2023 |
| **Venue** | NVIDIA (toolkit paper) |
| **URL / DOI** | https://www.semanticscholar.org/paper/NeMo-Guardrails |
| **Method** | Introduces Colang, a domain-specific language for defining programmable guardrail policies that intercept/validate input and output across five pipeline stages |
| **Dataset** | N/A (framework) |
| **Key result** | GPU-accelerated architecture achieves sub-100ms response times; native integration with LangChain/LangGraph |
| **Limitation** | General-purpose conversational control; does not enforce provenance-aware authority ordering between system instructions and untrusted content unless explicitly configured |
| **Relevance** | Primary candidate framework for both input and output guardrail layers in the architecture diagram; informs RQ1 (which guardrail classes matter) and RQ2 (performance overhead) |

**Notes:**
> Limitation noted here matters a lot for SOC use case — by default it won't distinguish "trusted system prompt" from "untrusted log content" without us designing that explicitly.

---

### Paper 5 — Presidio

| Field | Content |
|---|---|
| **Full title** | Presidio: An open-source framework for detecting, redacting, masking, and anonymizing sensitive data (PII) |
| **Authors** | Microsoft |
| **Year** | Ongoing (actively maintained) |
| **Venue** | GitHub / Microsoft open source |
| **URL / DOI** | https://github.com/microsoft/presidio |
| **Method** | Hybrid PII detection combining Named Entity Recognition (spaCy), regex pattern matching, rule-based logic, and checksum validation |
| **Dataset** | N/A (tool; ships with predefined recognizers for common entity types) |
| **Key result** | Detects entities like names, emails, phone numbers, SSNs, credit cards, and locations, with configurable anonymization operators (replace, mask, hash, redact, encrypt) |
| **Limitation** | Self-documented: automated detection provides no guarantee of catching all sensitive information; additional layered protections are recommended |
| **Relevance** | Direct implementation choice for the output guardrail's PII redaction component; its stated limitation directly informs the "PII leakage rate" evaluation metric |

**Notes:**
> The explicit "no guarantee" caveat from Microsoft is worth quoting in the final report when discussing residual risk after guardrails are applied.

---

## Reference Table

| # | Title (short) | Authors | Year | Method | Dataset | Relevance |
|---|---|---|---|---|---|---|
| 1 | InjecAgent | Zhan, Liang, Ying, Kang | 2024 | Benchmark of indirect prompt injection against tool-using LLM agents | 1,054 test cases across tool-integrated agents | RQ3 — threat model for malicious log entries |
| 2 | Survey on Hallucination in LLMs | Huang et al. | 2024 | Taxonomy + survey of detection/mitigation methods (incl. SelfCheckGPT) | N/A (survey) | RQ4 — output guardrail hallucination check |
| 3 | AI-Augmented SOC Survey | (MDPI authors) | 2025 | Survey of LLM/agent use across 8 SOC tasks | N/A (survey) | Background — baseline agent design |
| 4 | NeMo Guardrails | Rebedea et al. | 2023 | Colang-based programmable rails across 5 pipeline stages | N/A (framework) | RQ1/RQ2 — guardrail architecture & latency |
| 5 | Presidio | Microsoft | Ongoing | Hybrid NER + regex + rule-based PII detection/anonymization | N/A (tool) | Output guardrail — PII redaction, leakage metric |

---

## Tools and Frameworks

| Name | Type | URL | Notes |
|---|---|---|---|
| NeMo Guardrails | Framework | https://github.com/NVIDIA/NeMo-Guardrails | Primary guardrail library |
| Guardrails AI | Framework | https://github.com/guardrails-ai/guardrails | Alternative framework |
| LangGraph | Orchestration | https://github.com/langchain-ai/langgraph | Agent state machine |
| Presidio | PII detection | https://github.com/microsoft/presidio | PII redaction layer |
| MITRE ATT&CK | Threat intel | https://attack.mitre.org | Adversary TTP taxonomy |