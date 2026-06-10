# Research Proposal: SecureAgent-SOC — Guardrails and SOC Copilot for Trustworthy AI Agents

**Student:** Emaan Afroz Khuram
**GitHub:** @emaankhuram
**Supervisor:** _[Fill in]_
**Start date:** _[Fill in]_
**Expected end date:** _[Fill in]_

---

## 1. Background

Large Language Models (LLMs) are being adopted in Security Operations Centres (SOCs) to
automate alert triage, enrich threat intelligence, and generate analyst reports. However,
deploying LLM-based agents in production security environments poses critical risks:

- **Prompt injection**: adversarial inputs embedded in log files or alerts can hijack agent behaviour.
- **Hallucination**: agents may fabricate CVE details, threat actors, or severity scores.
- **Data leakage**: agents processing sensitive alerts may inadvertently expose PII or internal infrastructure details.
- **Lack of auditability**: opaque agent reasoning makes compliance and forensic analysis difficult.

Guardrail frameworks impose structured safety constraints on LLM inputs and outputs, but their
application to agentic SOC workflows is underexplored.

---

## 2. Problem Statement

There is no established, open-source guardrail architecture tailored to LLM-based SOC agents.
Existing frameworks (NeMo Guardrails, Guardrails AI) are general-purpose and lack threat-domain
ontologies, SOC-specific output schemas, and adversarial robustness benchmarks.

---

## 3. Research Questions

1. Which classes of guardrails (input, output, semantic, access-control) are most critical for SOC agent safety?
2. What is the performance overhead introduced by guardrail layers in real-time alert triage?
3. How robust are existing guardrail frameworks against adversarial prompt injection embedded in security logs?
4. Can hallucination in threat reports be reliably detected without ground-truth labels?

---

## 4. Proposed Methodology

### 4.1 Dataset
- Public SOC alert datasets: CICIDS, UNSW-NB15, CTU-13 (network intrusion)
- Synthetic adversarial prompts crafted to test injection resistance
- CVE and threat intelligence from NVD / MITRE ATT&CK

### 4.2 Approach
1. Implement a baseline LangChain SOC co-pilot (alert intake → analysis → report).
2. Layer guardrails: input sanitiser → agent → output validator + PII redactor.
3. Benchmark guardrail impact on accuracy, latency, and injection resistance.

### 4.3 Evaluation Metrics
- Alert classification accuracy (F1, precision, recall)
- Prompt injection success rate (before/after guardrails)
- PII leakage rate
- Average response latency (ms)
- Hallucination rate (human-evaluated sample)

---

## 5. Expected Outcome

A working open-source prototype of SecureAgent-SOC with documented guardrail architecture,
benchmark results, and a reusable guardrail template for LLM security applications.

---

## 6. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| LLM API cost too high | Medium | Use Ollama with local models (LLaMA 3, Mistral) |
| No public SOC alert dataset with labels | Low | Use CICIDS-2017 or generate synthetic alerts |
| Guardrail latency too high for real-time | Medium | Profile and optimise; consider async pipeline |
