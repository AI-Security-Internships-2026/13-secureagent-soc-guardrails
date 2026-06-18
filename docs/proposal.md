# Research Proposal: SecureAgent-SOC — Guardrails and SOC Copilot for Trustworthy AI Agents

**Student:** Emaan Afroz Khuram
**GitHub:** @emaankhuram
**Supervisor:** Dr. Rana Abu Bakar
**Start date:** 
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

## 2.1 Threat Model

This project considers the following attack scenarios against the LLM-based SOC co-pilot:

| # | Attack Type | Description | Guardrail Layer |
|---|---|---|---|
| T1 | Direct prompt injection | User or analyst input contains instruction-override phrases (e.g. "ignore previous instructions") that attempt to hijack agent behaviour | Input |
| T2 | Indirect prompt injection | Adversarial instructions embedded inside ingested alert/log data that the agent processes as part of normal triage | Input |
| T3 | PII leakage | Sensitive data present in raw alerts (names, IPs, emails, SSNs) surfaces unredacted in the generated analyst report | Output |
| T4 | Hallucination | Agent fabricates CVE IDs, threat actor names, or severity scores not grounded in the source alert data | Output |

T1 and T2 were validated experimentally in Week 2 using NeMo Guardrails 0.22.0 with Mistral 7B.
T3 and T4 will be addressed in the output guardrail layer in subsequent weeks using Presidio and
SelfCheckGPT-style consistency checking respectively.

## 3. Research Questions

1. Which classes of guardrails (input, output, semantic, access-control) are most critical for SOC agent safety?
2. What is the performance overhead introduced by guardrail layers in real-time alert triage?
3. How robust are existing guardrail frameworks against adversarial prompt injection embedded in security logs?
4. Can hallucination in threat reports be reliably detected without ground-truth labels?
5. How does guardrail classification reliability vary between LLM-based intent matching and deterministic rule-based approaches in adversarial SOC contexts?

> **Note on RQ5:** Initial experiments in Week 2 revealed that NeMo Guardrails' LLM-based
> intent classification failed to reliably intercept injection attempts when using a 7B local
> model (Mistral via Ollama). A deterministic Python-based input action using pattern matching
> proved more robust for security-critical blocking. RQ5 formalises this observation into a
> research question to be investigated systematically across multiple models and injection
> variants in the evaluation phase.

---

## 4. Proposed Methodology

### 4.1 Dataset
- Public SOC alert datasets: CICIDS, UNSW-NB15, CTU-13 (network intrusion)
- Synthetic adversarial prompts crafted to test injection resistance
- CVE and threat intelligence from NVD / MITRE ATT&CK

### 4.2 Approach

1. **Baseline LangChain SOC co-pilot** — Implement an alert intake → analysis → report
   pipeline using LangChain/LangGraph with Mistral 7B (via Ollama 0.30.8) as the local LLM
   backend. The prototype runs fully on CPU (Intel i7-1355U, 16GB RAM) with no external API
   dependency, ensuring no alert data leaves the local environment during development.

2. **Guardrail layering** — Wrap the baseline agent with NeMo Guardrails 0.22.0:
   - *Input layer*: deterministic Python-based action for injection pattern detection
     (preferred over LLM intent classification based on Week 2 findings), plus a keyword
     blocklist for known adversarial SOC log patterns.
   - *Output layer*: Presidio-based PII redaction (names, IPs, emails, SSNs) and a
     SelfCheckGPT-style consistency check for hallucination detection across sampled responses.

3. **Benchmarking** — Evaluate guardrail impact using:
   - Synthetic adversarial prompts modelled on CICIDS-2017 alert formats
   - Injection resistance measured as block rate before/after guardrails
   - Latency profiled on CPU-only hardware to establish a realistic baseline for
     resource-constrained deployments

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
| LLM API cost too high | Medium | Use Ollama with local models (Mistral 7B validated in Week 2) |
| No public SOC alert dataset with labels | Low | Use CICIDS-2017 or generate synthetic alerts |
| Guardrail latency too high for real-time | Medium | Profile and optimise; consider async pipeline |
| LLM-based intent classification unreliable for small models | High | Use deterministic Python actions for security-critical rails (validated in Week 2) |