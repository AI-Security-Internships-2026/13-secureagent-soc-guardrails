# Weekly Progress Log: SecureAgent-SOC

**Student:** Emaan Afroz Khuram
**GitHub:** @emaankhuram

---

## Week 1

**Branch:** `emaan-week-01`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/9

### Completed this week
- [x] Read README and proposal
- [x] Set up local Python environment
- [x] Ran `src/main.py` successfully
- [x] Wrote personal introduction (below)
- [x] Identified 5 related papers / tools / datasets

### Personal Introduction
I am a third-year Computer Science student at NUST SEECS with a strong academic and practical foundation in advanced machine learning, backend engineering, and multi-agent systems. My technical experience includes developing predictive pipelines using tree-based models, fine-tuning Vision Transformers, and engineering secure, agentic workflows inside containerized environments. Through this internship at CNIT/PNTLab Pisa, I hope to master the architecture of runtime LLM guardrail frameworks and understand how to build resilient, production-ready AI pipelines that can withstand adversarial exploitation. Ultimately, I aim to apply these secure engineering methodologies to deep-tech solutions within high-stakes, data-sensitive domains.

### Problems / Blockers
no blockers faced

### Next week plan
- Read the 5 identified papers
- Set up NeMo Guardrails locally
- Draft `docs/proposal.md` sections 3 and 4

---

## Week 2

**Branch:** `emaan-week-02`
**PR link:** _[Add after opening PR]_

### Completed this week
- [x] Read all 5 literature review papers identified in Week 1
- [x] Installed Ollama 0.30.8 and pulled Mistral 7B (4.4GB) as local LLM backend
- [x] Created `experiments/nemo_test/` with `config.yml`, `rails.co`, and `actions.py`
- [x] Wired Mistral into NeMo Guardrails 0.22.0 via Ollama's OpenAI-compatible `/v1` endpoint
- [x] Implemented and tested three guardrail scenarios: greeting flow, injection blocking, legitimate SOC query passthrough
- [x] Discovered that LLM-based intent classification in NeMo is unreliable for injection detection with 7B models, switched to deterministic Python action-based input rail
- [x] Drafted and expanded `docs/proposal.md` sections 3 and 4 with actual tech stack details and added RQ5 based on week 2 findings

### Problems / Blockers
- NeMo Guardrails initially returned 404 when connecting to Ollama — resolved by adding `/v1` to the base URL in `config.yml` to use Ollama's OpenAI-compatible endpoint.
- LLM-based Colang intent classification failed to reliably block injection attempts with Mistral 7B, resolved by replacing the intent-matching rail with a deterministic Python input action using pattern matching. This is now documented as RQ5 in the proposal.

### Next week plan
- Begin building the baseline LangChain SOC co-pilot (alert intake → analysis → report pipeline)
- Integrate the NeMo Guardrails input layer with the LangChain agent
- Start drafting `docs/proposal.md` remaining sections


