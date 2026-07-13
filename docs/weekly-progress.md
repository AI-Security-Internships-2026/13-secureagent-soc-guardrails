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
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/10

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

## Week 3

**Branch:** `emaan-week-03`
**PR link:** https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails/pull/11

### Completed this week
- [x] Built baseline SOC co-pilot agent (alert intake → LLM analysis → structured report)
- [x] Defined SecurityAlert dataclass with typed fields in `src/agent/alert_schema.py`
- [x] Created 3 synthetic test alerts: SSH brute force (HIGH), data exfiltration (CRITICAL), port scan (MEDIUM)
- [x] Integrated Groq API (llama-3.1-8b-instant) as LLM backend — switched from Ollama for faster inference per supervisor recommendation
- [x] Agent produces structured JSON reports with severity assessment, threat summary, recommended action, confidence score, and reasoning
- [x] Results saved to `experiments/results/baseline_results.json`

### Problems / Blockers
- `llama3-8b-8192` model was decommissioned by Groq — resolved by switching to `llama-3.1-8b-instant` which is the current recommended replacement
- Model name was hardcoded in multiple places — resolved by defining a single `MODEL_NAME` constant at the top of `soc_agent.py`

### Next week plan
- Wrap the baseline agent with the input guardrail layer
- Create `src/guardrails/` folder with proper separation of concerns
- Measure how many test alerts are correctly blocked/passed
- Begin building evaluation harness with precision/recall measurement

---

## Week 4

**Branch:** `emaan-week-04`
**PR link:** _[Add after opening PR]_

### Completed this week
- [x] Created `src/guardrails/input_guardrail.py` with deterministic pattern-matching injection detector
- [x] Wired input guardrail into SOC agent pipeline — guardrail runs before every LLM call
- [x] Added ALERT-004: synthetic malicious alert with injection phrase embedded in description and payload to simulate real attacker behaviour
- [x] All reports now include `guardrail_blocked` field for programmatic measurement
- [x] Added guardrail summary output: total processed, blocked, passed
- [x] Renamed output to `experiments/results/guardrail_results.json` to preserve baseline results as comparison point

### Guardrail measurement results
| Alert | Type | Decision | Correct |
|---|---|---|---|
| ALERT-001 | SSH brute force | Passed | ✓ |
| ALERT-002 | Data exfiltration | Passed | ✓ |
| ALERT-003 | Port scan | Passed | ✓ |
| ALERT-004 | Injection attempt | Blocked | ✓ |

4/4 correct — 0 false positives, 0 false negatives on synthetic test set.

### Problems / Blockers
- Guardrail logic was initially mixed into agent code, refactored into separate `src/guardrails/` folder to match architecture diagram and maintain clean separation of concerns.

### Next week plan
- scalability (prompts per second)

