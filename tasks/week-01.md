# Week 1 Tasks — SecureAgent-SOC

**Student:** Emaan Afroz Khuram (@emaankhuram)
**Branch:** `emaan-week-01`
**PR target:** `dev`

---

## Checklist

### a) Orientation
- [ ] Read `README.md` in full — understand the system architecture diagram
- [ ] Read `docs/proposal.md` in full
- [ ] Accept the GitHub repository invitation

### b) Environment setup
```bash
git clone https://github.com/AI-Security-Internships-2026/13-secureagent-soc-guardrails.git
cd 13-secureagent-soc-guardrails
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/main.py

git checkout dev && git pull origin dev
git checkout -b emaan-week-01
```

### c) Documentation
- [ ] Add personal introduction in `docs/weekly-progress.md`
- [ ] Explore NeMo Guardrails: https://github.com/NVIDIA/NeMo-Guardrails

### d) Literature search
Identify **5 papers or resources** on these topics and add to `docs/literature-review.md`:
1. Prompt injection attacks on LLM agents
2. LLM hallucination detection
3. SOC automation with LLMs
4. Guardrail frameworks (NeMo, Guardrails AI)
5. PII detection in NLP systems

### e) First Pull Request
```bash
git add docs/weekly-progress.md docs/literature-review.md
git commit -m "[Week 01] Add intro and initial literature notes"
git push origin emaan-week-01
```
Open PR on GitHub: base `dev` ← compare `emaan-week-01`
Title: `[Week 01] Introduction and literature search`
