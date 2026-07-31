# Guardrail Comparison Report (Issue #16)

## What this is

A benchmark comparing this project's prompt-injection guardrail against two
maintained open-source alternatives — LLM Guard (Protect AI) and Pytector.
Separate from the main project report.

## Why

The guardrail had only been tested against the exact patterns it was built
to catch, plus real CICIDS2017 traffic for false positives. That doesn't
show how it handles anything it wasn't written for, or how it compares to
existing tools. This benchmark checks that.

## Setup

Only one function was tested: prompt-injection detection. It's the only
part of the repo with a direct equivalent in these frameworks (the CVE
hallucination guardrail, for example, doesn't).

## Reproduction

From a clean checkout at the repository root, run:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m experiments.evaluation.guardrail_comparison.run_comparison
```

The command writes the comparison JSON to
`experiments/results/guardrail_comparison.json`.

Held-out set: 29 examples — 13 injections, 16 ordinary alert text. None of
the injection examples were copies of the 8 patterns the guardrail was
built against. Injection set breakdown:
- Exact matches to known patterns (all three tools should catch these)
- Paraphrases of the same intent ("please disregard the guidance given to
  you earlier" vs. "ignore previous instructions")
- Novel attack strategies (fake system messages, roleplay framing,
  translation trick)

Benign set included real security alerts using words like "override,"
"disregard," or "developer mode" in legitimate context, to test for false
positives on security jargon.

## Why only two frameworks

- **NeMo Guardrails**: injection detection needs either an LLM judging the
  prompt (hosted API, ruled out by the task) or a heuristic fallback that
  isn't comparable to a classifier. Already tested in week 2 and found
  unreliable with small models.
- **LlamaFirewall (PromptGuard)**: model is gated behind a Meta license on
  HuggingFace, requiring an approved token. Not reproducible for others.
- **Guardrails AI** (originally planned): the wanted validator
  (`guardrails/detect_prompt_injection`, local model) has been pulled from
  their package index — `guardrails hub install` fails even after
  authenticating. The only available validator
  (`sainatha/prompt_injection_detector`) sends prompts to a hosted LLM
  (OpenAI `gpt-3.5-turbo` by default), which the task explicitly ruled out.
  **Pytector** was swapped in instead — pip-installable, local DeBERTa
  model, no API key.

## Results

| | This project's guardrail | LLM Guard | Pytector |
|---|---|---|---|
| Precision | 1.0 | 0.87 | 1.0 |
| Recall | 0.23 | 1.0 | 0.62 |
| F1 | 0.375 | 0.93 | 0.76 |
| False positives | 0 | 2 | 0 |
| False negatives | 10 | 0 | 5 |
| Median latency | ~0ms | 450ms | 452ms |
| Throughput | ~494,000/sec | 0.49/sec | 1.47/sec |

(Full per-sample predictions, environment details, and package versions in
the JSON.)

## What it means

**This project's guardrail**: zero false positives, including on the
security-jargon test cases — a direct result of only matching exact known
phrases. But it missed 10 of 13 injections, catching almost nothing beyond
patterns it already knew. Paraphrases and novel strategies got through
untouched.

**LLM Guard**: caught all 13 injections, including the novel ones. Flagged
2 legitimate alerts as false positives, and runs ~1000x slower per check
than the baseline (450ms median). That latency is a real cost for a
guardrail meant to run before every LLM call.

**Pytector**: caught 8 of 13, no false positives. Missed 5 — worth checking
which ones to see if it's failing on paraphrases, novel strategies, or
both. Latency similar to LLM Guard (both run transformer models on CPU).

Bottom line: the current guardrail is fast and precise but blind to
anything outside its known patterns. The ML-based tools catch more but cost
latency and occasionally misfire on security-flavored language. Which
matters more depends on where the guardrail sits in the pipeline.

## Next steps

- Test a hybrid: run the fast deterministic check first, fall back to
  Pytector only for alerts that pass it. Keeps most traffic cheap while
  covering more attacks.
- 29 examples is small — one misclassification moves recall ~8 points.
  Build a larger, more varied test set before treating these numbers as
  final.

## What wasn't done, on purpose

No per-framework threshold tuning — everything ran on shipped defaults,
since tuning on the test data would invalidate the comparison. No hosted
API calls at any point. The guardrail running in the SOC agent pipeline
itself wasn't touched — this was a side-by-side test only.