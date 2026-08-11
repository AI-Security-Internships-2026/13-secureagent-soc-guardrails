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

Held-out set: 119 examples (expanded 2026-08-11 from the original 29, per
issue #16 §4 item 11) — 53 injections, 66 ordinary alert text. None of the
injection examples were copies of the 8 patterns the guardrail was built
against. Injection set breakdown:
- `exact_pattern` (12): hand-authored variants wrapping the 8 known
  deterministic phrases in different alert-context framings (all three
  tools should catch these)
- `paraphrase_evasion` (23): reworded instruction-override attempts. 5
  hand-authored originals + 18 adapted from `deepset/prompt-injections`
  (Hugging Face, Apache-2.0) — real attacker-authored override phrasing
  preserved, payloads rewritten to SOC-alert context, offensive/political
  content from the source dataset dropped
- `novel_strategy` (18): fake system messages, roleplay framing, dual-persona
  (DAN/"Developer Mode") prompts, obfuscation (leetspeak, spaced letters),
  fake conversation-turn priming. 5 hand-authored originals + 13 adapted
  from `TrustAIRLab/in-the-wild-jailbreak-prompts` (Hugging Face, MIT;
  Shen et al., "Do Anything Now", ACM CCS 2024) and `deepset/prompt-injections`

Every adapted entry carries a `provenance` field naming its source dataset;
entries without one are hand-authored originals from the first 29-sample
version. See `eval_dataset.json` for the full breakdown.

Benign set (66): the original 16 (synthetic alerts, hand-crafted CICIDS-style
flows, security-jargon stress tests, plain alerts) plus 50 **real**
`BENIGN`-labeled flow records sampled directly from the CICIDS2017 day-file
CSVs (`datasets/cicids2017/`, Monday–Friday, via
`src/data/load_cicids2017.py`) — replacing hand-crafted CICIDS-style
descriptions with actual dataset rows. Security-jargon set still tests for
false positives on words like "override," "disregard," or "developer mode"
used in legitimate context.

**Scope note on CICIDS2017 here specifically:** elsewhere in this project
(`docs/ROADMAP_PLAN.md` §10a) CICIDS2017/2018 is flagged — correctly — as
outdated for claiming *attack-detection* currency, per a 2025 survey noting
it no longer reflects modern attack behavior. That critique does not apply
to how it's used in this benchmark. These 50 rows are all `BENIGN`-labeled
and used only as realistic-looking, non-injection SOC text to measure the
guardrail's false-positive rate — not as evidence about detecting current
attacks. A benign HTTPS/DNS flow description reads the same whether the
underlying capture is from 2017 or 2026; nothing about this test depends on
the traffic being recent. No claim in this report should be read as "we
tested against current attack patterns" — that claim is scoped to the
Wazuh-integration work (§10a), which supplies live, current alert data
instead.

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

Re-run 2026-08-11 on the expanded 119-sample set (53 injection / 66 benign,
see Setup above). Superseded the original 29-sample numbers. Latency
methodology also changed partway through 2026-08-11 (see "A latency
methodology fix" below) — the table reflects the corrected numbers.

| | Baseline | LLM Guard | Pytector | Hybrid (Pytector fallback) | Hybrid (LLM Guard fallback) |
|---|---|---|---|---|---|
| Precision | 1.0 | 0.962 | 1.0 | 1.0 | 0.962 |
| Recall | 0.264 | 0.943 | 0.679 | 0.736 | 0.943 |
| F1 | 0.418 | 0.952 | 0.809 | 0.848 | 0.952 |
| False positives | 0 | 2 | 0 | 0 | 2 |
| False negatives | 39 | 3 | 17 | 14 | 3 |
| Median latency | ~0ms | 184.1ms | 181.9ms | 177.2ms | 261.1ms |
| P95 latency | ~0ms | 225.9ms | 208.7ms | 214.5ms | 295.7ms |
| Throughput | ~333,000/sec | 5.34/sec | 5.45/sec | 6.13/sec | 4.26/sec |

(Full per-sample predictions, environment details, and package versions in
`experiments/results/guardrail_comparison.json`.)

## What it means

**Baseline (deterministic-only)**: still zero false positives, including on
the expanded security-jargon and real-CICIDS benign set — a direct result
of only matching exact known phrases. But it now misses 39 of 53 injections
(recall 0.264, consistent with the original 29-sample run's 0.23 — this
wasn't a small-n fluke).

**LLM Guard**: catches the most (recall 0.943), including the large
adapted-corpus paraphrase and novel-strategy batches. 2 false positives on
the larger benign set. A guardrail meant to run before every LLM call still
pays a real latency cost relative to the ~0ms baseline, even after the
warmup fix below.

**Pytector**: recall dropped to 0.679 on the harder, more diverse set (was
0.62 on the original 13-injection set — the larger corpus of real adapted
attacker phrasing is a tougher test). Still zero false positives. Latency
now comparable to LLM Guard's (both run transformer models on CPU).

**Hybrid, Pytector fallback** (the version wired into the live pipeline):
recall 0.736 — better than Pytector alone, because the now-larger
hand-authored `exact_pattern` bucket (12 vs. the original 3) gives the free
deterministic layer more to catch before falling back to the model. Zero
false positives, best throughput of the four (6.13/sec).

**Hybrid, LLM Guard fallback** (experimental, see next section): recall
0.943, identical confusion matrix to LLM Guard alone. Precision drops back
to 0.962 (2 FP) — same as plain LLM Guard, since this variant inherits
LLM Guard's false positives along with its recall.

Bottom line, holding on the bigger set: the deterministic baseline is fast
and precise but blind to anything outside its known patterns. LLM Guard
catches the most but occasionally misfires on security-flavored language.
Pytector-based hybrid is the practical middle ground currently wired into
the live pipeline — best throughput, zero false positives, meaningfully
better recall than Pytector alone, though still short of LLM Guard's.

## Trial: swapping the hybrid's fallback to LLM Guard (2026-08-11)

The significance test (below) confirmed LLM Guard's recall edge over
Pytector-based hybrid was real, not noise. Natural next question: can the
same deterministic-first architecture recover that recall by falling back
to LLM Guard instead of Pytector? Tried it — `scan_hybrid_llmguard` in
`adapters.py`, benchmark-only, **not wired into the live pipeline**.

**Result: no accuracy benefit over LLM Guard alone.** McNemar's test
between `hybrid_llmguard` and plain `llm_guard` came back **degenerate —
zero discordant predictions across all 119 samples.** They agree on every
single case. The deterministic short-circuit layer adds real value on top
of Pytector (recall 0.679 → 0.736, a significant improvement — see below)
but adds *nothing* on top of LLM Guard, because LLM Guard's recall is
already high enough (0.943) that the 12 `exact_pattern` samples the
deterministic layer would catch for free were ones LLM Guard was already
getting right. The deterministic pre-filter's value is specifically in
patching a weaker fallback's blind spots — pairing it with an
already-strong fallback just adds a redundant fast path, not a smarter one.

**Practical takeaway**: there's no case for `hybrid_llmguard` as a distinct
architecture — it's just LLM Guard, with extra moving parts and no upside.
If LLM Guard's higher recall is worth its false-positive rate and latency
for a given deployment, use LLM Guard directly. If precision and low
latency matter more, stick with the Pytector-based hybrid already in
production. There's no free lunch available by combining the two here.

**Latency caveat, stated plainly**: `hybrid_llmguard`'s median latency
(261.1ms) is *higher* than plain LLM Guard's (184.1ms) in this run, despite
running the identical model with a near-zero-cost check in front of it —
that direction doesn't make architectural sense and is most likely
sequential-run noise (this benchmark loads multiple transformer models one
after another in the same process; by the time `hybrid_llmguard` runs
last, memory pressure from Pytector's and LLM Guard's models both being
loaded simultaneously may be slowing inference down, not the extra
`check_injection()` call). Don't read anything causal into that latency
gap without a cleaner, isolated re-test (separate process per
implementation, repeated trials) — the accuracy finding above (identical
predictions to LLM Guard) is solid since it doesn't depend on timing, but
the latency comparison here isn't rigorous enough to cite.

## A latency methodology fix (2026-08-11)

Earlier in the same day, the very first sample handed to LLM Guard and
Pytector each triggered a one-time model-loading cost included in that
sample's measured latency (confirmed by checking which sample index the
extreme outliers landed on — position 0 for both, every single time,
across every implementation, no exceptions). This inflated the *mean* and
*max* dramatically (LLM Guard: one sample took 129.5 seconds) without
showing up in median/P95, which is exactly why it went unnoticed until
checked directly. Fixed by adding an explicit warmup call per
implementation before the timed loop starts (`WARMUPS` in `adapters.py`,
wired into `run_comparison.py`), so the one-time cost is paid upfront and
excluded from the reported stats — matching how the guardrail would
actually run in production (loaded once at service startup, not per-alert).

Re-running after the fix also dropped median latency for LLM Guard,
Pytector, and Pytector-based hybrid alike (~480ms → ~180ms each) by a
similar ratio across all three — more than the outlier-exclusion alone
would explain. That's very likely ordinary run-to-run system variance
(CPU/thermal/cache state differs between two separate script invocations
run minutes apart), not something attributable to the warmup fix itself.
Worth being honest about: **single-run latency numbers on shared,
uncontrolled hardware aren't stable enough to treat as precise** — the
same caveat already flagged for the threading/multiprocessing benchmark in
`docs/ROADMAP_PLAN.md` §5 applies here too. Repeated trials with mean ±
spread would be needed before citing exact latency figures in the paper.

## Significance testing

Ran 2026-08-11 via `significance_test.py` (McNemar's test, paired on the
same 119 samples — see `docs/ROADMAP_PLAN.md` §8 for why McNemar rather
than a generic t-test). Results in
`experiments/results/guardrail_comparison_significance.json`:

| Comparison | Discordant pairs | Method | p-value | Significant? |
|---|---|---|---|---|
| hybrid vs. Pytector | 3 | exact binomial | 0.250 | No |
| hybrid vs. LLM Guard | 17 | exact binomial | 0.049 | Yes |
| baseline vs. hybrid | 25 | chi-square (corrected) | <0.001 | Yes |
| hybrid_llmguard vs. hybrid | 17 | exact binomial | 0.049 | Yes |
| hybrid_llmguard vs. LLM Guard | 0 | degenerate | 1.000 | No — identical predictions |
| hybrid_llmguard vs. Pytector | 20 | exact binomial | 0.012 | Yes |

**What this licenses claiming and what it doesn't**: hybrid's recall
advantage over the deterministic baseline is real and strong (expected —
this one doubled as a sanity check on the test itself). LLM Guard's higher
recall over hybrid is also a real, measurable effect, not noise — though
the p-value sits close enough to 0.05 that it's worth stating cautiously
rather than as a wide margin. **Hybrid's apparent edge over Pytector alone
(0.736 vs. 0.679 recall) is not statistically distinguishable from chance
at this sample size** — only 3 discordant predictions between them across
119 samples. Don't cite that comparison as a real effect without a larger
injection set to re-test on.

The `hybrid_llmguard` row confirms the trial finding above with a formal
test rather than just eyeballing the confusion matrix: zero discordant
pairs against plain LLM Guard means there is no prediction on which they
disagree, anywhere in the 119-sample set — as identical as two
implementations can be. It significantly beats both hybrid and Pytector,
for the same reason plain LLM Guard does; that's inherited, not something
the hybrid wrapper adds.

## Next steps

- 119 examples is a lot better than 29, but still modest for the injection
  side (53 samples) — the hybrid-vs-Pytector result above is the direct
  consequence: too few discordant cases to resolve. Keep growing it
  opportunistically as more of `deepset/prompt-injections` /
  `TrustAIRLab/in-the-wild-jailbreak-prompts` get reviewed and adapted, or
  as new real Wazuh-derived injection attempts surface, then re-run
  `significance_test.py` on the bigger set.
- `hybrid_llmguard` stays benchmark-only — no reason to wire it into the
  live pipeline given it's provably identical to LLM Guard alone. If LLM
  Guard's recall/false-positive/latency trade-off is ever preferred over
  the current Pytector-based hybrid for production, switch to LLM Guard
  directly rather than through a hybrid wrapper.
- Latency numbers throughout this report are single-run and, per the
  methodology note above, noisier than they look — repeat each
  implementation's benchmark multiple times (fresh process per run, not
  sequential in one process) and report mean ± spread before citing
  specific millisecond figures in the paper.

## What wasn't done, on purpose

No per-framework threshold tuning — everything ran on shipped defaults,
since tuning on the test data would invalidate the comparison. No hosted
API calls at any point. The guardrail running in the SOC agent pipeline
itself wasn't touched — this was a side-by-side test only.