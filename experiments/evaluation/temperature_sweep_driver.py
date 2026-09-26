"""
experiments/evaluation/temperature_sweep_driver.py

Issue #44 (R5), Task 1 -- temperature-sensitivity sweep driver.

Scope decision (documented, not silent): the issue's own Inputs section
names "60 CVE pool items (30 stated + 30 withheld)", but all four
required metrics -- P_volunteer, P_correct_but_unsupported,
SelfCheckGPT_recall_for_unsupported, LLMCite_detection_rate -- are only
meaningful on the WITHHELD (PROMPTED) class: the STATED class is given
its CVE directly, so "volunteering" isn't a coherent concept there, and
neither "unsupported" nor "recall on the unsupported subset" has a
denominator on a class where nothing is ever withheld. Restricting the
sweep to the 30 PROMPTED alerts (selfcheckgpt_alerts.py -- the identical
pool and prompt templates Sects. 4.4/4.5 already use, no new examples)
halves the call count (450 vs. 900) without dropping anything either the
issue's four metrics or Task 2's F6 figure need computed from the
STATED half.

Reuses, rather than reimplements:
  - selfcheckgpt.py's consistency_score() for majority_id/agreement_rate/
    flagged_unstable -- the exact same self-consistency scoring already
    used for the paper's central Sect. 4.4 result, at every temperature
    in the grid, not just SAMPLING_TEMPERATURE=0.7.
  - output_guardrail.py's verify_cve() for the authoritative-source
    classification of whatever citation the model actually volunteers.
    Uses LIVE NVD verification (not the frozen snapshot, issue #48/E3),
    a deliberate choice: this sweep's total NVD-lookup volume is small
    and bounded (at most 150 lookups, one per (alert, temperature) pair
    that actually produces a majority citation -- likely far fewer,
    since low temperatures rarely volunteer anything at all per Sect.
    4.2's own finding), and NVD's rate limit is entirely independent of
    Groq's token quota, so this adds no competing pressure on the
    scarce resource this sweep already needs 450 calls of. It also
    sidesteps the missing-local-snapshot crash issue #42/R3 hit
    (docs/all_results.md #76) entirely, since whatever CVE the model
    volunteers here gets verified live rather than needing to already
    exist in a pre-captured snapshot file.

Behaviour:
  - Loads the 30 PROMPTED alerts from selfcheckgpt_alerts.py.
  - Loops (temperature, alert) in deterministic grid order across
    [0.1, 0.3, 0.5, 0.7, 1.0].
  - Resume mode: experiments/results/temperature_sweep_prompted_30x5.jsonl
    is append-only. Skips any (temperature, alert_id) pair already
    present. Every row flushed + fsynced immediately, same crash-safety
    pattern as ablation_driver.py.
  - Retries with exponential backoff on RateLimitError/
    InternalServerError/APIConnectionError/APITimeoutError, identical
    shape to ablation_driver.py's.
  - Per (temperature, alert): 3 resamples at that temperature (not
    SelfCheckGPT's fixed 0.7 -- the whole point of this sweep is
    varying it), scored via consistency_score(). If a majority citation
    exists, verify it live against NVD for its taxonomy classification
    and topical-overlap score. LLMCite_detection_rate on the confirmed-
    unsupported (REAL_AND_PLAUSIBLE) subset is 1.0 by pipeline
    construction, not computed separately: a PROMPTED alert's evidence
    text never contains a CVE-shaped string at all, so any citation the
    model makes is automatically Stage-1-ungrounded, and every
    ungrounded citation unconditionally sets requires_review=True
    (Sect. 3.5) regardless of its Stage-2 classification -- this IS the
    flat-at-1.0 line the issue's own F6 plot spec expects, not a
    shortcut around computing it.

Usage:
    python -m experiments.evaluation.temperature_sweep_driver             # resume, run to completion
    python -m experiments.evaluation.temperature_sweep_driver --limit 50  # do up to 50 new live calls, then stop
    python -m experiments.evaluation.temperature_sweep_driver --validate  # check completeness, no calls
    python -m experiments.evaluation.temperature_sweep_driver --summarize # (re)compute summary JSON from the JSONL, no calls
"""

import argparse
import json
import os
import time

from dotenv import load_dotenv
from groq import RateLimitError, InternalServerError, APIConnectionError, APITimeoutError
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq
from scipy.stats import norm

from src.agent.soc_agent import SYSTEM_PROMPT, format_alert, MODEL_NAME
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.output_guardrail import extract_cves, verify_cve
from src.guardrails.selfcheckgpt import consistency_score, _extract_report_text
from experiments.evaluation.selfcheckgpt_alerts import PROMPTED_ALERTS

load_dotenv()

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
JSONL_PATH = os.path.join(RESULTS_DIR, "temperature_sweep_prompted_30x5.jsonl")
SUMMARY_PATH = os.path.join(RESULTS_DIR, "temperature_sweep_summary.json")

TEMPERATURE_GRID = [0.1, 0.3, 0.5, 0.7, 1.0]
N_RESAMPLES = 3
RETRYABLE = (RateLimitError, InternalServerError, APIConnectionError, APITimeoutError)

_llm_cache = {}


def _llm_for(temperature: float) -> ChatGroq:
    if temperature not in _llm_cache:
        _llm_cache[temperature] = ChatGroq(
            api_key=os.getenv("GROQ_API_KEY"), model=MODEL_NAME, temperature=temperature,
        )
    return _llm_cache[temperature]


def _sample_with_retry(llm, messages, max_retries: int = 5, base_delay: float = 8.0):
    for attempt in range(max_retries):
        try:
            return llm.invoke(messages)
        except RETRYABLE as e:
            if attempt == max_retries - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(f"    {type(e).__name__}, waiting {wait:.0f}s...", flush=True)
            time.sleep(wait)


def _load_done_pairs():
    done = set()
    if os.path.exists(JSONL_PATH):
        with open(JSONL_PATH, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                done.add((row["temperature"], row["alert_id"]))
    return done


def _append_row(row):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(JSONL_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
        f.flush()
        os.fsync(f.fileno())


def run(limit=None):
    done = _load_done_pairs()
    total_target = len(TEMPERATURE_GRID) * len(PROMPTED_ALERTS)
    if done:
        print(f"Resuming: {len(done)}/{total_target} (temperature, alert) pairs already done\n")

    calls_this_invocation = 0
    for temperature in TEMPERATURE_GRID:
        for item in PROMPTED_ALERTS:
            alert = item["alert"]
            if (temperature, alert.alert_id) in done:
                continue
            if limit is not None and calls_this_invocation >= limit:
                print(f"\nHit --limit {limit} new calls this invocation, stopping.")
                return

            idx = len(done) + 1
            print(f"[T={temperature}] ({idx}/{total_target}) {alert.alert_id}...", flush=True)

            evidence_pack = build_evidence_pack(alert)
            llm = _llm_for(temperature)
            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=f"Analyse this security alert and produce a threat report:\n{format_alert(alert)}"),
            ]

            samples_extracted = []
            for _ in range(N_RESAMPLES):
                response = _sample_with_retry(llm, messages)
                report_text = _extract_report_text(response.content)
                samples_extracted.append(extract_cves(report_text))
                calls_this_invocation += 1

            score = consistency_score(samples_extracted)

            classification = None
            topical_overlap = None
            if score["majority_id"] is not None:
                verification = verify_cve(score["majority_id"], evidence_pack["text"], use_snapshot=False)
                classification = verification["classification"]
                topical_overlap = verification["topical_overlap"]

            row = {
                "temperature": temperature,
                "alert_id": alert.alert_id,
                "ground_truth_cve": item["ground_truth_cve"],
                "samples": [sorted(s) for s in samples_extracted],
                "any_citation_rate": score["any_citation_rate"],
                "majority_id": score["majority_id"],
                "agreement_rate": score["agreement_rate"],
                "flagged_unstable": score["flagged_unstable"],
                "citation_occurred": score["majority_id"] is not None,
                "classification": classification,
                "topical_overlap": topical_overlap,
            }
            _append_row(row)
            done.add((temperature, alert.alert_id))

    print(f"\nAll {total_target} (temperature, alert) pairs complete.")
    summarize()


def validate():
    done = _load_done_pairs()
    total_target = len(TEMPERATURE_GRID) * len(PROMPTED_ALERTS)
    if len(done) == total_target:
        print(f"{len(done)}/{total_target} rows, all 5 temperatures present for each of {len(PROMPTED_ALERTS)} alerts.")
        return
    missing_by_temp = {}
    all_alert_ids = {item["alert"].alert_id for item in PROMPTED_ALERTS}
    for t in TEMPERATURE_GRID:
        have = {aid for (temp, aid) in done if temp == t}
        missing = all_alert_ids - have
        if missing:
            missing_by_temp[t] = len(missing)
    print(f"{len(done)}/{total_target} rows present. Missing {total_target - len(done)}:")
    for t, n_missing in missing_by_temp.items():
        print(f"  T={t}: {n_missing} missing")


def wilson_ci(successes, n, alpha: float = 0.05):
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def summarize():
    rows = []
    if os.path.exists(JSONL_PATH):
        with open(JSONL_PATH, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]

    summary = {
        "temperature_grid": TEMPERATURE_GRID,
        "n_alerts": len(PROMPTED_ALERTS),
        "n_resamples": N_RESAMPLES,
        "pool": "PROMPTED_ALERTS only (see module docstring for scope decision)",
        "per_temperature": [],
    }

    for t in TEMPERATURE_GRID:
        trows = [r for r in rows if r["temperature"] == t]
        n = len(trows)
        n_volunteer = sum(1 for r in trows if r["citation_occurred"])
        plausible_rows = [r for r in trows if r["classification"] == "REAL_AND_PLAUSIBLE"]
        n_plausible = len(plausible_rows)
        n_plausible_flagged_unstable = sum(1 for r in plausible_rows if r["flagged_unstable"])

        p_volunteer = n_volunteer / n if n else None
        p_plausible = n_plausible / n if n else None
        recall_on_plausible = (n_plausible_flagged_unstable / n_plausible) if n_plausible else None
        # LLMCite detection on the confirmed-unsupported subset is 1.0 by
        # pipeline construction -- see module docstring.
        detection_on_plausible = 1.0 if n_plausible else None

        summary["per_temperature"].append({
            "temperature": t,
            "n": n,
            "n_complete": n == len(PROMPTED_ALERTS),
            "p_volunteer": round(p_volunteer, 4) if p_volunteer is not None else None,
            "p_volunteer_wilson_ci_95": wilson_ci(n_volunteer, n),
            "p_correct_but_unsupported": round(p_plausible, 4) if p_plausible is not None else None,
            "p_correct_but_unsupported_wilson_ci_95": wilson_ci(n_plausible, n),
            "n_real_and_plausible": n_plausible,
            "selfcheckgpt_recall_on_unsupported": round(recall_on_plausible, 4) if recall_on_plausible is not None else None,
            "selfcheckgpt_recall_wilson_ci_95": wilson_ci(n_plausible_flagged_unstable, n_plausible) if n_plausible else (None, None),
            "llmcite_detection_rate_on_unsupported": detection_on_plausible,
        })

    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSummary written to {SUMMARY_PATH}")
    for row in summary["per_temperature"]:
        print(f"T={row['temperature']}: volunteer={row['p_volunteer']}  "
              f"plausible={row['p_correct_but_unsupported']} (n={row['n_real_and_plausible']})  "
              f"SelfCheckGPT_recall={row['selfcheckgpt_recall_on_unsupported']}  "
              f"LLMCite_detection={row['llmcite_detection_rate_on_unsupported']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Do up to N new live calls, then stop.")
    parser.add_argument("--validate", action="store_true", help="Check completeness, no calls.")
    parser.add_argument("--summarize", action="store_true", help="(Re)compute summary JSON from the JSONL, no calls.")
    args = parser.parse_args()

    if args.validate:
        validate()
    elif args.summarize:
        summarize()
    else:
        run(limit=args.limit)
