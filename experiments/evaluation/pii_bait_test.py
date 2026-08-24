"""
experiments/evaluation/pii_bait_test.py

Runs the PII-redaction guardrail (src/guardrails/pii_guardrail.py, wired
into src.agent.soc_agent.analyse_alert) against the pii_bait_alerts.py set
through the FULL guardrailed pipeline -- a real Groq call per alert, same
as cve_bait_test.py/attack_bait_test.py, so this needs live API access and
is not part of the offline pytest suite.

Two things are measured, and they answer different questions:

  pii_found: does the FINAL report (as returned by analyse_alert, i.e.
    AFTER redaction already ran) carry a non-empty `pii_detections` list --
    did the LLM echo something from the raw evidence that the guardrail
    then caught and redacted. For PII_ALERTS this is the "did sensitive
    data even survive into the LLM's generated prose at all" signal (a
    model that summarizes abstractly rather than quoting raw fields would
    legitimately show pii_found=False with nothing wrong). For
    CLEAN_ALERTS this must stay False -- any True here is a false positive.

  residual_pii: independently re-scans the FINAL report's own text fields
    (the ones soc_agent.py already overwrote with redacted_fields) with the
    same detector. Should always be empty -- redact_report_fields()
    detects and redacts in the same pass, so nothing should survive. A
    non-empty residual means the guardrail's own redaction step missed
    something it had actually just detected (a real bug, not merely low
    recall) -- kept as its own explicit check rather than assumed away.

Checkpointed after every alert (established pattern in this project after
losing an unrecoverable synthetic-judge run to a quota crash -- see
llm_judge_synthetic_test.py's _write_output), even though this set is
small enough that the risk is low.

Usage:
    python -m experiments.evaluation.pii_bait_test
"""

import json
import os

from src.agent.soc_agent import analyse_alert
from src.guardrails.grounding_utils import REPORT_TEXT_FIELDS
from src.guardrails.pii_guardrail import detect_pii
from experiments.evaluation.pii_bait_alerts import PII_ALERTS, CLEAN_ALERTS

OUTPUT_PATH = "experiments/results/pii_bait_results.json"


def _report_text(report: dict) -> str:
    return " ".join(str(report.get(field, "")) for field in REPORT_TEXT_FIELDS)


def _write_output(n_total: int, results: list, complete: bool) -> dict:
    pii_rows = [r for r in results if r["kind"] == "pii"]
    clean_rows = [r for r in results if r["kind"] == "clean"]

    pii_found_count = sum(1 for r in pii_rows if r["pii_found"])
    false_positive_count = sum(1 for r in clean_rows if r["pii_found"])
    residual_count = sum(1 for r in results if r["residual_pii"])

    output = {
        "task": "PII-redaction guardrail bait test -- full pipeline, live Groq calls",
        "n_total": n_total,
        "n_completed": len(results),
        "run_complete": complete,
        "n_pii_alerts": len(pii_rows),
        "n_clean_alerts": len(clean_rows),
        "pii_alerts_with_detection": pii_found_count,
        "pii_alerts_detection_rate": round(pii_found_count / len(pii_rows), 4) if pii_rows else None,
        "clean_alerts_false_positives": false_positive_count,
        "clean_alerts_false_positive_rate": round(false_positive_count / len(clean_rows), 4) if clean_rows else None,
        "residual_pii_after_redaction_count": residual_count,
        "results": results,
    }

    os.makedirs("experiments/results", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    return output


def run():
    all_items = [("pii", item) for item in PII_ALERTS] + [("clean", item) for item in CLEAN_ALERTS]
    n_total = len(all_items)

    # Resume from a prior checkpoint if one exists -- same pattern as
    # cve_bait_test.py/attack_bait_test.py/selfcheckgpt_test.py, added once
    # this set grew from 14 to 60 alerts (60 real Groq calls is real quota
    # exposure, not free to just redo from scratch after a crash or a
    # daily-quota wall mid-run).
    results = []
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            prior = json.load(f)
        if isinstance(prior.get("results"), list):
            results = prior["results"]
            print(f"Resuming from checkpoint: {len(results)} alerts already completed\n")
    done_ids = {r["alert_id"] for r in results}
    remaining = [(kind, item) for kind, item in all_items if item["alert"].alert_id not in done_ids]

    print(f"Running {len(remaining)}/{n_total} remaining alerts through the full guardrailed pipeline\n")

    for i, (kind, item) in enumerate(remaining):
        alert = item["alert"]
        print(f"[{len(results)+1}/{n_total}] {alert.alert_id} ({kind})...")
        report = analyse_alert(alert)

        detections = report.get("pii_detections", [])
        residual = detect_pii(_report_text(report))

        results.append({
            "alert_id": alert.alert_id,
            "kind": kind,
            "expected_entities": sorted(item.get("expected_entities", [])),
            "detected_entities": sorted({d["entity_type"] for d in detections}),
            "pii_detections": detections,
            "pii_found": len(detections) > 0,
            "residual_pii": residual,
        })
        status = f"detected {sorted({d['entity_type'] for d in detections})}" if detections else "nothing detected"
        residual_flag = " [RESIDUAL PII AFTER REDACTION]" if residual else ""
        print(f"    {status}{residual_flag}")

        _write_output(n_total, results, complete=False)

    output = _write_output(n_total, results, complete=(len(results) == n_total))

    print(f"\n=== PII bait test summary ===")
    print(f"PII alerts with a detection: {output['pii_alerts_with_detection']}/{output['n_pii_alerts']} "
          f"({output['pii_alerts_detection_rate']:.1%})" if output["pii_alerts_detection_rate"] is not None else "")
    print(f"Clean alerts false-flagged: {output['clean_alerts_false_positives']}/{output['n_clean_alerts']} "
          f"({output['clean_alerts_false_positive_rate']:.1%})" if output["clean_alerts_false_positive_rate"] is not None else "")
    print(f"Residual PII surviving redaction: {output['residual_pii_after_redaction_count']}")
    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
