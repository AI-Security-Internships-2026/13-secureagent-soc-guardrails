"""
experiments/evaluation/make_ablation_table_t6.py

Issue #42 (R3), Task 3 — builds Table T6, the 6-config ablation summary
table, from the now-complete `experiments/results/ablation_full.jsonl`
(2,616 rows: 6 configs x 436 alerts, see docs/all_results.md #75-#83).

Deviations from the issue's own template, both made for honesty rather
than convenience:

  - "#PII-TP (FPR)" -> "#PII detections". The pool has no ground-truth
    PII labels per alert, so a true/false-positive rate can't actually
    be computed or verified here -- reporting a raw detection count
    instead of a fabricated-looking FPR number.

  - "Unique alerts caught" / "Alerts lost vs Full" (two separate columns
    in the issue's template) -> reported as one pair, "alerts lost" and
    "alerts gained" vs. Full, computed directly from set difference on
    each config's flagged-alert-id set. Reporting both directions (not
    just the loss) matters here specifically because each (config,
    alert) row is an independent LIVE LLM call -- there is no shared
    "same generation, different guardrail" pairing -- so some of the
    churn between any two configs is ordinary sampling variance, not a
    causal effect of removing that guardrail. This is most visible on
    C1 (input guardrail off): input_guardrail never actually blocked a
    single alert in this pool in ANY config, so any C0-vs-C1 difference
    is, by construction, entirely sampling noise rather than a real
    causal signal -- worth stating plainly rather than implying a clean
    causal read the data can't support.

Usage:
    python -m experiments.evaluation.make_ablation_table_t6
"""

import json
import os
import statistics
from collections import defaultdict

RESULTS_PATH = "experiments/results/ablation_full.jsonl"
OUT_JSON_PATH = "experiments/results/ablation_table_t6.json"

CONFIG_ORDER = ["C0", "C1", "C2", "C3", "C4", "C5"]
CONFIG_NAMES = {
    "C0": "Full pipeline",
    "C1": r"$-$Input",
    "C2": r"$-$CVE",
    "C3": r"$-$ATT\&CK",
    "C4": r"$-$PII",
    "C5": "None",
}


def _iqr(values):
    if len(values) < 2:
        return (0.0, 0.0)
    q1, q3 = statistics.quantiles(values, n=4)[0], statistics.quantiles(values, n=4)[2]
    return (q1, q3)


def compute():
    stats = defaultdict(lambda: {
        "n": 0, "ungrounded": 0, "requires_review": 0, "pii_detections": 0,
        "input_fp": 0, "runtimes": [], "flagged_alerts": set(),
    })

    with open(RESULTS_PATH, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            cfg = row["config_id"]
            rep = row.get("output_report") or {}
            s = stats[cfg]
            s["n"] += 1
            s["ungrounded"] += len(rep.get("hallucinated_cves") or []) + \
                len(rep.get("hallucinated_attack_techniques") or [])
            if rep.get("requires_review"):
                s["requires_review"] += 1
                s["flagged_alerts"].add(row["alert_id"])
            s["pii_detections"] += len(rep.get("pii_detections") or [])
            if rep.get("guardrail_blocked"):
                s["input_fp"] += 1
            rt = row.get("runtime_ms")
            if isinstance(rt, (int, float)):
                s["runtimes"].append(rt)

    full_flagged = stats["C0"]["flagged_alerts"]

    table = []
    for cfg in CONFIG_ORDER:
        s = stats[cfg]
        median_ms = statistics.median(s["runtimes"]) if s["runtimes"] else 0.0
        q1, q3 = _iqr(s["runtimes"])
        if cfg == "C0":
            lost, gained = None, None
        else:
            lost = len(full_flagged - s["flagged_alerts"])
            gained = len(s["flagged_alerts"] - full_flagged)
        table.append({
            "config_id": cfg,
            "name": CONFIG_NAMES[cfg],
            "n_alerts": s["n"],
            "ungrounded_detections": s["ungrounded"],
            "requires_review_flags": s["requires_review"],
            "requires_review_pct": round(100 * s["requires_review"] / s["n"], 1),
            "pii_detections": s["pii_detections"],
            "input_rail_fp": s["input_fp"],
            "median_latency_ms": round(median_ms),
            "iqr_latency_ms": [round(q1), round(q3)],
            "alerts_lost_vs_full": lost,
            "alerts_gained_vs_full": gained,
        })

    with open(OUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump({"source": RESULTS_PATH, "table": table}, f, indent=2)
    print(f"wrote {OUT_JSON_PATH}\n")

    _print_latex(table)
    return table


def _print_latex(table):
    print(r"\begin{table}[h]")
    print(r"\caption{Component ablation summary (T6): 6 configurations "
          r"$\times$ 436 alerts, 2{,}616 total runs}\label{tab:ablation}")
    print(r"\begin{tabular}{@{}lcccccc@{}}")
    print(r"\toprule")
    print(r"Config & Ungrounded & Review & PII det. & Input FP & Latency ms (IQR) & Lost/gained vs.\ Full \\")
    print(r"\midrule")
    for row in table:
        if row["config_id"] == "C0":
            lg = "---"
        else:
            lg = f"{row['alerts_lost_vs_full']} / {row['alerts_gained_vs_full']}"
        print(f"{row['name']} & {row['ungrounded_detections']} & "
              f"{row['requires_review_flags']} ({row['requires_review_pct']}\\%) & "
              f"{row['pii_detections']} & {row['input_rail_fp']} & "
              f"{row['median_latency_ms']} [{row['iqr_latency_ms'][0]}, {row['iqr_latency_ms'][1]}] & "
              f"{lg} \\\\")
    print(r"\botrule")
    print(r"\end{tabular}")
    print(r"\end{table}")


if __name__ == "__main__":
    compute()
