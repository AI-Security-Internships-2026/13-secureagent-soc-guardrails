"""
experiments/evaluation/relevance_classifier_validation/compute_inter_rater_agreement.py

Issue #43 (R4) Part A, Task A.3 -- the actual two-independent-annotator
version, per the supervisor's explicit follow-up comment on the issue
(2026-09-22): "Please proceed with the actual independent second
annotation... Afterward, compute and report inter-rater agreement
(Cohen's kappa and percentage agreement) and resolve disagreements
transparently rather than modifying labels simply to improve
agreement." Supersedes the degraded-scope 20%-cross-check fallback
(compute_cohen_kappa.py, docs/all_results.md #89/#91) for this
question -- that script remains useful as a record of the
self-consistency check already done, but this is the real independent
double-annotation the issue originally asked for.

Compares annotator 1's original labels (frozen in
pairs_to_label_with_suggestions.csv, via annotator1_and_key_HIDDEN.csv)
against annotator 2's independent blind labels
(annotator2_cve_pairs_BLIND.xlsx's `your_label` column, filled in by a
genuinely different person, not the same rater self-checking) on all 80
pairs.

Reports:
  - n and % observed raw agreement
  - Cohen's kappa (sklearn.metrics.cohen_kappa_score)
  - 95% CI via 1000 bootstrap resamples
  - disagreements_cve.csv: pair_id, annotator1_label, annotator2_label,
    resolved_label (blank -- filled in by hand via third-rater
    tie-break, per the issue's own Task A.2), reason (blank -- one
    qualitative sentence per disagreement, also per Task A.2). Labels
    are never silently adjusted to improve agreement -- every
    disagreement is surfaced, not resolved algorithmically.

Refuses to run until every row in the blind sheet is filled in, same
guard as compute_cohen_kappa.py.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.compute_inter_rater_agreement
"""

import csv
import json
import os
import random

import openpyxl
from sklearn.metrics import cohen_kappa_score

HERE = os.path.dirname(__file__)
KEY_CSV_PATH = os.path.join(HERE, "annotator1_and_key_HIDDEN.csv")
ANNOTATOR2_XLSX_PATH = os.path.join(HERE, "annotator2_cve_pairs_labeled.xlsx")
DISAGREEMENTS_PATH = os.path.join(HERE, "disagreements_cve_full.csv")
RESULTS_JSON_PATH = os.path.join(HERE, "inter_rater_agreement_results.json")

N_BOOTSTRAP = 1000
BOOTSTRAP_SEED = 20260927


def _load_annotator1():
    with open(KEY_CSV_PATH, encoding="utf-8") as f:
        return {r["pair_id"]: r["annotator1_label"] for r in csv.DictReader(f)}


def _load_annotator2(xlsx_path):
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb["CVE Pairs"]
    labels = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        pair_id, label = row[0], row[4]
        if pair_id is None:
            continue
        labels[pair_id] = (label or "").strip()
    return labels


def compute(annotator2_xlsx_path=ANNOTATOR2_XLSX_PATH):
    annotator1 = _load_annotator1()
    annotator2 = _load_annotator2(annotator2_xlsx_path)

    missing = [pid for pid in annotator1 if not annotator2.get(pid)]
    if missing:
        raise SystemExit(
            f"{len(missing)}/{len(annotator1)} rows in {annotator2_xlsx_path} still have no "
            f"your_label value: {missing}\nFill in every row before running this script."
        )

    pair_ids = sorted(annotator1)
    y1 = [annotator1[pid] for pid in pair_ids]
    y2 = [annotator2[pid] for pid in pair_ids]

    n = len(pair_ids)
    agree = sum(1 for a, b in zip(y1, y2) if a == b)
    observed_agreement = agree / n
    kappa = cohen_kappa_score(y1, y2)

    rng = random.Random(BOOTSTRAP_SEED)
    boot_kappas = []
    for _ in range(N_BOOTSTRAP):
        idx = [rng.randrange(n) for _ in range(n)]
        by1 = [y1[i] for i in idx]
        by2 = [y2[i] for i in idx]
        k = cohen_kappa_score(by1, by2)
        if k == k:  # excludes NaN
            boot_kappas.append(k)
    boot_kappas.sort()
    lo = boot_kappas[int(0.025 * len(boot_kappas))]
    hi = boot_kappas[int(0.975 * len(boot_kappas)) - 1]

    disagreements = [
        {"pair_id": pid, "annotator1_label": annotator1[pid], "annotator2_label": annotator2[pid],
         "resolved_label": "", "reason": ""}
        for pid in pair_ids if annotator1[pid] != annotator2[pid]
    ]
    with open(DISAGREEMENTS_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["pair_id", "annotator1_label", "annotator2_label",
                                           "resolved_label", "reason"])
        w.writeheader()
        w.writerows(disagreements)

    results = {
        "n": n,
        "observed_agreement": round(observed_agreement, 4),
        "cohen_kappa": round(kappa, 4),
        "cohen_kappa_bootstrap_95ci": [round(lo, 4), round(hi, 4)],
        "n_bootstrap": N_BOOTSTRAP,
        "n_disagreements": len(disagreements),
    }
    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"n = {n}")
    print(f"Observed agreement: {observed_agreement:.1%}")
    print(f"Cohen's kappa: {kappa:.3f} (95% CI [{lo:.3f}, {hi:.3f}], {N_BOOTSTRAP} bootstrap resamples)")
    print(f"Disagreements: {len(disagreements)} -- written to {DISAGREEMENTS_PATH}")
    print("Fill in 'resolved_label' (third-rater tie-break) and 'reason' for each before "
          "computing pipeline accuracy against resolved labels.")
    print(f"Full results: {RESULTS_JSON_PATH}")


if __name__ == "__main__":
    compute()
