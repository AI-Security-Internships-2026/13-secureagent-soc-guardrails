"""
experiments/evaluation/relevance_classifier_validation/compute_cohen_kappa.py

Issue #43 (R4), Task A.3 -- inter-rater agreement for the CVE relevance
cross-check, under the issue's own degraded-scope fallback ("single
annotator + 20% blind cross-check", no second independent annotator
recruited). Compares annotator 1's original label (frozen in
pairs_to_label_with_suggestions.csv, via cve_crosscheck_key_HIDDEN.csv)
against the same person's blind relabel of a 20% sample
(cve_crosscheck_BLIND.xlsx's `your_label` column) on the identical 16
pairs.

Reports:
  - n and % observed raw agreement
  - Cohen's kappa (sklearn.metrics.cohen_kappa_score)
  - 95% CI via 1000 bootstrap resamples (resample pair_ids with
    replacement, recompute kappa each resample, take the 2.5th/97.5th
    percentiles) -- appropriate here specifically because n=16 is small
    (n=0.2xN per the issue's own fallback text), where a single formula
    based on asymptotic normality would be a poor approximation.
  - disagreements_cve.csv: pair_id, annotator1_label, your_label for
    every pair where the two labels differ, with a blank `reason` column
    for the qualitative one-sentence disagreement note the issue's own
    Task A.2 asks for (filled in by hand, not inferred here).

Refuses to run (with a clear message, not a silent wrong number) until
every row in the blind sheet's `your_label` column is filled in --
computing kappa on a partially-labeled sample would silently understate
n rather than fail loudly.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.compute_cohen_kappa
"""

import csv
import json
import os
import random

import openpyxl
from sklearn.metrics import cohen_kappa_score

HERE = os.path.dirname(__file__)
KEY_CSV_PATH = os.path.join(HERE, "cve_crosscheck_key_HIDDEN.csv")
BLIND_XLSX_PATH = os.path.join(HERE, "cve_crosscheck_BLIND.xlsx")
DISAGREEMENTS_PATH = os.path.join(HERE, "disagreements_cve.csv")
RESULTS_JSON_PATH = os.path.join(HERE, "cve_crosscheck_kappa_results.json")

N_BOOTSTRAP = 1000
BOOTSTRAP_SEED = 20260926


def _load_key():
    with open(KEY_CSV_PATH, encoding="utf-8") as f:
        return {r["pair_id"]: r["annotator1_label"] for r in csv.DictReader(f)}


def _load_blind_labels():
    wb = openpyxl.load_workbook(BLIND_XLSX_PATH, data_only=True)
    ws = wb["CVE Cross-check (20%)"]
    labels = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        pair_id, your_label = row[0], row[4]
        if pair_id is None:
            continue
        labels[pair_id] = (your_label or "").strip()
    return labels


def compute():
    annotator1 = _load_key()
    crosscheck = _load_blind_labels()

    missing = [pid for pid in annotator1 if not crosscheck.get(pid)]
    if missing:
        raise SystemExit(
            f"{len(missing)}/{len(annotator1)} rows in {BLIND_XLSX_PATH} still have no "
            f"your_label value: {missing}\nFill in every row before running this script -- "
            f"a partial count would silently understate n rather than fail loudly."
        )

    pair_ids = sorted(annotator1)
    y1 = [annotator1[pid] for pid in pair_ids]
    y2 = [crosscheck[pid] for pid in pair_ids]

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
        # A resample can be single-class (no disagreement possible / no
        # variance) -- cohen_kappa_score returns 0.0 or nan in the
        # degenerate all-same-label case rather than raising, which is
        # the right behavior for a bootstrap distribution (skip only
        # genuine nan, don't silently drop legitimate 0.0 values).
        k = cohen_kappa_score(by1, by2)
        if k == k:  # excludes NaN without importing math for one check
            boot_kappas.append(k)
    boot_kappas.sort()
    lo = boot_kappas[int(0.025 * len(boot_kappas))]
    hi = boot_kappas[int(0.975 * len(boot_kappas)) - 1]

    disagreements = [
        {"pair_id": pid, "annotator1_label": annotator1[pid], "your_label": crosscheck[pid], "reason": ""}
        for pid in pair_ids if annotator1[pid] != crosscheck[pid]
    ]
    with open(DISAGREEMENTS_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["pair_id", "annotator1_label", "your_label", "reason"])
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
    print(f"Disagreements: {len(disagreements)} -- written to {DISAGREEMENTS_PATH} "
          f"(fill in the 'reason' column by hand for each)")
    print(f"Full results: {RESULTS_JSON_PATH}")


if __name__ == "__main__":
    compute()
