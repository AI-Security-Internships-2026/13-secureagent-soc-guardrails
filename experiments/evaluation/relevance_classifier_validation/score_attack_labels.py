"""
experiments/evaluation/relevance_classifier_validation/score_attack_labels.py

Issue #43 (R4) Part B, Task B.2 -- ATT&CK counterpart of score_labels.py.
Scores the deterministic relevance classifier (src/guardrails/grounding_utils.py's
_topical_overlap(), at attack_grounding.py's verify_attack_technique()
overlap_threshold=0.15 default) against the human labels filled in on
`attack_annotation_BLIND.xlsx` -- single annotator, no cross-check, per
issue #43's own degraded-scope fallback (documented in
docs/all_results.md #89).

Scores against the REAL bare technique description
(attack_grounding.py's own `record["description"]`, re-derived from the
local MITRE snapshot rather than trusted from the CSV's merged
"Name: description" field) -- matching exactly what
verify_attack_technique() itself compares against, not the
name-prefixed text the CSV happens to store or the further-redacted
text the human annotator actually saw. The classifier's own score must
be computed the same way the real pipeline computes it; the human's
blind judgment and the classifier's input text are two independent
things that only need to agree on which (alert, description) pair
they're both judging, not on which exact string was displayed.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.score_attack_labels <path_to_labeled_xlsx>
"""

import csv
import json
import os
import sys

import openpyxl
from scipy.stats import norm

from src.guardrails.attack_grounding import _load_attack_techniques
from src.guardrails.grounding_utils import _topical_overlap

HERE = os.path.dirname(__file__)
PAIRS_CSV_PATH = os.path.join(HERE, "attack_pairs_to_label.csv")
DEFAULT_LABELED_XLSX = os.path.join(HERE, "attack_annotation_labeled.xlsx")
RESULTS_JSON_PATH = os.path.join(HERE, "attack_relevance_classifier_validation_results.json")

OVERLAP_THRESHOLD = 0.15  # must match attack_grounding.py's verify_attack_technique() default
VALID_LABELS = {"relevant", "not_relevant"}


def wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(float(max(0.0, center - margin)), 4), round(float(min(1.0, center + margin)), 4))


def _load_human_labels(xlsx_path):
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb["ATT&CK Pairs"]
    labels = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        pair_id, label = row[0], row[4]
        if pair_id is None:
            continue
        labels[pair_id] = (label or "").strip()
    return labels


def score(labeled_xlsx_path=DEFAULT_LABELED_XLSX):
    with open(PAIRS_CSV_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    human_labels = _load_human_labels(labeled_xlsx_path)
    techniques = _load_attack_techniques()

    labeled = [r for r in rows if human_labels.get(r["pair_id"], "") in VALID_LABELS]
    unlabeled = len(rows) - len(labeled)
    if unlabeled:
        print(f"{unlabeled}/{len(rows)} pairs not yet labeled -- scoring only the {len(labeled)} that are.")
    if not labeled:
        print(f"Nothing labeled yet in {labeled_xlsx_path}.")
        return

    per_pair = []
    tp = fp = tn = fn = 0
    for row in labeled:
        tid = row["candidate_technique_id"]
        bare_description = techniques.get(tid, {}).get("description") or row["candidate_technique_description"]
        overlap = round(_topical_overlap(row["alert_text"], bare_description), 4)
        predicted_relevant = overlap >= OVERLAP_THRESHOLD
        human_label = human_labels[row["pair_id"]]
        actual_relevant = human_label == "relevant"

        if predicted_relevant and actual_relevant:
            tp += 1
        elif predicted_relevant and not actual_relevant:
            fp += 1
        elif not predicted_relevant and not actual_relevant:
            tn += 1
        else:
            fn += 1

        per_pair.append({
            "pair_id": row["pair_id"],
            "alert_id": row["alert_id"],
            "candidate_technique_id": tid,
            "topical_overlap": overlap,
            "classifier_predicted": "relevant" if predicted_relevant else "not_relevant",
            "human_label": human_label,
            "agree": predicted_relevant == actual_relevant,
        })

    n = len(labeled)
    accuracy = (tp + tn) / n
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    output = {
        "task": "ATT&CK relevance classifier (_topical_overlap, threshold=0.15) vs. human judgment "
                "(single annotator, no cross-check -- issue #43 degraded-scope fallback)",
        "n_labeled": n,
        "n_unlabeled": unlabeled,
        "n_relevant_by_human": sum(1 for r in per_pair if r["human_label"] == "relevant"),
        "n_not_relevant_by_human": sum(1 for r in per_pair if r["human_label"] == "not_relevant"),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round(accuracy, 4),
        "accuracy_wilson_ci_95": wilson_ci(tp + tn, n),
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_ci_95": wilson_ci(tp, tp + fp) if (tp + fp) else None,
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_ci_95": wilson_ci(tp, tp + fn) if (tp + fn) else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "results": per_pair,
    }

    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n=== ATT&CK relevance classifier validation (n={n}) ===")
    print(f"Accuracy:  {accuracy:.1%} (95% CI {output['accuracy_wilson_ci_95']})")
    if precision is not None:
        print(f"Precision: {precision:.1%} (95% CI {output['precision_wilson_ci_95']})")
    if recall is not None:
        print(f"Recall:    {recall:.1%} (95% CI {output['recall_wilson_ci_95']})")
    if f1 is not None:
        print(f"F1:        {f1:.1%}")
    print(f"Confusion matrix: {output['confusion_matrix']}")
    print(f"\nresults saved to {RESULTS_JSON_PATH}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LABELED_XLSX
    score(path)
