"""
experiments/evaluation/relevance_classifier_validation/score_labels.py

Once pairs_to_label.csv's human_label column has been filled in (each row:
"relevant" or "not_relevant"), scores the deterministic relevance
classifier (src/guardrails/grounding_utils.py's _topical_overlap(), at
output_guardrail.py's overlap_threshold=0.15) against those human
judgments -- precision/recall/F1/accuracy with Wilson 95% CIs, same
convention as every other guardrail comparison in this project.

Does NOT touch construction_key.json -- the whole point of this benchmark
is testing the classifier against an INDEPENDENT human judgment, not
against how the pairs happened to be built. construction_key.json is only
useful afterward, for manually spot-checking any case where the human
label disagreed with how the pair was constructed (e.g. a "negative" pair
that a human actually judged relevant purely by coincidence -- CVE pools
aren't curated to avoid all topical overlap, so this can legitimately
happen and isn't itself an error in either the label or the classifier).

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.score_labels
"""

import csv
import json
import os

from scipy.stats import norm

from src.guardrails.grounding_utils import _topical_overlap

OUTPUT_DIR = os.path.dirname(__file__)
PAIRS_CSV_PATH = os.path.join(OUTPUT_DIR, "pairs_to_label_with_suggestions.csv")
RESULTS_JSON_PATH = os.path.join(OUTPUT_DIR, "relevance_classifier_validation_results.json")

OVERLAP_THRESHOLD = 0.15  # must match output_guardrail.py's verify_cve() default
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


def score():
    with open(PAIRS_CSV_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    labeled = [r for r in rows if r["human_label"].strip() in VALID_LABELS]
    unlabeled = len(rows) - len(labeled)
    if unlabeled:
        print(f"{unlabeled}/{len(rows)} pairs not yet labeled (human_label must be "
              f"'relevant' or 'not_relevant') -- scoring only the {len(labeled)} that are.")
    if not labeled:
        print("Nothing labeled yet -- fill in pairs_to_label_with_suggestions.csv's human_label column first.")
        return

    per_pair = []
    tp = fp = tn = fn = 0
    for row in labeled:
        overlap = round(_topical_overlap(row["alert_text"], row["candidate_cve_description"]), 4)
        predicted_relevant = overlap >= OVERLAP_THRESHOLD
        actual_relevant = row["human_label"].strip() == "relevant"

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
            "candidate_cve_id": row["candidate_cve_id"],
            "topical_overlap": overlap,
            "classifier_predicted": "relevant" if predicted_relevant else "not_relevant",
            "human_label": row["human_label"].strip(),
            "agree": predicted_relevant == actual_relevant,
        })

    n = len(labeled)
    accuracy = (tp + tn) / n
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    output = {
        "task": "Relevance classifier (_topical_overlap, threshold=0.15) vs. human judgment",
        "n_labeled": n,
        "n_unlabeled": unlabeled,
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

    print(f"\n=== Relevance classifier validation (n={n}) ===")
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
    score()
