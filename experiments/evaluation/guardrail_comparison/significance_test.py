"""
experiments/evaluation/guardrail_comparison/significance_test.py

McNemar's test on the per-sample predictions already produced by
run_comparison.py (experiments/results/guardrail_comparison.json).

Why McNemar and not a t-test / independent-samples test: all implementations
were run on the *same* 119 examples, so their predictions are paired per
sample, not independent draws. McNemar's test is built for exactly this --
paired binary outcomes (correct/incorrect) on shared test items, using the
discordant-pair counts (A right/B wrong vs. A wrong/B right) rather than raw
accuracy. See docs/ROADMAP_PLAN.md sec.8.

No new dependency: implemented directly on top of scipy (already an
effective project dependency via scikit-learn) instead of adding
statsmodels just for this one test.

CLI:
    python -m experiments.evaluation.guardrail_comparison.significance_test
"""

import json
import os

from scipy.stats import binomtest, chi2

RESULTS_PATH = "experiments/results/guardrail_comparison.json"
OUTPUT_PATH = "experiments/results/guardrail_comparison_significance.json"

# The three comparisons flagged in docs/ROADMAP_PLAN.md sec.8 as the ones
# that matter most for this benchmark, plus the hybrid_llmguard trial added
# 2026-08-11 (deterministic layer falling back to LLM Guard instead of
# Pytector -- see adapters.py).
COMPARISON_PAIRS = [
    ("hybrid", "pytector"),
    ("hybrid", "llm_guard"),
    ("baseline", "hybrid"),
    ("hybrid_llmguard", "hybrid"),
    ("hybrid_llmguard", "llm_guard"),
    ("hybrid_llmguard", "pytector"),
]

# Below this many discordant pairs, the chi-square approximation is
# unreliable -- use the exact binomial test instead. 25 is the conventional
# threshold (matches statsmodels' mcnemar(..., exact=True) default cutoff).
EXACT_THRESHOLD = 25


def load_predictions(results: dict, name: str) -> dict:
    impl = results["implementations"][name]
    if "predictions" not in impl:
        raise ValueError(f"Implementation '{name}' has no predictions (status: {impl.get('status')})")
    return {p["id"]: p for p in impl["predictions"]}


def mcnemar(name_a: str, preds_a: dict, name_b: str, preds_b: dict) -> dict:
    common_ids = sorted(set(preds_a) & set(preds_b))
    if not common_ids:
        raise ValueError(f"No overlapping sample ids between '{name_a}' and '{name_b}'")

    both_correct = 0
    a_only_correct = 0  # b: A correct, B incorrect
    b_only_correct = 0  # c: A incorrect, B correct
    both_incorrect = 0

    for sample_id in common_ids:
        pa, pb = preds_a[sample_id], preds_b[sample_id]
        if pa["actual"] != pb["actual"]:
            raise ValueError(f"Ground-truth label mismatch on {sample_id} between '{name_a}' and '{name_b}'")
        a_correct = pa["predicted"] == pa["actual"]
        b_correct = pb["predicted"] == pb["actual"]
        if a_correct and b_correct:
            both_correct += 1
        elif a_correct and not b_correct:
            a_only_correct += 1
        elif not a_correct and b_correct:
            b_only_correct += 1
        else:
            both_incorrect += 1

    discordant = a_only_correct + b_only_correct

    if discordant == 0:
        # Identical error patterns -- nothing to test, and division by zero
        # in the chi-square statistic otherwise.
        method = "degenerate"
        statistic = 0.0
        p_value = 1.0
    elif discordant < EXACT_THRESHOLD:
        method = "exact_binomial"
        result = binomtest(a_only_correct, discordant, 0.5, alternative="two-sided")
        statistic = None
        p_value = result.pvalue
    else:
        method = "chi_square_continuity_corrected"
        statistic = (abs(a_only_correct - b_only_correct) - 1) ** 2 / discordant
        p_value = 1 - chi2.cdf(statistic, df=1)

    return {
        "a": name_a,
        "b": name_b,
        "n_samples": len(common_ids),
        "contingency": {
            "both_correct": both_correct,
            f"{name_a}_only_correct": a_only_correct,
            f"{name_b}_only_correct": b_only_correct,
            "both_incorrect": both_incorrect,
        },
        "discordant_pairs": discordant,
        "method": method,
        "statistic": float(statistic) if statistic is not None else None,
        "p_value": float(p_value) if p_value is not None else None,
        "significant_at_0.05": bool(p_value < 0.05) if p_value is not None else None,
    }


def main():
    with open(RESULTS_PATH) as f:
        results = json.load(f)

    all_preds = {}
    for name_a, name_b in COMPARISON_PAIRS:
        for name in (name_a, name_b):
            if name not in all_preds:
                all_preds[name] = load_predictions(results, name)

    comparisons = []
    print(f"McNemar's test on {results['dataset_size']} paired samples "
          f"({RESULTS_PATH})\n")

    for name_a, name_b in COMPARISON_PAIRS:
        outcome = mcnemar(name_a, all_preds[name_a], name_b, all_preds[name_b])
        comparisons.append(outcome)

        c = outcome["contingency"]
        sig = "SIGNIFICANT" if outcome["significant_at_0.05"] else "not significant"
        print(f"{name_a} vs {name_b}:")
        print(f"  both correct={c['both_correct']}  "
              f"{name_a}-only={c[f'{name_a}_only_correct']}  "
              f"{name_b}-only={c[f'{name_b}_only_correct']}  "
              f"both wrong={c['both_incorrect']}")
        print(f"  method={outcome['method']}  p={outcome['p_value']:.4f}  ({sig} at alpha=0.05)\n")

    output = {
        "task": "McNemar significance test on paired guardrail predictions",
        "source": RESULTS_PATH,
        "dataset_size": results["dataset_size"],
        "alpha": 0.05,
        "comparisons": comparisons,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Results written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
