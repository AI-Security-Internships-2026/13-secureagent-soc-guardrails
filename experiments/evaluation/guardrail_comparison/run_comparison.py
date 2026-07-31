
import json
import os
import platform
import statistics
import sys
from importlib.metadata import version, PackageNotFoundError

from experiments.evaluation.guardrail_comparison.adapters import IMPLEMENTATIONS

DATASET_PATH = os.path.join(os.path.dirname(__file__), "eval_dataset.json")
OUTPUT_PATH = "experiments/results/guardrail_comparison.json"


def load_dataset():
    with open(DATASET_PATH) as f:
        return json.load(f)


def pkg_version(name: str):
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def capture_environment():
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "package_versions": {
            "llm-guard": pkg_version("llm-guard"),
            "pytector": pkg_version("pytector"),
        },
        "note": (
            "Baseline (this repo's own check_injection) has no external "
            "package version — it's the code in src/guardrails/input_guardrail.py "
            "at the commit this benchmark was run against."
        ),
    }


def evaluate_implementation(name: str, scan_fn, dataset: list) -> dict:
    predictions = []
    latencies = []
    execution_failures = []

    for sample in dataset:
        result = scan_fn(sample["text"])
        latencies.append(result.latency_ms)

        if result.error is not None:
            execution_failures.append({
                "id": sample["id"],
                "error": result.error,
            })
            predicted_positive = False
        else:
            predicted_positive = result.is_flagged

        actual_positive = sample["label"] == "injection"

        predictions.append({
            "id": sample["id"],
            "actual": sample["label"],
            "predicted": "injection" if predicted_positive else "benign",
            "score": result.score,
            "latency_ms": result.latency_ms,
            "error": result.error,
        })

    tp = sum(1 for p in predictions if p["actual"] == "injection" and p["predicted"] == "injection")
    fp = sum(1 for p in predictions if p["actual"] == "benign" and p["predicted"] == "injection")
    tn = sum(1 for p in predictions if p["actual"] == "benign" and p["predicted"] == "benign")
    fn = sum(1 for p in predictions if p["actual"] == "injection" and p["predicted"] == "benign")

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    fnr = fn / (fn + tp) if (fn + tp) > 0 else None

    sorted_latencies = sorted(latencies)
    median_latency = statistics.median(sorted_latencies) if sorted_latencies else None
    p95_latency = (
        sorted_latencies[int(len(sorted_latencies) * 0.95)]
        if len(sorted_latencies) > 1
        else (sorted_latencies[0] if sorted_latencies else None)
    )
    total_time_sec = sum(latencies) / 1000
    throughput = len(dataset) / total_time_sec if total_time_sec > 0 else None

    return {
        "implementation": name,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "median_latency_ms": median_latency,
        "p95_latency_ms": p95_latency,
        "throughput_per_sec": throughput,
        "execution_failures": execution_failures,
        "execution_failure_count": len(execution_failures),
        "predictions": predictions,
    }


def main():
    dataset = load_dataset()
    print(f"Loaded {len(dataset)} held-out samples "
          f"({sum(1 for d in dataset if d['label']=='injection')} injection / "
          f"{sum(1 for d in dataset if d['label']=='benign')} benign)")

    results = {
        "task": "prompt-injection detection",
        "dataset_path": "experiments/evaluation/guardrail_comparison/eval_dataset.json",
        "dataset_size": len(dataset),
        "environment": capture_environment(),
        "implementations": {},
        "excluded_frameworks": {
            "NeMo Guardrails": (
                "Jailbreak/injection detection requires either an LLM self-check "
                "call (hosted API - violates the no-sensitive-data-to-hosted-APIs "
                "constraint if this were run on real alert data) or a heuristic "
                "module not directly comparable to a classifier. Already evaluated "
                "and dropped in week 2 for unreliable classification with small "
                "models (documented in proposal.md, RQ5)."
            ),
            "Meta LlamaFirewall (PromptGuard)": (
                "Underlying model is gated on HuggingFace behind Meta's license "
                "terms, requiring authenticated access - a reproducibility barrier "
                "for anyone re-running this benchmark without their own accepted "
                "license/HF token."
            ),
            "Guardrails AI": (
                "Originally selected as the second framework. Its hub validator "
                "for this task (guardrails/detect_prompt_injection, a local "
                "DeBERTa classifier) has been removed from the Guardrails Hub "
                "package index - `guardrails hub install` fails with 'Could not "
                "find a version that satisfies the requirement "
                "guardrails-grhub-detect-prompt-injection' even with an "
                "authenticated hub account. The only currently available "
                "replacement validator (sainatha/prompt_injection_detector) "
                "works by sending the prompt to a hosted LLM judge (defaults to "
                "OpenAI gpt-3.5-turbo, requires OPENAI_API_KEY), which would "
                "violate the no-sensitive-data-to-hosted-APIs constraint. "
                "Replaced with Pytector (pip-installable, local DeBERTa "
                "inference, no hosted API) to keep two working local baselines."
            ),
        },
    }

    for name, scan_fn in IMPLEMENTATIONS.items():
        print(f"\nRunning implementation: {name}")
        try:
            result = evaluate_implementation(name, scan_fn, dataset)
            results["implementations"][name] = result
            cm = result["confusion_matrix"]
            print(f"  TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}")
            print(f"  Precision={result['precision']} Recall={result['recall']} F1={result['f1']}")
            if result["median_latency_ms"] is not None:
                print(f"  Median latency={result['median_latency_ms']:.2f}ms  "
                      f"P95={result['p95_latency_ms']:.2f}ms  "
                      f"Throughput={result['throughput_per_sec']:.2f}/sec")
            if result["execution_failure_count"] > 0:
                print(f"  WARNING: {result['execution_failure_count']} execution failures - see JSON for details")
        except ImportError as e:
            print(f"  NOT COMPARABLE - could not import required package: {e}")
            results["implementations"][name] = {
                "implementation": name,
                "status": "not_comparable",
                "reason": f"Import failed: {e}",
            }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults committed to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()