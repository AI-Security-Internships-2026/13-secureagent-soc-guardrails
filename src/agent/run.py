import argparse
import json
import os

from dotenv import load_dotenv

from src.agent.soc_agent import analyse_alert
from src.agent.alert_schema import SAMPLE_ALERTS
from src.data.load_cicids2017 import load_cicids2017_alerts

load_dotenv()


def run(alerts, results_path: str):
    results = []

    for alert in alerts:
        print(f"\nProcessing {alert.alert_id} ({alert.severity})...")
        report = analyse_alert(alert)
        results.append(report)
        print(json.dumps(report, indent=2))

    blocked_count = sum(1 for r in results if r.get("guardrail_blocked"))
    passed_count = len(results) - blocked_count

    print(f"\nGuardrail summary")
    print(f"Total alerts processed: {len(results)}")
    print(f"Blocked by guardrail: {blocked_count}")
    print(f"Passed through to LLM: {passed_count}")

    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nresults saved to {results_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        choices=["synthetic", "cicids2017"],
        default="synthetic",
        help="synthetic = SAMPLE_ALERTS (default, unchanged from week 4); "
             "cicids2017 = real alerts built from a CICIDS2017 CSV",
    )
    parser.add_argument(
        "--csv",
        help="Path to a CICIDS2017 daily CSV file (required when --source cicids2017)",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=20,
        help="Number of alerts to sample when --source cicids2017 (default: 20)",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Sample a random mix of attack types instead of the first N rows in file order",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible shuffling (only used with --shuffle)",
    )
    args = parser.parse_args()

    if args.source == "synthetic":
        run(SAMPLE_ALERTS, "experiments/results/guardrail_results.json")
    else:
        if not args.csv:
            parser.error("--csv is required when --source cicids2017")
        alerts = load_cicids2017_alerts(args.csv, n=args.n, shuffle=args.shuffle, seed=args.seed)
        if not alerts:
            print("No matching attack rows found in the given CSV — check ATTACK_MAP in load_cicids2017.py.")
        else:
            run(alerts, "experiments/results/cicids2017_results.json")