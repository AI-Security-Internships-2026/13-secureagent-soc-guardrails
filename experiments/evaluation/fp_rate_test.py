

import argparse
import json
import os

from src.agent.soc_agent import format_alert
from src.guardrails.input_guardrail import check_injection
from src.data.load_cicids2017 import load_cicids2017_alerts


def run_fp_test(csv_path: str, n: int = 10, seed: int | None = None):
    alerts = load_cicids2017_alerts(
        csv_path,
        n=n,
        skip_benign=False,
        shuffle=True,
        seed=seed,
        only_event_types={"BENIGN"},
    )

    if not alerts:
        print(
            "No BENIGN-labeled rows found in this file. "
            "Try Monday-WorkingHours.pcap_ISCX.csv, which is benign-only in CICIDS2017."
        )
        return

    results = []
    for alert in alerts:
        alert_text = format_alert(alert)
        blocked = check_injection(alert_text)
        results.append({
            "alert_id": alert.alert_id,
            "event_type": alert.event_type,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "guardrail_blocked": blocked,
        })
        status = "WRONGLY BLOCKED" if blocked else "correctly passed"
        print(f"{alert.alert_id} | {alert.event_type} | {status}")

    false_positives = sum(1 for r in results if r["guardrail_blocked"])
    total = len(results)
    fp_rate = false_positives / total if total else 0.0

    print(f"\nFalse positive test summary")
    print(f"Total clean alerts tested: {total}")
    print(f"Wrongly blocked (false positives): {false_positives}")
    print(f"False positive rate: {fp_rate:.1%}")

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/fp_rate_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "total_tested": total,
            "false_positives": false_positives,
            "false_positive_rate": fp_rate,
            "results": results,
        }, f, indent=2)

    print(f"\nresults saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to a CICIDS2017 CSV file (Monday's is benign-only)")
    parser.add_argument("--n", type=int, default=10, help="Number of clean alerts to test (default: 10)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible sampling")
    args = parser.parse_args()

    run_fp_test(args.csv, n=args.n, seed=args.seed)