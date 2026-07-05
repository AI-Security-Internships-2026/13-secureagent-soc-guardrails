from dotenv import load_dotenv
import json
import os
from src.agent.soc_agent import analyse_alert
from src.agent.alert_schema import SAMPLE_ALERTS

load_dotenv()

def run():
    results = []
    
    for alert in SAMPLE_ALERTS:
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
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/guardrail_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nresults saved to experiments/results/guardrail_results.json")

if __name__ == "__main__":
    run()