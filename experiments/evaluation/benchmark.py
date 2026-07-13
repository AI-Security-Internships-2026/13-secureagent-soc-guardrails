import time
import json
import os
from dotenv import load_dotenv
from src.agent.soc_agent import analyse_alert
from src.agent.alert_schema import SAMPLE_ALERTS
from src.guardrails.input_guardrail import check_injection
from src.agent.alert_schema import SecurityAlert, SAMPLE_ALERTS

load_dotenv()

CLEAN_ALERTS = [a for a in SAMPLE_ALERTS if a.alert_id != "ALERT-004"]

def benchmark_guardrail_only(alerts: list, runs: int = 10) -> dict:
    """Measure throughput of guardrail check only (no LLM call)."""
    
    # Repeat alerts to get N runs
    test_set = (alerts * ((runs // len(alerts)) + 1))[:runs]
    
    start = time.perf_counter()
    results = []
    for alert in test_set:
        from src.agent.soc_agent import format_alert
        alert_text = format_alert(alert)
        blocked = check_injection(alert_text)
        results.append(blocked)
    end = time.perf_counter()
    
    elapsed = end - start
    return {
        "mode": "guardrail_only",
        "total_alerts": runs,
        "elapsed_seconds": round(elapsed, 4),
        "alerts_per_second": round(runs / elapsed, 2),
        "blocked_count": sum(results)
    }

def benchmark_full_pipeline(alerts: list, runs: int = 5) -> dict:
    """Measure throughput of full pipeline (guardrail + LLM call)."""
    
    test_set = (alerts * ((runs // len(alerts)) + 1))[:runs]
    
    start = time.perf_counter()
    results = []
    for alert in test_set:
        report = analyse_alert(alert)
        results.append(report)
    end = time.perf_counter()
    
    elapsed = end - start
    return {
        "mode": "full_pipeline",
        "total_alerts": runs,
        "elapsed_seconds": round(elapsed, 4),
        "alerts_per_second": round(runs / elapsed, 2),
        "blocked_count": sum(1 for r in results if r.get("guardrail_blocked"))
    }

def run():
    print("Throughput Benchmark\n")
    
    print("Running guardrail-only benchmark (100 alerts)...")
    guardrail_result = benchmark_guardrail_only(CLEAN_ALERTS, runs=100)
    print(json.dumps(guardrail_result, indent=2))
    
    print("\nRunning full pipeline benchmark (5 alerts)...")
    pipeline_result = benchmark_full_pipeline(CLEAN_ALERTS, runs=5)
    print(json.dumps(pipeline_result, indent=2))
    
    print("\nSummary")
    print(f"Guardrail only:   {guardrail_result['alerts_per_second']} alerts/sec")
    print(f"Full pipeline:    {pipeline_result['alerts_per_second']} alerts/sec")
    print(f"Guardrail overhead: {round((1/guardrail_result['alerts_per_second']) * 1000, 3)} ms per alert")
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/benchmark_results.json", "w") as f:
        json.dump({
            "guardrail_only": guardrail_result,
            "full_pipeline": pipeline_result
        }, f, indent=2)
    
    print("\nResults saved to experiments/results/benchmark_results.json")

if __name__ == "__main__":
    run()