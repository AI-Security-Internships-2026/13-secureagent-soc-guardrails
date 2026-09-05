"""
experiments/evaluation/ablation_smoke_test.py

Phase 2 of the component ablation study (docs/ROADMAP_PLAN.md sec.12).
Runs a handful of real alerts through every toggle combination of
analyse_alert() and checks, before any Groq quota gets spent on the real
Phase 3 run, that:

  (a) the function still returns a valid, schema-complete report dict
      in every configuration;
  (b) each toggle disables ONLY its own stage -- a disabled stage's
      output fields always hold their fixed "nothing found" value, and
      turning one stage off never changes another (still-enabled)
      stage's output shape;
  (c) output_guardrail_flagged / requires_review still aggregate
      correctly (boolean OR of whichever stages actually ran) when one
      or more stages are disabled.

Alerts used (5, one more than Phase 2's minimum-scoped 4 -- see note
below):
  - SAMPLE_ALERTS[0]  (ALERT-001, plain SSH brute-force)  -- normal alert
  - SAMPLE_ALERTS[3]  (ALERT-004, real prompt-injection text already in
    the schema module)                                    -- injection alert
  - CVE_BAIT_ALERTS[0]  (BAIT-001)                          -- CVE-bait alert
  - ATTACK_BAIT_ALERTS[0]  (ATTACK-BAIT-001)                -- ATT&CK-bait alert
  - PII_ALERTS[0]  (PII-BAIT-001)                           -- PII-bait alert

The roadmap's Phase 2 description only names 4 alerts (normal, CVE-bait,
ATT&CK-bait, PII-bait). The injection alert is an addition: without it,
toggling input_guardrail_enabled on/off is untestable in practice, since
none of the other 4 alerts would ever trip the input guardrail either
way -- there'd be no way to confirm turning it off actually changes
behavior rather than just not crashing.

Live-call budget: 6 configs x 5 alerts = 30 (alert, config) pairs, but
4 of those pairs are the injection alert with input_guardrail_enabled=True,
which short-circuits before ever calling the LLM (no Groq call spent) --
so this uses 26 live Groq calls total, not 30.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.agent.soc_agent import analyse_alert
from src.agent.alert_schema import SAMPLE_ALERTS
from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS
from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS
from experiments.evaluation.pii_bait_alerts import PII_ALERTS

EXPECTED_SCHEMA_KEYS = {
    "alert_id", "severity_assessment", "threat_summary", "threat_type",
    "recommended_action", "confidence_score", "reasoning", "processed_at",
    "model", "agent_version", "guardrail_blocked", "hallucinated_cves",
    "cve_verifications", "hallucinated_attack_techniques",
    "attack_technique_verifications", "pii_detections",
    "output_guardrail_flagged", "requires_review", "evidence_pack",
}

CONFIGS = {
    "all-on":     dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "input-off":  dict(input_guardrail_enabled=False, cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "cve-off":    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=False, attack_guardrail_enabled=True,  pii_guardrail_enabled=True),
    "attack-off": dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=False, pii_guardrail_enabled=True),
    "pii-off":    dict(input_guardrail_enabled=True,  cve_guardrail_enabled=True,  attack_guardrail_enabled=True,  pii_guardrail_enabled=False),
    "all-off":    dict(input_guardrail_enabled=False, cve_guardrail_enabled=False, attack_guardrail_enabled=False, pii_guardrail_enabled=False),
}

TEST_ALERTS = {
    "normal": SAMPLE_ALERTS[0],
    "injection": SAMPLE_ALERTS[3],
    "cve-bait": CVE_BAIT_ALERTS[0],
    "attack-bait": ATTACK_BAIT_ALERTS[0],
    "pii-bait": PII_ALERTS[0]["alert"],
}


def check_schema(report: dict) -> list:
    """(a) every expected key present, nothing missing."""
    missing = EXPECTED_SCHEMA_KEYS - set(report.keys())
    return [f"missing schema key(s): {sorted(missing)}"] if missing else []


def check_toggle_gating(report: dict, cfg: dict) -> list:
    """(b) a disabled stage's own fields always hold their fixed empty value."""
    problems = []
    if not cfg["cve_guardrail_enabled"]:
        if report.get("hallucinated_cves") != [] or report.get("cve_verifications") != []:
            problems.append("cve_guardrail_enabled=False but CVE fields are non-empty")
    if not cfg["attack_guardrail_enabled"]:
        if report.get("hallucinated_attack_techniques") != [] or report.get("attack_technique_verifications") != []:
            problems.append("attack_guardrail_enabled=False but ATT&CK fields are non-empty")
    if not cfg["pii_guardrail_enabled"]:
        if report.get("pii_detections") != []:
            problems.append("pii_guardrail_enabled=False but pii_detections is non-empty")
    return problems


def check_aggregation(report: dict, cfg: dict) -> list:
    """(c) output_guardrail_flagged/requires_review = OR of whichever stages ran."""
    problems = []
    if report.get("guardrail_blocked"):
        # Blocked-at-input path has its own fixed False/False by design --
        # nothing to re-derive here, just confirm it took the fixed shape.
        if report.get("output_guardrail_flagged") is not False or report.get("requires_review") is not False:
            problems.append("guardrail_blocked=True but flagged/requires_review weren't both False")
        return problems

    cve_hit = cfg["cve_guardrail_enabled"] and len(report.get("hallucinated_cves", [])) > 0
    attack_hit = cfg["attack_guardrail_enabled"] and len(report.get("hallucinated_attack_techniques", [])) > 0
    pii_hit = cfg["pii_guardrail_enabled"] and len(report.get("pii_detections", [])) > 0

    expected_flagged = cve_hit or attack_hit or pii_hit
    if report.get("output_guardrail_flagged") != expected_flagged:
        problems.append(
            f"output_guardrail_flagged={report.get('output_guardrail_flagged')}, "
            f"expected {expected_flagged} (cve_hit={cve_hit}, attack_hit={attack_hit}, pii_hit={pii_hit})"
        )
    if report.get("requires_review") != expected_flagged:
        problems.append(
            f"requires_review={report.get('requires_review')}, expected {expected_flagged}"
        )
    return problems


def check_injection_behavior(alert_name: str, report: dict, cfg: dict) -> list:
    """Extra check specific to the injection alert: input_guardrail_enabled
    should be the only thing determining whether it gets blocked."""
    if alert_name != "injection":
        return []
    problems = []
    if cfg["input_guardrail_enabled"]:
        if not report.get("guardrail_blocked"):
            problems.append("input_guardrail_enabled=True on the injection alert but it was NOT blocked")
    else:
        if report.get("guardrail_blocked"):
            problems.append("input_guardrail_enabled=False but the injection alert was still blocked")
    return problems


def main():
    results = {}
    all_problems = []
    total_llm_calls_expected = 0

    for alert_name, alert in TEST_ALERTS.items():
        results[alert_name] = {}
        for cfg_name, cfg in CONFIGS.items():
            will_call_llm = not (alert_name == "injection" and cfg["input_guardrail_enabled"])
            if will_call_llm:
                total_llm_calls_expected += 1

            print(f"[{alert_name} / {cfg_name}] running...", flush=True)
            report = analyse_alert(alert, **cfg)

            problems = []
            problems += check_schema(report)
            problems += check_toggle_gating(report, cfg)
            problems += check_aggregation(report, cfg)
            problems += check_injection_behavior(alert_name, report, cfg)

            status = "PASS" if not problems else "FAIL"
            print(f"  -> {status}" + (f": {problems}" if problems else ""))

            results[alert_name][cfg_name] = {
                "status": status,
                "problems": problems,
                "guardrail_blocked": report.get("guardrail_blocked"),
                "output_guardrail_flagged": report.get("output_guardrail_flagged"),
                "requires_review": report.get("requires_review"),
                "hallucinated_cves": report.get("hallucinated_cves"),
                "hallucinated_attack_techniques": report.get("hallucinated_attack_techniques"),
                "pii_detections_count": len(report.get("pii_detections", [])),
            }
            if problems:
                all_problems.extend([f"{alert_name}/{cfg_name}: {p}" for p in problems])

    total_checks = sum(len(v) for v in results.values())
    total_pass = sum(1 for a in results.values() for c in a.values() if c["status"] == "PASS")

    summary = {
        "total_checks": total_checks,
        "total_pass": total_pass,
        "total_fail": total_checks - total_pass,
        "expected_llm_calls": total_llm_calls_expected,
        "all_problems": all_problems,
        "results": results,
    }

    out_path = Path(__file__).resolve().parents[1] / "results" / "ablation_smoke_test_results.json"
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    print(f"\n{total_pass}/{total_checks} checks passed. Expected LLM calls: {total_llm_calls_expected}.")
    print(f"Results written to {out_path}")
    if all_problems:
        print("\nPROBLEMS FOUND:")
        for p in all_problems:
            print(f"  - {p}")
        sys.exit(1)


if __name__ == "__main__":
    main()
