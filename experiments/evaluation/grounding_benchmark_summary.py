"""
experiments/evaluation/grounding_benchmark_summary.py

Consolidates every already-run grounding-checker result (CVE + MITRE ATT&CK)
across all alert sources into one cross-source benchmark table. Reads only
existing result JSON files -- no new LLM calls, no new alert generation.

Usage:
    python -m experiments.evaluation.grounding_benchmark_summary
"""

import json
import os

from scipy.stats import norm

RESULTS_DIR = "experiments/results"
OUTPUT_PATH = os.path.join(RESULTS_DIR, "grounding_benchmark_summary.json")


def wilson_ci(successes: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (None, None)
    z = norm.ppf(1 - alpha / 2)
    p_hat = successes / n
    denom = 1 + z ** 2 / n
    center = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z / denom) * ((p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def _load(name: str) -> dict:
    with open(os.path.join(RESULTS_DIR, name)) as f:
        return json.load(f)


def _rate_row(label: str, n: int, cve_count, attack_count, review_count, note: str = "") -> dict:
    row = {
        "source": label,
        "n": n,
        "cve_ungrounded_count": cve_count,
        "cve_ungrounded_rate": round(cve_count / n, 4) if cve_count is not None and n else None,
        "cve_ungrounded_ci_95": wilson_ci(cve_count, n) if cve_count is not None else None,
        "attack_ungrounded_count": attack_count,
        "attack_ungrounded_rate": round(attack_count / n, 4) if attack_count is not None and n else None,
        "attack_ungrounded_ci_95": wilson_ci(attack_count, n) if attack_count is not None else None,
        "requires_review_count": review_count,
        "requires_review_rate": round(review_count / n, 4) if review_count is not None and n else None,
    }
    if note:
        row["note"] = note
    return row


def build_summary() -> dict:
    cve_bait = _load("cve_bait_results.json")
    attack_bait = _load("attack_bait_results.json")
    wazuh = _load("wazuh_integration_results.json")
    soc = _load("soc_integration_results.json")
    soc_cve_pool = _load("soc_integration_cve_pool_results.json")

    rows = [
        _rate_row(
            "CVE-bait (hand-authored + CISA KEV)",
            cve_bait["total_tested"],
            cve_bait["ungrounded_count"], None,
            cve_bait["requires_review_count"],
            note="CVE grounding only. 0/97 alerts that don't ask for a CVE citation ever "
                 "hallucinate one; both flagged hits come from the 3 alerts that explicitly "
                 "request a CVE ID.",
        ),
        _rate_row(
            "ATT&CK-bait (MITRE snapshot)",
            attack_bait["n_completed"],
            None, attack_bait["overall"]["ungrounded_count"],
            attack_bait["overall"]["requires_review_count"],
            note="ATT&CK grounding only.",
        ),
        _rate_row(
            "Wazuh live Docker SIEM",
            wazuh["total_tested"],
            wazuh["cve_ungrounded_count"], wazuh["attack_ungrounded_count"],
            wazuh["requires_review_count"],
            note="Real agent-observed alerts, not synthetic. CVE-producing alert type "
                 "(vulnerability-detector) not exercised on this single-node setup -- "
                 "0% CVE-ungrounded here means 'not tested', not 'tested and clean'.",
        ),
        _rate_row(
            "Secure_SOC_AI rule engine",
            soc["total_tested"],
            soc["cve_ungrounded_count"], soc["attack_ungrounded_count"],
            soc["requires_review_count"],
            note="External rule-engine/correlator as the alert source; this project's "
                 "guardrailed pipeline replaces only the triage step.",
        ),
        _rate_row(
            "Secure_SOC_AI CVE pool (15 real NVD CVEs)",
            soc_cve_pool["summary"]["total_tested"],
            round(soc_cve_pool["summary"]["cve_ungrounded_rate_overall"] * soc_cve_pool["summary"]["total_tested"]),
            None,
            round(soc_cve_pool["summary"]["requires_review_rate_overall"] * soc_cve_pool["summary"]["total_tested"]),
            note="Bait-style (CVE withheld): cites the correct CVE 0% of the time, never "
                 "hallucinates a wrong one either -- it just stays silent. Stated-style "
                 "(CVE given): reflected correctly 100% of the time.",
        ),
    ]

    cve_sources = [r for r in rows if r["cve_ungrounded_count"] is not None]
    attack_sources = [r for r in rows if r["attack_ungrounded_count"] is not None]
    pooled_cve_n = sum(r["n"] for r in cve_sources)
    pooled_cve_hits = sum(r["cve_ungrounded_count"] for r in cve_sources)
    pooled_attack_n = sum(r["n"] for r in attack_sources)
    pooled_attack_hits = sum(r["attack_ungrounded_count"] for r in attack_sources)

    pooled = {
        "cve_sources_pooled_n": pooled_cve_n,
        "cve_sources_pooled_ungrounded_count": pooled_cve_hits,
        "cve_sources_pooled_ungrounded_rate": round(pooled_cve_hits / pooled_cve_n, 4),
        "cve_sources_pooled_ci_95": wilson_ci(pooled_cve_hits, pooled_cve_n),
        "attack_sources_pooled_n": pooled_attack_n,
        "attack_sources_pooled_ungrounded_count": pooled_attack_hits,
        "attack_sources_pooled_ungrounded_rate": round(pooled_attack_hits / pooled_attack_n, 4),
        "attack_sources_pooled_ci_95": wilson_ci(pooled_attack_hits, pooled_attack_n),
        "total_alerts_across_all_sources": sum(r["n"] for r in rows),
    }

    significance_note = (
        "Formal significance testing (McNemar) is not meaningful for any pairwise "
        "source comparison here: the CVE-bait set has only 2 positives at n=100 and "
        "the ATT&CK-bait set only 3 at n=50 -- both far below the discordant-pair "
        "count McNemar needs to say anything. Reported as descriptive rates with "
        "Wilson 95% CIs instead, consistent with the existing CVE-bait (#21) and "
        "ATT&CK-bait precedent."
    )

    known_gap = (
        "Wazuh's vulnerability-detector (CVE-producing) alert type is not exercised "
        "in this benchmark -- blocked on a single-node Docker inventory-harvester "
        "sync limitation. The pooled CVE rate above is therefore driven by CVE-bait "
        "and the Secure_SOC_AI CVE pool, not by live Wazuh CVE alerts."
    )

    return {
        "sources": rows,
        "pooled": pooled,
        "significance_note": significance_note,
        "known_gap": known_gap,
    }


def main():
    summary = build_summary()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    print("Cross-source grounding benchmark")
    print("=" * 78)
    for r in summary["sources"]:
        cve = f"{r['cve_ungrounded_rate']:.1%}" if r["cve_ungrounded_rate"] is not None else "n/a"
        atk = f"{r['attack_ungrounded_rate']:.1%}" if r["attack_ungrounded_rate"] is not None else "n/a"
        print(f"  {r['source']:<42} n={r['n']:>4}  CVE={cve:>6}  ATT&CK={atk:>6}  "
              f"review={r['requires_review_rate']:.1%}")

    p = summary["pooled"]
    print("\nPooled")
    print(f"  CVE-checker sources:    {p['cve_sources_pooled_ungrounded_count']}/{p['cve_sources_pooled_n']} "
          f"({p['cve_sources_pooled_ungrounded_rate']:.2%}), "
          f"95% CI [{p['cve_sources_pooled_ci_95'][0]:.1%}, {p['cve_sources_pooled_ci_95'][1]:.1%}]")
    print(f"  ATT&CK-checker sources: {p['attack_sources_pooled_ungrounded_count']}/{p['attack_sources_pooled_n']} "
          f"({p['attack_sources_pooled_ungrounded_rate']:.2%}), "
          f"95% CI [{p['attack_sources_pooled_ci_95'][0]:.1%}, {p['attack_sources_pooled_ci_95'][1]:.1%}]")
    print(f"  Total alerts across all sources: {p['total_alerts_across_all_sources']}")
    print(f"\nresults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
