"""
scripts/inventory_cve_ids.py

Builds the deduplicated CVE-ID inventory issue #48/E3 needs, from every
source that actually contains real CVE IDs used in a published result
(not the paths the issue itself named, which don't match this repo --
verified before writing this script: `experiments/evaluation/
cve_bait_alerts/*.{py,json}` doesn't exist, it's a single file
`cve_bait_alerts.py`; `grounding_benchmark_summary/*` is likewise a
single script, not a directory; `relevance_classifier_validation/
cve_pairs.csv` doesn't exist -- the real, final validated set is
`relevance_classifier_validation_results.json`, not the working
template `pairs_to_label.csv`, which has 92 candidate pairs but only 80
were ever actually validated/used in the paper's Sect. 4.6 n=80 figure).

Three real sources, all IDs extracted directly from the files rather
than re-typed:
  1. experiments/evaluation/cve_bait_alerts.py -- Sect. 4.2's 150-alert
     CVE-bait set (stated + withheld).
  2. experiments/evaluation/soc_integration/cve_pool.py -- the 15 real
     CVEs behind Sect. 4.4/4.5's 60-alert SelfCheckGPT pool (15 CVEs x
     2 styles x 2 variants = 60 alerts, but only 15 distinct IDs).
  3. experiments/evaluation/relevance_classifier_validation/
     relevance_classifier_validation_results.json -- the actual
     validated 80-pair set behind Sect. 4.6's citable accuracy figure.

The issue also mentions a 4th, conditional source ("the 479 pooled
cross-source set, if still used after R3") -- R3 (issue #42) is
currently on hold and its scope conflict unresolved (see
docs/ROADMAP_PLAN.md Sect. 15), and the "479" figure itself doesn't
match this project's real pooled cross-source count (575, per
experiments/results/grounding_benchmark_summary.json). Deliberately
left out of this inventory: it would need R3 to land first to know what
it actually is, and NEEDED_IDS.txt can be regenerated (this script is
idempotent) once that's resolved.

Usage:
    python -m scripts.inventory_cve_ids
"""

import re
from pathlib import Path

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")

SOURCES = [
    "experiments/evaluation/cve_bait_alerts.py",
    "experiments/evaluation/soc_integration/cve_pool.py",
    "experiments/evaluation/relevance_classifier_validation/relevance_classifier_validation_results.json",
]

OUTPUT_PATH = "data/nvd_snapshot/NEEDED_IDS.txt"


def collect_ids() -> dict:
    """Returns {cve_id: sorted list of source files it appeared in}."""
    by_id: dict = {}
    for source in SOURCES:
        text = Path(source).read_text(encoding="utf-8")
        for cve_id in set(CVE_PATTERN.findall(text)):
            by_id.setdefault(cve_id, set()).add(source)
    return {k: sorted(v) for k, v in by_id.items()}


def main():
    by_id = collect_ids()
    ids_sorted = sorted(by_id)

    out_dir = Path(OUTPUT_PATH).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_PATH).write_text("\n".join(ids_sorted) + "\n", encoding="utf-8")

    print(f"{len(ids_sorted)} unique CVE IDs across {len(SOURCES)} sources -> {OUTPUT_PATH}")
    for source in SOURCES:
        count = sum(1 for v in by_id.values() if source in v)
        print(f"  {source}: {count} IDs")


if __name__ == "__main__":
    main()
