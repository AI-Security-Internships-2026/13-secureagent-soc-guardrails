# E3 · NVD Snapshot Mode + Frozen Cached Responses Committed
- **Labels:** engineering, reproducibility, priority:P1
- **Milestone:** M4 — Reproducibility & Release
- **Acceptance items:** 5

---

## Summary
The paper's §4.1 honestly discloses a reproducibility asymmetry (lines 334–340 in PDF):
- MITRE ATT&CK Enterprise STIX snapshot is downloaded once, versioned, SHA-256 hash committed in manuscript text. Reviewers can independently verify they have the same ATT&CK data.
- **NVD (National Vulnerability Database) lookups** are performed LIVE at runtime via the REST v2 API. NVD updates CVE descriptions, deprecates REJECTED CVEs, changes CVSS base scores, etc. over time. A reviewer re-running the experiment in 6 months or 2 years CANNOT reproduce §4.2 + §4.6 results byte-for-byte because the underlying API returns different JSON.

A reviewer who notices this asymmetry (as 3rd-tool review §23 did) will write: *"Data availability statement for CVE-side is incomplete because NVD responses are not frozen."* Fixing this is a small, bounded, high-trust engineering task.

---

## Task 1 — Inventory of CVE IDs used in ALL published experiments
Build a deduplicated CVE-ID inventory from the following 4 sources:
1. `experiments/evaluation/cve_bait_alerts/*.{py,json}` — §4.2's 150 CVE-bait IDs (both bait stated + withheld).
2. `experiments/evaluation/grounding_benchmark_summary/*` — §4.4 / §4.5 60 CVE pool IDs.
3. `experiments/evaluation/relevance_classifier_validation/cve_pairs.csv` — §4.6 80-pair NVD IDs.
4. (If still used after R3) The 479 pooled cross-source set — enumerate every unique CVE ID present in any alert evidence or any detected-citation output JSON.

Script: `scripts/inventory_cve_ids.py` → `data/nvd_snapshot/NEEDED_IDS.txt` (one ID per line, deduped + sorted). Expected count: **~290 unique CVE IDs** (rough 150+60+80 sum minus overlaps).

- [ ] **AC1:** `data/nvd_snapshot/NEEDED_IDS.txt` committed. IDs cover every CVE lookup that could possibly be triggered by a result-JSON's lookup path in the committed result files.

---

## Task 2 — Snapshot Download Script
File: `scripts/capture_nvd_snapshot.py`

For each `CVE-ID` in NEEDED_IDS.txt:
- GET `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>` with 1.0 s delay per request + retry on 429/503 (NVD public API rate limit = 5 reqs/10 s without API key — safe delay).
- Save FULL response body JSON to `data/nvd_snapshot/<CVE-ID>.json` exactly as served (no stripping, no pretty-printing — preserve byte-for-byte).
- After all saves, compute `SHA-256(cve.json)` per file and a combined manifest.
- After all files written, run:
  ```bash
  cd data/nvd_snapshot
  sha256sum *.json | sort > MANIFEST.sha256
  wc -l MANIFEST.sha256  # MUST equal count(NEEDED_IDS.txt)
  ```

- [ ] **AC2:** `data/nvd_snapshot/<CVE-ID>.json` committed for every ID. Total files = `wc -l NEEDED_IDS.txt`.
- [ ] **AC3:** `data/nvd_snapshot/MANIFEST.sha256` committed; `sha256sum -c MANIFEST.sha256` passes cleanly on a fresh checkout.

---

## Task 3 — Add `--use-snapshot` Flag to Grounding Module
Modify `src/guardrails/output_guardrail.py` (and the ATT&CK one if any live MITRE queries are used — ATT&CK is already versioned, so probably not).

```python
def query_cve_grounding(cve_id: str, use_snapshot: bool = False, snapshot_dir: str = "data/nvd_snapshot"):
    if use_snapshot:
        fp = os.path.join(snapshot_dir, f"{cve_id}.json")
        if not os.path.exists(fp):
            raise RuntimeError(f"NVD snapshot missing for {cve_id} — see scripts/capture_nvd_snapshot.py")
        with open(fp) as f:
            return json.load(f)
    # else: live NVD REST call (existing code path)
```

Then modify `soc_agent.analyse_alert()` to accept `use_snapshot=False` kwarg (default live for new alerts, explicit True for reproducibility runs), and all evaluation scripts (`cve_bait_alerts`, `selfcheckgpt_*`, `relevance_classifier_validation`) accept a CLI flag `--use-snapshot` that they plumb through.

In `selfcheckgpt_significance_test.py`, the default MUST become `--use-snapshot True` when re-running the paper's published numbers.

- [ ] **AC4:** `--use-snapshot` flag added to output_guardrail + soc_agent + all 3 evaluation driver scripts (bait, selfcheckgpt_sig, relevance_validation). Verified for 3 IDs it returns identical JSON to live-today query for those 3.

---

## Task 4 — Update Reproducibility Metadata
In `sn-article.tex` §4.1 Setup, right after the MITRE snapshot SHA, add the 2 new lines:

> *"National Vulnerability Database (NVD) lookups for all 290 CVE IDs referenced in the committed evaluation result files are frozen as a committed snapshot under `data/nvd_snapshot/` with SHA-256 manifest `<manifest_hash>` (see Issue E3). Reviewers can re-run all published CVE-side experiments with the `--use-snapshot` CLI flag across evaluation scripts to reproduce §4.2, §4.4, §4.6 without any network access to the NVD API, eliminating time-dependence of live REST lookups."*

- [ ] **AC5:** 2 new sentences in §4.1 referencing the snapshot folder + manifest hash.

---

## Risks
- NVD returns 403/429 for some CVEs during capture. In that case, request a free NVD API key from https://nvd.nist.gov/developers/request-an-api-key (instant email delivery) and pass via `NVD_API_KEY` env var in `capture_nvd_snapshot.py`.
- Snapshot size (each JSON ~ 20 KB × 290 ≈ 6 MB uncompressed). This is below most git repo size thresholds; commit it directly, no LFS needed.

---