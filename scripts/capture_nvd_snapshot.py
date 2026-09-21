"""
scripts/capture_nvd_snapshot.py

Downloads and freezes NVD's response for every CVE ID in
data/nvd_snapshot/NEEDED_IDS.txt (issue #48/E3, Task 2), so the paper's
CVE-side experiments (Sect. 4.2, 4.4-4.5, 4.6) can be reproduced without
depending on NVD's live API returning the same data years from now.

Saves each response body byte-for-byte (no stripping, no re-formatting)
to data/nvd_snapshot/<CVE-ID>.json, then writes a combined SHA-256
manifest (data/nvd_snapshot/MANIFEST.sha256, same `sha256sum`-compatible
format the existing verification tooling in this project already uses).

Rate limiting: NVD's public (no-API-key) limit is 5 requests per rolling
30-second window -- verified directly against NVD's own current
documentation before writing this script, since the issue that
requested this script claimed "5 reqs/10s" (Task 2's own text), which is
wrong; using it would have caused this script to be rate-limited on
nearly every request. This project's own existing NVD client
(src/guardrails/output_guardrail.py's _query_nvd()) already documents
the correct ~5/30s figure and handles it with a 1.0s inter-call delay
plus exponential backoff on 403/429 -- this script reuses that exact
proven pattern rather than inventing a new one.

Idempotent / resumable: skips any CVE ID whose JSON file already exists,
so re-running after a partial failure only fetches what's missing.

Usage:
    python -m scripts.capture_nvd_snapshot
    NVD_API_KEY=<key> python -m scripts.capture_nvd_snapshot   # optional, raises the rate limit to 50/30s
"""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NEEDED_IDS_PATH = "data/nvd_snapshot/NEEDED_IDS.txt"
SNAPSHOT_DIR = "data/nvd_snapshot"
MANIFEST_PATH = "data/nvd_snapshot/MANIFEST.sha256"

INTER_CALL_DELAY = 1.0  # matches output_guardrail.py's proven pacing
MAX_RETRIES = 5
BASE_BACKOFF = 5.0


def _fetch_raw(cve_id: str, api_key: str | None) -> bytes:
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"User-Agent": "SecureAgent-SOC/nvd-snapshot-capture"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < MAX_RETRIES - 1:
                wait = BASE_BACKOFF * (2 ** attempt)
                print(f"    HTTP {e.code}, retrying in {wait:.0f}s...")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"exhausted retries for {cve_id}")


def main():
    with open(NEEDED_IDS_PATH, encoding="utf-8") as f:
        needed_ids = [line.strip() for line in f if line.strip()]

    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        print("NVD_API_KEY set -- using the higher (50/30s) rate limit.")

    fetched, skipped, failed = 0, 0, []
    for i, cve_id in enumerate(needed_ids):
        out_path = os.path.join(SNAPSHOT_DIR, f"{cve_id}.json")
        if os.path.exists(out_path):
            skipped += 1
            continue

        print(f"[{i+1}/{len(needed_ids)}] {cve_id}...")
        try:
            raw = _fetch_raw(cve_id, api_key)
        except Exception as e:
            print(f"    FAILED: {e}")
            failed.append(cve_id)
            continue

        with open(out_path, "wb") as f:
            f.write(raw)
        fetched += 1

        if not api_key:
            time.sleep(INTER_CALL_DELAY)

    print(f"\nFetched {fetched}, skipped (already present) {skipped}, failed {len(failed)}")
    if failed:
        print(f"Failed IDs: {failed}")

    _write_manifest(needed_ids)


def _write_manifest(needed_ids: list):
    lines = []
    for cve_id in sorted(needed_ids):
        path = os.path.join(SNAPSHOT_DIR, f"{cve_id}.json")
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        # sha256sum-compatible format: "<hash>  <relative-path>"
        lines.append(f"{digest}  {cve_id}.json")

    with open(MANIFEST_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Manifest written: {MANIFEST_PATH} ({len(lines)} entries)")
    if len(lines) != len(needed_ids):
        print(f"WARNING: manifest has {len(lines)} entries but {len(needed_ids)} IDs were needed -- some downloads failed.")


if __name__ == "__main__":
    main()
