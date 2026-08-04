"""
src/data/fetch_mitre_attack.py

One-time (periodically re-run) fetch of MITRE ATT&CK's public Enterprise
matrix, converted into a slim local snapshot for the ATT&CK technique
grounding checker (src/guardrails/attack_grounding.py).

Why a local snapshot rather than a live per-ID lookup like the NVD CVE
checker (output_guardrail.py) uses: MITRE publishes ATT&CK as a single
STIX 2.1 bundle covering the whole Enterprise matrix (~50MB, ~850
technique objects) — there's no lightweight per-technique-ID REST endpoint
the way NVD offers `?cveId=...`. Downloading and parsing the full bundle on
every verification call would be far too slow and bandwidth-heavy for a
guardrail that runs per-report. This script fetches the bundle once,
extracts only the attack-pattern (technique) objects, and writes a slim
technique_id -> {name, description, revoked} mapping that
attack_grounding.py loads locally with no network dependency at check
time.

This is a real, documented tradeoff versus the CVE checker's live NVD
lookups: the snapshot can lag MITRE's published data between refreshes.
Re-run this script periodically to pick up new/updated techniques.

Usage:
    python -m src.data.fetch_mitre_attack
    python -m src.data.fetch_mitre_attack --output data/mitre_attack/enterprise_attack_techniques.json
"""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

DEFAULT_OUTPUT = os.path.join("data", "mitre_attack", "enterprise_attack_techniques.json")


def fetch_techniques(url: str = ATTACK_STIX_URL, timeout: float = 60.0) -> dict:
    """
    Download the full Enterprise ATT&CK STIX bundle and extract a slim
    technique_id -> {name, description, revoked, url} mapping.

    `revoked` covers both STIX's own "revoked" flag (superseded/merged into
    another technique) and ATT&CK's "x_mitre_deprecated" flag (removed from
    the framework entirely) — both mean "not a technique you should expect
    an LLM to currently be citing," and the checker treats them the same
    way (a REVOKED classification, distinct from a live FABRICATED-vs-real
    distinction).
    """
    req = urllib.request.Request(url, headers={"User-Agent": "SecureAgent-SOC/attack-grounding"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))

    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if ref is None or not ref.get("external_id"):
            continue
        technique_id = ref["external_id"]
        techniques[technique_id] = {
            "name": obj.get("name"),
            "description": obj.get("description"),
            "revoked": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
            "url": ref.get("url"),
        }
    return techniques


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                         help="Where to write the slim technique snapshot")
    parser.add_argument("--url", default=ATTACK_STIX_URL,
                         help="Source STIX bundle URL")
    args = parser.parse_args()

    print(f"Fetching MITRE ATT&CK Enterprise matrix from {args.url} ...")
    techniques = fetch_techniques(args.url)

    snapshot = {
        "source": args.url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "technique_count": len(techniques),
        "techniques": techniques,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)

    revoked_count = sum(1 for t in techniques.values() if t["revoked"])
    print(f"Fetched {len(techniques)} techniques ({revoked_count} revoked/deprecated) -> {args.output}")


if __name__ == "__main__":
    main()
