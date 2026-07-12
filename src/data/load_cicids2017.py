"""
src/data/load_cicids2017.py

Loads a CICIDS2017 CSV (e.g. from the Kaggle "cicids2017" mirror) and
converts rows into SecurityAlert objects matching src/agent/alert_schema.py.

Importable:
    from src.data.load_cicids2017 import load_cicids2017_alerts
    alerts = load_cicids2017_alerts("path/to/day.csv", n=20)

CLI:
    python -m src.data.load_cicids2017 path/to/day.csv --n 20

Notes:
- CICIDS2017 CSVs (esp. Kaggle "MachineLearningCSV" mirrors) have inconsistent
  column naming: leading spaces (' Label', ' Destination Port') and sometimes
  missing Source IP / Destination IP columns depending on the mirror. This
  loader normalises column names and falls back to synthetic IPs when the
  real ones aren't present.
- Only a handful of attack labels are mapped below. Extend ATTACK_MAP as you
  pull in more days/files (CICIDS2017 ships one CSV per day, each with a
  different subset of attacks — Tue=brute force, Wed=DoS/Heartbleed,
  Thu=web attacks/infiltration, Fri=DDoS/PortScan/Botnet).
"""

import argparse
import csv
import random

from src.agent.alert_schema import SecurityAlert

# label (as it appears in the Label column, case-insensitive) -> (event_type, severity)
ATTACK_MAP = {
    "benign": ("BENIGN", "INFO"),
    "ddos": ("DDOS", "CRITICAL"),
    "dos hulk": ("DOS", "HIGH"),
    "dos goldeneye": ("DOS", "HIGH"),
    "dos slowloris": ("DOS", "MEDIUM"),
    "dos slowhttptest": ("DOS", "MEDIUM"),
    "portscan": ("PORT_SCAN", "MEDIUM"),
    "ssh-patator": ("SSH_BRUTE_FORCE", "HIGH"),
    "ftp-patator": ("FTP_BRUTE_FORCE", "HIGH"),
    "web attack – brute force": ("WEB_BRUTE_FORCE", "HIGH"),
    "web attack - brute force": ("WEB_BRUTE_FORCE", "HIGH"),
    "web attack – xss": ("WEB_XSS", "HIGH"),
    "web attack - xss": ("WEB_XSS", "HIGH"),
    "web attack – sql injection": ("WEB_SQL_INJECTION", "CRITICAL"),
    "web attack - sql injection": ("WEB_SQL_INJECTION", "CRITICAL"),
    "infiltration": ("DATA_EXFILTRATION", "CRITICAL"),
    "bot": ("BOTNET_C2", "CRITICAL"),
    "heartbleed": ("HEARTBLEED", "CRITICAL"),
}

PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def _normalise_key(k: str) -> str:
    return k.strip().lower().replace(" ", "_")


def _iter_rows(csv_path: str):
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield {_normalise_key(k): v for k, v in row.items()}


def _row_to_alert(row: dict, idx: int):
    label_raw = row.get("label", "").strip()
    key = label_raw.lower()
    if key not in ATTACK_MAP:
        return None  # skip labels we haven't mapped yet
    event_type, severity = ATTACK_MAP[key]

    src_ip = row.get("source_ip") or row.get("src_ip") or f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    dst_ip = row.get("destination_ip") or row.get("dst_ip") or f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

    dst_port_raw = row.get("destination_port", "")
    try:
        port = int(dst_port_raw) if dst_port_raw not in ("", None) else None
    except ValueError:
        port = None

    protocol = PROTO_MAP.get(str(row.get("protocol", "")).strip())

    duration = row.get("flow_duration", "?")
    fwd_pkts = row.get("total_fwd_packets", "?")
    bwd_pkts = row.get("total_backward_packets", "?")

    description = (
        f"CICIDS2017-derived flow labeled '{label_raw}': "
        f"{fwd_pkts} forward / {bwd_pkts} backward packets over {duration} flow ticks "
        f"to port {port if port is not None else 'N/A'}."
    )
    payload_snippet = f"flow_duration={duration} fwd_packets={fwd_pkts} bwd_packets={bwd_pkts} label={label_raw}"

    return SecurityAlert(
        alert_id=f"CICIDS-{idx:05d}",
        timestamp="2017-07-05 12:00:00",  # dataset capture window; parse Timestamp col if you need per-row times
        severity=severity,
        source_ip=src_ip,
        destination_ip=dst_ip,
        event_type=event_type,
        description=description,
        protocol=protocol,
        port=port,
        payload_snippet=payload_snippet,
    )


def load_cicids2017_alerts(csv_path: str, n: int = 20, skip_benign: bool = True,
                            shuffle: bool = False, seed: int | None = None,
                            only_event_types: set[str] | None = None):
    """
    Read csv_path and return up to n SecurityAlert objects built from real rows.

    shuffle=False (default): takes the first n matching rows in file order —
        fast, but biased toward whichever attack type appears first in the file
        (e.g. Tuesday's file is FTP-Patator rows before SSH-Patator rows).
    shuffle=True: reads all matching rows into memory first, shuffles, then
        takes n — gives a representative mix across attack types in the file,
        at the cost of reading the whole file before sampling. Fine for
        CICIDS2017 since attack rows (post skip_benign) are a small minority
        of each day-file, not the full multi-hundred-thousand-row CSV.
    seed: pass an int for a reproducible shuffle (useful if you want the same
        sample across repeated runs for a report).
    only_event_types: restrict to specific event_type values, e.g. {"BENIGN"}
        for false-positive testing, or {"PORT_SCAN"} to isolate one attack
        type. Applied in addition to skip_benign (set skip_benign=False if
        you want only_event_types={"BENIGN"} to actually return anything).
    """
    if not shuffle:
        alerts = []
        for row in _iter_rows(csv_path):
            alert = _row_to_alert(row, len(alerts) + 1)
            if alert is None:
                continue
            if skip_benign and alert.event_type == "BENIGN":
                continue
            if only_event_types is not None and alert.event_type not in only_event_types:
                continue
            alerts.append(alert)
            if len(alerts) >= n:
                break
        return alerts

    # shuffle=True: collect all matching raw rows first, then sample
    matching_rows = []
    for row in _iter_rows(csv_path):
        label_raw = row.get("label", "").strip()
        if label_raw.lower() not in ATTACK_MAP:
            continue
        if skip_benign and label_raw.lower() == "benign":
            continue
        matching_rows.append(row)

    rng = random.Random(seed)
    rng.shuffle(matching_rows)

    alerts = []
    for row in matching_rows:
        alert = _row_to_alert(row, len(alerts) + 1)
        if alert is None:
            continue
        if only_event_types is not None and alert.event_type not in only_event_types:
            continue
        alerts.append(alert)
        if len(alerts) >= n:
            break
    return alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="Path to a CICIDS2017 daily CSV file")
    parser.add_argument("--n", type=int, default=20, help="Number of alerts to sample")
    parser.add_argument("--shuffle", action="store_true", help="Sample a random mix instead of first N rows in file order")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible shuffling")
    args = parser.parse_args()

    alerts = load_cicids2017_alerts(args.csv_path, n=args.n, shuffle=args.shuffle, seed=args.seed)

    if not alerts:
        print("No matching attack rows found — check ATTACK_MAP against this file's Label values.")
        return

    for a in alerts:
        print(f"{a.alert_id} | {a.event_type} | {a.severity} | {a.source_ip} -> {a.destination_ip}:{a.port}")

    print(f"\nLoaded {len(alerts)} SecurityAlert objects from {args.csv_path}")


if __name__ == "__main__":
    main()