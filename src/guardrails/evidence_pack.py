"""
src/guardrails/evidence_pack.py

Issue #23 step 4. Today, the CVE/ATT&CK grounding checks extract identifiers
from `format_alert()`'s output — one big formatted string that concatenates
every alert field (timestamp, IPs, ports, description, payload) together.
That works for ID-extraction (a CVE/ATT&CK regex won't false-match inside an
IP or timestamp field), but it conflates two different kinds of evidence:
free text an LLM might legitimately cite an identifier from, and structured
fields (IP, host, user, hash) that are exact values, not prose to regex over.

The Evidence Pack makes that split explicit: pull the alert's structured
fields into their own typed buckets, and separate out the free-text fields
(description, payload_snippet) as the actual surface CVE/ATT&CK grounding
should run against. `text` replaces the raw formatted blob as the input to
the existing checkers — same behaviour (structured fields never matched a
CVE/ATT&CK regex anyway), but now the grounding surface is explicit rather
than an artefact of how the LLM prompt happens to be formatted.

The structured buckets (ips/hosts/users/hashes/ports) aren't consumed by any
checker yet — CVE and MITRE ATT&CK are the only claim types in scope for
issue #23 (per the issue: no malware/tool or IOC claim-type checkers here,
that's a separate research problem). They're built now so a future
IOC-grounding checker can consume them without another schema pass, and so
the evidence pack is visible in the report for audit purposes.
"""

from src.agent.alert_schema import SecurityAlert


def build_evidence_pack(alert: SecurityAlert) -> dict:
    """
    Build the structured evidence object for one alert.

    ips/hosts/users/hashes/ports are sorted lists of the alert's own typed
    field values (empty where the alert doesn't have that field set).
    `text` is the free-text surface (description + payload_snippet) that
    CVE/ATT&CK identifier grounding runs against.
    """
    ips = sorted({ip for ip in (alert.source_ip, alert.destination_ip) if ip})
    hosts = sorted({alert.hostname} if alert.hostname else set())
    users = sorted({alert.user} if alert.user else set())
    hashes = sorted({alert.file_hash} if alert.file_hash else set())
    ports = sorted({str(alert.port)} if alert.port else set())
    text = " ".join(filter(None, [alert.description, alert.payload_snippet]))

    return {
        "ips": ips,
        "hosts": hosts,
        "users": users,
        "hashes": hashes,
        "ports": ports,
        "text": text,
    }
