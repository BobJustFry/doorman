#!/usr/bin/env python3
"""Applies the dashboard's manual blocks to fail2ban and reports what is blocked. Run as root.

Reads manual-bans.json written by the panel:
  {"bans": [{"ip": ...}], "unban": [{"ip": ..., "ts": ...}]}
and keeps the fail2ban jail "doorman-manual" equal to "bans". Addresses in "unban" are lifted
from every Doorman jail (a false positive of an automatic jail can be undone from the panel).
Afterwards ban-status.json is written so the panel can show what is really blocked.

The file is written by an unprivileged container, so nothing in it is trusted: every address
is validated, only public unicast addresses are accepted, only fixed jails are touched and no
shell is involved.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

MANUAL_JAIL = "doorman-manual"
JAILS = ["doorman-auth", "doorman-stub", "doorman-probe", MANUAL_JAIL, "sshd"]
MAX_ADDRESSES = 200
UNBAN_TTL = 600


def run_f2b(*args: str) -> str:
    done = subprocess.run(["fail2ban-client", *args], capture_output=True, text=True, timeout=30)
    return done.stdout


def public_ip(value) -> str | None:
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(addr) if addr.is_global and not addr.is_multicast else None


def banned_in(jail: str, f2b=run_f2b) -> list[str]:
    m = re.search(r"Banned IP list:\s*(.*)", f2b("status", jail))
    return [ip for ip in (m.group(1).split() if m else []) if public_ip(ip)]


def apply(data_dir: str, f2b=run_f2b, now: float | None = None) -> list[str]:
    now = now or time.time()
    try:
        with open(os.path.join(data_dir, "manual-bans.json"), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    wanted = {public_ip(b.get("ip")) for b in data.get("bans", [])[:MAX_ADDRESSES] if isinstance(b, dict)} - {None}
    lift = {public_ip(u.get("ip")) for u in data.get("unban", [])[:MAX_ADDRESSES]
            if isinstance(u, dict) and now - float(u.get("ts", 0) or 0) < UNBAN_TTL} - {None}
    log = []

    current = set(banned_in(MANUAL_JAIL, f2b))
    for ip in sorted(wanted - current):
        f2b("set", MANUAL_JAIL, "banip", ip)
        log.append(f"blocked {ip}")
    for ip in sorted(current - wanted):
        f2b("set", MANUAL_JAIL, "unbanip", ip)
        log.append(f"unblocked {ip} (manual)")
    for ip in sorted(lift):
        for jail in JAILS:
            if ip in banned_in(jail, f2b):
                f2b("set", jail, "unbanip", ip)
                log.append(f"unblocked {ip} ({jail})")

    status = {"updated": now, "jails": {jail: banned_in(jail, f2b) for jail in JAILS}}
    target = os.path.join(data_dir, "ban-status.json")
    with open(target, "w", encoding="utf-8") as f:
        json.dump(status, f)
    os.chmod(target, 0o644)
    return log


if __name__ == "__main__":
    for line in apply(sys.argv[1]):
        print(line)
