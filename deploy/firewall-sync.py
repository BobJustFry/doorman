#!/usr/bin/env python3
"""Keeps ufw in sync with the Doorman routes. Must run as root.

Reads the JSON file written by the admin panel:
  {"tcp": [8444, ...], "upstreams": ["192.168.1.10:443", ...]}

Inbound: exactly one "doorman-route" rule per extra port. Rules without that comment
(SSH, 80, 443, ...) are never touched.

Outbound (only with --egress): assume the internet-facing proxy gets broken into. Without a
limit it could then reach every machine on the LAN. With --egress the server may talk to
private networks only where a route needs it (the upstreams, port by port) plus DNS/DHCP;
everything else private is rejected. The internet stays reachable (certificates, updates).
These rules carry the comment "doorman-egress"; running without --egress removes them.

The file is written by an unprivileged container, so nothing in it is trusted: only numbers
and addresses are taken from it, symlinks are not followed and no shell is involved.
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys

TAG = "doorman-route"
EGRESS_TAG = "doorman-egress"
RULE = re.compile(r"^\[\s*(\d+)\]\s+(\d+)/tcp(?: \(v6\))?\s+ALLOW IN\b.*#\s*" + TAG + r"\s*$")
EGRESS_RULE = re.compile(r"^\[\s*(\d+)\].*#\s*" + EGRESS_TAG + r"\s*$")
STATE = "/var/lib/doorman/egress.json"
MAX_UPSTREAMS = 500
# Private, link-local and carrier-grade NAT space: the LAN, VPNs, router and cloud metadata.
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
           "fc00::/7", "fe80::/10"]


def ufw(*args: str) -> str:
    return subprocess.run(["ufw", *args], capture_output=True, text=True, check=True).stdout


def read_json(path: str) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return {}
    with os.fdopen(fd, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except ValueError:
            return {}
    return data if isinstance(data, dict) else {}


def wanted_ports(data: dict) -> set[int]:
    out = set()
    for p in data.get("tcp", []) if isinstance(data.get("tcp"), list) else []:
        try:
            p = int(p)
        except (TypeError, ValueError):
            continue
        if 1024 <= p <= 65535:  # never privileged ports
            out.add(p)
    return out


def is_private(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in ipaddress.ip_network(n) for n in PRIVATE)


def resolve(host: str) -> set[str]:
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        return set()
    try:
        return {i[4][0] for i in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)}
    except OSError:
        return set()


def wanted_upstreams(data: dict, resolver=resolve) -> tuple[set[tuple[str, int]], int]:
    """(private address, port) pairs the routes need, and how many names did not resolve.
    Public upstreams need no rule."""
    out = set()
    unresolved = 0
    items = data.get("upstreams", []) if isinstance(data.get("upstreams"), list) else []
    for item in items[:MAX_UPSTREAMS]:
        host, _, port = str(item).rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port)
        except ValueError:
            continue
        if not 0 < port < 65536:
            continue
        ips = resolver(host)
        unresolved += not ips
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if is_private(addr) and not addr.is_loopback:
                out.add((str(addr), port))
    return out, unresolved


def infrastructure() -> set[tuple[str, int, str]]:
    """DNS servers and the default gateway (DNS, DHCP): the server stops working without them."""
    out = set()
    servers = set()
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path, encoding="utf-8") as f:
                servers |= {line.split()[1] for line in f if line.startswith("nameserver ") and len(line.split()) > 1}
        except OSError:
            pass
    try:
        route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
        gateway = re.findall(r"\bvia (\S+)", route)
    except OSError:
        gateway = []
    for ip in servers | set(gateway):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if is_private(addr) and not addr.is_loopback:
            out |= {(str(addr), 53, "udp"), (str(addr), 53, "tcp")}
    for ip in gateway:
        try:
            if is_private(ipaddress.ip_address(ip)):
                out.add((str(ipaddress.ip_address(ip)), 67, "udp"))
        except ValueError:
            pass
    return out


def ipv6_enabled() -> bool:
    try:
        with open("/etc/default/ufw", encoding="utf-8") as f:
            return any(line.strip().lower() == "ipv6=yes" for line in f)
    except OSError:
        return False


def egress_plan(upstreams: set[tuple[str, int]], infra: set[tuple[str, int, str]],
                v6: bool = True) -> list[list[str]]:
    """ufw commands in order: every allow comes before the rejects (ufw checks rules in order)."""
    allows = {(ip, port, "tcp") for ip, port in upstreams} | infra
    allows = {a for a in allows if v6 or ipaddress.ip_address(a[0]).version == 4}
    plan = [["allow", "out", "proto", proto, "to", ip, "port", str(port), "comment", EGRESS_TAG]
            for ip, port, proto in sorted(allows)]
    plan += [["reject", "out", "to", net, "comment", EGRESS_TAG] for net in PRIVATE
             if v6 or ipaddress.ip_network(net).version == 4]
    return plan


def sync_ports(desired: set[int]) -> None:
    rules = []  # (rule number, port)
    for line in ufw("status", "numbered").splitlines():
        m = RULE.match(line.strip())
        if m:
            rules.append((int(m.group(1)), int(m.group(2))))
    present = {port for _, port in rules}
    # Delete from the highest number down so remaining numbers stay valid.
    for number, port in sorted(rules, reverse=True):
        if port not in desired:
            ufw("--force", "delete", str(number))
            print(f"closed {port}/tcp")
    for port in sorted(desired - present):
        ufw("allow", f"{port}/tcp", "comment", TAG)
        print(f"opened {port}/tcp")


def egress_rule_numbers() -> list[int]:
    return [int(m.group(1)) for line in ufw("status", "numbered").splitlines()
            if (m := EGRESS_RULE.match(line.strip()))]


def load_state(state_path: str = STATE):
    try:
        with open(state_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def remove_egress(applied) -> None:
    """Delete by rule text, not by number: fail2ban inserts rules at the top at any moment,
    which shifts the numbers. Numbers are only the fallback for rules we have no record of."""
    for rule in applied if isinstance(applied, list) else []:
        if isinstance(rule, list) and rule[-2:] == ["comment", EGRESS_TAG]:
            subprocess.run(["ufw", "--force", "delete", *rule[:-2]], capture_output=True, text=True)
    for number in sorted(egress_rule_numbers(), reverse=True):
        ufw("--force", "delete", str(number))


def sync_egress(plan: list[list[str]], state_path: str = STATE) -> None:
    """Rebuilds the egress rules only when the plan changed (or someone removed them)."""
    present = egress_rule_numbers()
    applied = load_state(state_path)
    # Every command yields exactly one numbered rule: each address belongs to one family.
    if applied == plan and len(present) == len(plan):
        return
    remove_egress(applied)
    for rule in plan:
        ufw(*rule)
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(plan, f)
    allows = sum(1 for r in plan if r[0] == "allow")
    print(f"egress: {allows} allowed upstream/infrastructure rules, private networks otherwise rejected")


def main(argv: list[str]) -> None:
    egress = "--egress" in argv
    paths = [a for a in argv if not a.startswith("--")]
    data = read_json(paths[0]) if paths else {}
    sync_ports(wanted_ports(data))
    if egress:
        ups, unresolved = wanted_upstreams(data)
        if unresolved and egress_rule_numbers():
            # A name did not resolve right now: keep the rules we have rather than cut a route.
            print(f"egress: {unresolved} upstream name(s) did not resolve, rules left as they are")
            return
        sync_egress(egress_plan(ups, infrastructure(), ipv6_enabled()))
    elif egress_rule_numbers():
        remove_egress(load_state())
        try:
            os.unlink(STATE)
        except OSError:
            pass
        print("egress: rules removed")


if __name__ == "__main__":
    main(sys.argv[1:])
