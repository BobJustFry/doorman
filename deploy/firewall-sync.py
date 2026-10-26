#!/usr/bin/env python3
"""Keeps ufw in sync with the extra ports used by Doorman routes.

Reads the JSON file written by the admin panel ({"tcp": [8444, ...]}) and makes sure
there is exactly one "doorman-route" ufw rule per listed port. Rules without that
comment (SSH, 80, 443, ...) are never touched. Must run as root.
"""
import json
import re
import subprocess
import sys

TAG = "doorman-route"
RULE = re.compile(r"^\[\s*(\d+)\]\s+(\d+)/tcp(?: \(v6\))?\s+ALLOW IN\b.*#\s*" + TAG + r"\s*$")


def ufw(*args: str) -> str:
    return subprocess.run(["ufw", *args], capture_output=True, text=True, check=True).stdout


def main(path: str) -> None:
    try:
        with open(path, encoding="utf-8") as f:
            desired = {int(p) for p in json.load(f).get("tcp", []) if 1024 <= int(p) <= 65535}  # never privileged ports
    except FileNotFoundError:
        desired = set()

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


if __name__ == "__main__":
    main(sys.argv[1])
