"""Manual bans from the dashboard.

The panel runs in an unprivileged container and cannot touch the firewall. It only records
what the operator asked for in manual-bans.json; a small root helper on the host
(deploy/fail2ban-bans.py) applies the list to the fail2ban jail "doorman-manual" and writes
back ban-status.json so the panel can show what is really blocked.
"""
import ipaddress
import json
import os
import time
from pathlib import Path

MAX_BANS = 200
HELPER_FRESH_SECONDS = 600


def _dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "./data"))


def validate_ip(ip: str) -> str:
    """Only public unicast addresses may be banned: never the LAN, the server itself or a range."""
    addr = ipaddress.ip_address(str(ip).strip())
    if not addr.is_global or addr.is_multicast:
        raise ValueError("Only public internet addresses can be banned")
    return str(addr)


def _read(name: str, default):
    try:
        return json.loads((_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def desired() -> list[dict]:
    items = _read("manual-bans.json", {}).get("bans", [])
    return [b for b in items if isinstance(b, dict) and "ip" in b]


UNBAN_TTL = 600


def unbans() -> list[dict]:
    now = time.time()
    items = _read("manual-bans.json", {}).get("unban", [])
    return [u for u in items if isinstance(u, dict) and "ip" in u and now - float(u.get("ts", 0)) < UNBAN_TTL]


def _write(items: list[dict], unban: list[dict] | None = None) -> None:
    # Written in place (not renamed) so the host's systemd path unit sees the change.
    with open(_dir() / "manual-bans.json", "w", encoding="utf-8") as f:
        json.dump({"bans": items, "unban": unbans() if unban is None else unban}, f)


def add(ip: str, note: str = "") -> list[dict]:
    ip = validate_ip(ip)
    items = [b for b in desired() if b["ip"] != ip]
    if len(items) >= MAX_BANS:
        raise ValueError(f"At most {MAX_BANS} manual bans")
    items.append({"ip": ip, "note": note.strip()[:100], "ts": int(time.time())})
    _write(items, [u for u in unbans() if u["ip"] != ip])
    return items


def remove(ip: str) -> list[dict]:
    ip = validate_ip(ip)
    items = [b for b in desired() if b["ip"] != ip]
    # the host helper also lifts blocks made by the automatic jails for a short while
    _write(items, [u for u in unbans() if u["ip"] != ip] + [{"ip": ip, "ts": int(time.time())}])
    return items


def status() -> dict:
    """What the host helper reports: {"updated": epoch, "jails": {jail: [ips]}}."""
    data = _read("ban-status.json", {})
    updated = float(data.get("updated", 0) or 0)
    return {"helper_alive": time.time() - updated < HELPER_FRESH_SECONDS if updated else False,
            "jails": data.get("jails", {}) if isinstance(data.get("jails"), dict) else {}}


def state_for(ip: str) -> dict:
    """none | queued (asked, not applied yet) | banned, plus which jails hold it."""
    st = status()
    jails = [j for j, ips in st["jails"].items() if ip in ips]
    asked = any(b["ip"] == ip for b in desired())
    if jails:
        state = "banned"
    elif asked:
        state = "queued"
    else:
        state = "none"
    return {"state": state, "jails": jails, "helper_alive": st["helper_alive"]}
