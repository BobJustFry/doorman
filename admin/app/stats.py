"""Reads Caddy's JSON access log and feeds per-domain statistics into the store."""
import json
import logging
import os
import threading
import time
from pathlib import Path

from .common import DOMAIN_RE
from .db import Store

log = logging.getLogger("doorman.stats")
BATCH_LINES = 5000


def parse_line(line: bytes) -> dict | None:
    try:
        e = json.loads(line)
        req = e["request"]
        return {
            # only counters are derived: no IPs, paths or queries are ever stored
            "ts": float(e["ts"]),
            "host": req["host"].split(":")[0].lower(),
            "status": int(e.get("status", 0)),
            "size": int(e.get("size", 0)),
        }
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def step(store: Store, path: Path) -> int:
    """Ingest new complete lines. Returns the number of lines consumed."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return 0
    inode = str(st.st_ino)
    pos = int(store.get_meta("log_pos") or 0)
    if store.get_meta("log_inode") != inode or st.st_size < pos:
        pos = 0  # file was rotated or replaced
    if st.st_size == pos:
        store.set_meta("log_inode", inode)
        return 0
    hits, consumed, lines = [], 0, 0
    with open(path, "rb") as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n") or lines >= BATCH_LINES:
                break
            consumed += len(raw)
            lines += 1
            hit = parse_line(raw)
            if hit:
                hits.append(hit)
    store.add_hits(hits)
    store.set_meta("log_inode", inode)
    store.set_meta("log_pos", str(pos + consumed))
    return lines


def run(store: Store, path: Path, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            while step(store, path) >= BATCH_LINES:
                pass
        except Exception:
            log.exception("stats ingest failed")
        stop.wait(1.0)


RANGES = {  # name: (table, bucket seconds, bucket count)
    "1h": ("hits_minute", 300, 12),
    "24h": ("hits_hourly", 3600, 24),
    "7d": ("hits_hourly", 86400, 7),
    "30d": ("hits_hourly", 86400, 30),
}


def build_dashboard(store: Store, range_name: str, now: float | None = None) -> dict:
    table, bucket, count = RANGES[range_name]
    now = now or time.time()
    hosts: dict[str, dict] = {}
    timeline = [{"t": now - (count - 1 - i) * bucket, "ok": 0, "c4": 0, "c5": 0} for i in range(count)]
    total = {"requests": 0, "s2": 0, "s3": 0, "s4": 0, "s5": 0, "bytes": 0}

    def host_row(name: str) -> dict:
        return hosts.setdefault(name, {
            "host": name, "requests": 0, "errors": 0, "bytes": 0, "series": [0] * count,
        })

    routed = {r["domain"]: r for r in store.list()}
    for r in store.counters_since(table, now - bucket * count):
        if r["host"] not in routed:
            continue  # unrouted hosts are listed separately and never counted as traffic
        idx = count - 1 - int((now - r["t"]) // bucket)
        if not 0 <= idx < count:
            continue
        h = host_row(r["host"])
        h["requests"] += r["n"]
        h["errors"] += r["s4"] + r["s5"]
        h["bytes"] += r["bytes"]
        h["series"][idx] += r["n"]
        tl = timeline[idx]
        tl["ok"] += r["s2"] + r["s3"]
        tl["c4"] += r["s4"]
        tl["c5"] += r["s5"]
        total["requests"] += r["n"]
        for k in ("s2", "s3", "s4", "s5", "bytes"):
            total[k] += r[k]

    for domain in routed:
        host_row(domain)
    seen = store.seen_all()
    for name, h in hosts.items():
        h["enabled"] = bool(routed[name]["enabled"])
        h["active"] = now - seen.get(name, {}).get("ts", 0) < 300
        h["share"] = h["requests"] / total["requests"] if total["requests"] else 0
    ordered = sorted(hosts.values(), key=lambda h: (-h["requests"], h["host"]))

    # requests during the last 5 minutes, from per-minute counters
    last5 = sum(r["n"] for r in store.counters_since("hits_minute", now - 300)
                if r["host"] in routed and r["t"] + 60 > now - 300)
    total["error_rate"] = (total["s4"] + total["s5"]) / total["requests"] if total["requests"] else 0
    total["active_domains"] = sum(1 for h in ordered if h["active"])
    total["domains"] = len(routed)
    total["last5"] = last5
    return {"now": now, "range": range_name, "bucket": bucket, "totals": total,
            "timeline": timeline, "hosts": ordered, "unknown": unknown_domains(store, set(routed))}


def unknown_domains(store: Store, routed: set[str]) -> list[dict]:
    """Domains that reached Doorman (HTTP requests or TLS handshakes) but have no route."""
    requests = {h: s["total"] for h, s in store.seen_all().items()}
    attempts = store.unknown_attempts()
    ignored = store.ignored_all()
    out = []
    for host in set(requests) | set(attempts):
        if host in routed or host in ignored or not DOMAIN_RE.match(host):
            continue
        out.append({"host": host, "requests": requests.get(host, 0), "attempts": attempts.get(host, 0)})
    return sorted(out, key=lambda u: (-(u["requests"] + u["attempts"]), u["host"]))


def start(store: Store) -> threading.Event:
    stop = threading.Event()
    path = Path(os.environ.get("ACCESS_LOG", "/logs/access.log"))
    threading.Thread(target=run, args=(store, path, stop), daemon=True, name="stats").start()
    return stop
