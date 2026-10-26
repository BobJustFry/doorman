"""Reads Caddy's JSON access log and feeds per-domain statistics into the store."""
import json
import logging
import os
import threading
from pathlib import Path

from .db import Store

log = logging.getLogger("doorman.stats")
BATCH_LINES = 5000


def parse_line(line: bytes) -> dict | None:
    try:
        e = json.loads(line)
        req = e["request"]
        return {
            "ts": float(e["ts"]),
            "host": req["host"].split(":")[0].lower(),
            "ip": req.get("remote_ip", ""),
            "method": req.get("method", ""),
            # query strings can carry tokens, so only the path is kept
            "uri": req.get("uri", "").split("?")[0][:200],
            "status": int(e.get("status", 0)),
            "size": int(e.get("size", 0)),
            "ms": int(float(e.get("duration", 0)) * 1000),
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


def start(store: Store) -> threading.Event:
    stop = threading.Event()
    path = Path(os.environ.get("ACCESS_LOG", "/logs/access.log"))
    threading.Thread(target=run, args=(store, path, stop), daemon=True, name="stats").start()
    return stop
