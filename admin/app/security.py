"""Writes a tiny, fail2ban-friendly log of suspicious events.

One line per event: "<epoch> doorman-<kind> ip=<address>". The panel is the only thing
that parses Caddy's JSON access log, so it also emits these lines; fail2ban on the host
only has to match this simple format. The file lives in the panel's data volume.
"""
import os
import threading
import time
from pathlib import Path

_lock = threading.Lock()
MAX_BYTES = 512 * 1024
KINDS = {"auth", "stub", "probe"}


def _path() -> Path:
    return Path(os.environ.get("DATA_DIR", "./data")) / "security.log"


def emit(kind: str, ip: str, now: float | None = None) -> None:
    if kind not in KINDS or not ip:
        return
    line = f"{int(now or time.time())} doorman-{kind} ip={ip}\n"
    path = _path()
    try:
        with _lock:
            if path.exists() and path.stat().st_size > MAX_BYTES:
                keep = path.read_text(encoding="utf-8").splitlines()[-500:]
                path.write_text("\n".join(keep) + "\n", encoding="utf-8")
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass
