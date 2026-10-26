from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time
from pathlib import Path

from .common import DOMAIN_RE

_lock = threading.Lock()

_COUNTERS = """n INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0,
    s3 INTEGER NOT NULL DEFAULT 0, s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0"""

# Host names come straight from clients, so the number of distinct ones is capped:
# a scanner sending random Host headers must not be able to grow the database forever.
MAX_HOSTS = 1000
MAX_CLIENT_ROWS = 200_000
MAX_EVIDENCE_ROWS = 20_000
OTHER_HOST = "(other)"
RAW_IP_HOST = "(ip address)"


def _route(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["ports"] = json.loads(d.get("ports") or "[]")
    return d


def normalize_host(host: str) -> str:
    """Valid domains are kept as they are; IP literals and junk are folded into buckets."""
    if DOMAIN_RE.match(host):
        return host
    try:
        ipaddress.ip_address(host.strip("[]"))
        return RAW_IP_HOST
    except ValueError:
        return OTHER_HOST


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with _lock:
            self.conn.executescript(
                f"""CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    upstream TEXT NOT NULL,
                    upstream_tls INTEGER NOT NULL DEFAULT 0,
                    tls_mode TEXT NOT NULL DEFAULT 'auto',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    note TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS hits_hourly (
                    host TEXT NOT NULL, hour INTEGER NOT NULL, {_COUNTERS}, PRIMARY KEY (host, hour));
                CREATE TABLE IF NOT EXISTS hits_minute (
                    host TEXT NOT NULL, minute INTEGER NOT NULL, {_COUNTERS}, PRIMARY KEY (host, minute));
                CREATE TABLE IF NOT EXISTS clients_hourly (
                    host TEXT NOT NULL, ip TEXT NOT NULL, hour INTEGER NOT NULL,
                    n INTEGER NOT NULL DEFAULT 0, err INTEGER NOT NULL DEFAULT 0,
                    probe INTEGER NOT NULL DEFAULT 0, stub INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (host, ip, hour));
                CREATE TABLE IF NOT EXISTS clients_minute (
                    host TEXT NOT NULL, ip TEXT NOT NULL, minute INTEGER NOT NULL,
                    n INTEGER NOT NULL DEFAULT 0, err INTEGER NOT NULL DEFAULT 0,
                    probe INTEGER NOT NULL DEFAULT 0, stub INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (host, ip, minute));
                CREATE TABLE IF NOT EXISTS evidence (
                    ip TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
                    ts REAL NOT NULL, PRIMARY KEY (ip, kind));
                CREATE TABLE IF NOT EXISTS seen (
                    host TEXT PRIMARY KEY, ts REAL NOT NULL, total INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
                CREATE TABLE IF NOT EXISTS unknown (
                    host TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, ts REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS ignored (host TEXT PRIMARY KEY);
                DROP TABLE IF EXISTS recent;"""
            )
            cols = [r[1] for r in self.conn.execute("PRAGMA table_info(routes)")]
            for table in ("clients_hourly", "clients_minute"):  # databases from before suspicious counters
                ccols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
                for col in ("probe", "stub"):
                    if col not in ccols:
                        self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            if "ports" not in cols:  # extra ports per route, stored as JSON
                self.conn.execute("ALTER TABLE routes ADD COLUMN ports TEXT NOT NULL DEFAULT '[]'")
            self.conn.commit()

    # ---- routes ------------------------------------------------------------

    def list(self) -> list[dict]:
        with _lock:
            rows = self.conn.execute("SELECT * FROM routes ORDER BY domain").fetchall()
        return [_route(r) for r in rows]

    def get(self, route_id: int) -> dict | None:
        with _lock:
            row = self.conn.execute("SELECT * FROM routes WHERE id=?", (route_id,)).fetchone()
        return _route(row) if row else None

    def create(self, r: dict) -> dict:
        with _lock:
            cur = self.conn.execute(
                "INSERT INTO routes (domain, upstream, upstream_tls, tls_mode, enabled, note, ports)"
                " VALUES (?,?,?,?,?,?,?)",
                (r["domain"], r["upstream"], int(r["upstream_tls"]), r["tls_mode"],
                 int(r["enabled"]), r["note"], json.dumps(r.get("ports", []))),
            )
            self.conn.commit()
            new_id = cur.lastrowid
        return self.get(new_id)

    def update(self, route_id: int, r: dict) -> dict | None:
        with _lock:
            self.conn.execute(
                "UPDATE routes SET domain=?, upstream=?, upstream_tls=?, tls_mode=?,"
                " enabled=?, note=?, ports=? WHERE id=?",
                (r["domain"], r["upstream"], int(r["upstream_tls"]), r["tls_mode"],
                 int(r["enabled"]), r["note"], json.dumps(r.get("ports", [])), route_id),
            )
            self.conn.commit()
        return self.get(route_id)

    def delete(self, route_id: int) -> bool:
        with _lock:
            cur = self.conn.execute("DELETE FROM routes WHERE id=?", (route_id,))
            self.conn.commit()
        return cur.rowcount > 0

    # ---- access counters (no per-request data is kept) -----------------------

    def add_hits(self, hits: list[dict]) -> None:
        if not hits:
            return
        with _lock:
            now = time.time()
            known = {r[0] for r in self.conn.execute("SELECT domain FROM routes")}
            seen_hosts = {r[0] for r in self.conn.execute("SELECT host FROM seen")}
            client_rows = self.conn.execute("SELECT COUNT(*) FROM clients_hourly").fetchone()[0]
            if client_rows > MAX_CLIENT_ROWS:  # make room: keep a week of detail
                self.conn.execute("DELETE FROM clients_hourly WHERE hour < ?", (now - 7 * 86400,))
                client_rows = self.conn.execute("SELECT COUNT(*) FROM clients_hourly").fetchone()[0]
            for h in hits:
                host = normalize_host(h["host"])
                if host not in known and host not in seen_hosts and len(seen_hosts) >= MAX_HOSTS:
                    host = OTHER_HOST  # too many different unknown names: stop tracking new ones
                seen_hosts.add(host)
                # 499 = the browser cancelled the request itself: counted as a request, never as an error
                cancelled = h["status"] == 499
                col = None if cancelled else f"s{min(max(h['status'] // 100, 2), 5)}"
                add_c, add_v, add_u = (f", {col}", ",1", f", {col}={col}+1") if col else ("", "", "")
                for table, key, step in (("hits_hourly", "hour", 3600), ("hits_minute", "minute", 60)):
                    self.conn.execute(
                        f"INSERT INTO {table} (host, {key}, n{add_c}, bytes) VALUES (?,?,1{add_v},?)"
                        f" ON CONFLICT(host, {key}) DO UPDATE SET n=n+1{add_u}, bytes=bytes+?",
                        (host, int(h["ts"] // step * step), h["size"], h["size"]),
                    )
                err = 1 if h["status"] >= 400 and not cancelled else 0
                probe, stub = int(bool(h.get("probe"))), int(bool(h.get("stub")))
                if h.get("ip") and client_rows <= MAX_CLIENT_ROWS:
                    for table, key, step in (("clients_hourly", "hour", 3600), ("clients_minute", "minute", 60)):
                        self.conn.execute(
                            f"INSERT INTO {table} (host, ip, {key}, n, err, probe, stub) VALUES (?,?,?,1,?,?,?)"
                            f" ON CONFLICT(host, ip, {key}) DO UPDATE SET n=n+1, err=err+?, probe=probe+?, stub=stub+?",
                            (host, h["ip"], int(h["ts"] // step * step), err, probe, stub, err, probe, stub),
                        )
                if h.get("ip") and h.get("probe_kind"):
                    self._evidence(h["ip"], h["probe_kind"], h["ts"])
                if h.get("ip") and stub:
                    self._evidence(h["ip"], "stub", h["ts"])
                self.conn.execute(
                    "INSERT INTO seen (host, ts, total) VALUES (?,?,1)"
                    " ON CONFLICT(host) DO UPDATE SET ts=MAX(ts, excluded.ts), total=total+1",
                    (host, h["ts"]),
                )
            self.conn.execute("DELETE FROM hits_hourly WHERE hour < ?", (now - 31 * 86400,))
            self.conn.execute("DELETE FROM hits_minute WHERE minute < ?", (now - 3 * 3600,))
            self.conn.execute("DELETE FROM clients_hourly WHERE hour < ?", (now - 31 * 86400,))
            self.conn.execute("DELETE FROM clients_minute WHERE minute < ?", (now - 3 * 3600,))
            self.conn.execute("DELETE FROM seen WHERE ts < ?", (now - 90 * 86400,))
            self.conn.execute("DELETE FROM evidence WHERE ts < ?", (now - 31 * 86400,))
            self.conn.commit()

    def _evidence(self, ip: str, kind: str, ts: float) -> None:
        """Why an address looks hostile: a count per kind of behaviour (caller holds the lock)."""
        if self.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] >= MAX_EVIDENCE_ROWS:
            self.conn.execute("DELETE FROM evidence WHERE ts < ?", (ts - 7 * 86400,))
            if self.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] >= MAX_EVIDENCE_ROWS:
                return
        self.conn.execute(
            "INSERT INTO evidence (ip, kind, n, ts) VALUES (?,?,1,?)"
            " ON CONFLICT(ip, kind) DO UPDATE SET n=n+1, ts=MAX(ts, excluded.ts)",
            (ip, kind, ts),
        )

    def add_evidence(self, ip: str, kind: str) -> None:
        with _lock:
            self._evidence(ip, kind, time.time())
            self.conn.commit()

    def evidence_for(self, ip: str) -> list[dict]:
        with _lock:
            rows = self.conn.execute(
                "SELECT kind, n FROM evidence WHERE ip=? ORDER BY n DESC", (ip,)).fetchall()
        return [dict(r) for r in rows]

    def client_hosts(self, ip: str, since: float) -> list[dict]:
        with _lock:
            rows = self.conn.execute(
                "SELECT host, SUM(n) AS requests, SUM(err) AS errors, SUM(probe) AS probes, SUM(stub) AS stubs"
                " FROM clients_hourly WHERE ip=? AND hour >= ? GROUP BY host ORDER BY requests DESC",
                (ip, int(since // 3600 * 3600)),
            ).fetchall()
        return [dict(r) for r in rows]

    def counters_since(self, table: str, since: float) -> list[dict]:
        key = {"hits_hourly": "hour", "hits_minute": "minute"}[table]
        step = 3600 if key == "hour" else 60
        with _lock:
            rows = self.conn.execute(
                f"SELECT host, {key} AS t, n, s2, s3, s4, s5, bytes FROM {table} WHERE {key} >= ?",
                (int(since // step * step),),
            ).fetchall()
        return [dict(r) for r in rows]

    def clients_since(self, table: str, since: float, limit: int = 1500) -> list[dict]:
        key = {"clients_hourly": "hour", "clients_minute": "minute"}[table]
        step = 3600 if key == "hour" else 60
        with _lock:
            rows = self.conn.execute(
                f"SELECT ip, host, SUM(n) AS requests, SUM(err) AS errors,"
                f" SUM(probe) AS probes, SUM(stub) AS stubs FROM {table}"
                f" WHERE {key} >= ? GROUP BY ip, host ORDER BY requests DESC LIMIT ?",
                (int(since // step * step), limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def seen_all(self) -> dict[str, dict]:
        with _lock:
            rows = self.conn.execute("SELECT * FROM seen").fetchall()
        return {r["host"]: dict(r) for r in rows}

    # ---- domains that reached Doorman without a route -----------------------

    def note_unknown(self, host: str) -> bool:
        """Counts a TLS handshake for a name that has no route (reported by Caddy).

        Returns False when the table is full and the name could not be recorded."""
        now = time.time()
        with _lock:
            self.conn.execute("DELETE FROM unknown WHERE ts < ?", (now - 30 * 86400,))
            count = self.conn.execute("SELECT COUNT(*) FROM unknown").fetchone()[0]
            exists = self.conn.execute("SELECT 1 FROM unknown WHERE host=?", (host,)).fetchone()
            if count >= 1000 and not exists:
                return False  # cap the table so scanners cannot grow it without bound
            self.conn.execute(
                "INSERT INTO unknown (host, n, ts) VALUES (?,1,?)"
                " ON CONFLICT(host) DO UPDATE SET n=n+1, ts=excluded.ts",
                (host, now),
            )
            self.conn.commit()
            return True

    def unknown_attempts(self) -> dict[str, int]:
        with _lock:
            rows = self.conn.execute("SELECT host, n FROM unknown").fetchall()
        return {r["host"]: r["n"] for r in rows}

    def ignore(self, host: str) -> None:
        with _lock:
            self.conn.execute("INSERT OR IGNORE INTO ignored (host) VALUES (?)", (host,))
            self.conn.commit()

    def ignored_all(self) -> set[str]:
        with _lock:
            rows = self.conn.execute("SELECT host FROM ignored").fetchall()
        return {r["host"] for r in rows}

    # ---- reset -----------------------------------------------------------------

    def reset(self, scope: str) -> None:
        """counters: all numbers; lists: unrouted names and dismissed names; all: both.

        The read position in Caddy's access log is kept, so old lines are never counted again."""
        if scope not in ("counters", "lists", "all"):
            raise ValueError(scope)
        with _lock:
            if scope in ("counters", "all"):
                for table in ("hits_hourly", "hits_minute", "clients_hourly", "clients_minute", "evidence"):
                    self.conn.execute(f"DELETE FROM {table}")
                self.conn.execute("UPDATE seen SET total=0")
            if scope in ("lists", "all"):
                self.conn.execute("DELETE FROM unknown")
                self.conn.execute("DELETE FROM ignored")
                self.conn.execute("DELETE FROM seen WHERE host NOT IN (SELECT domain FROM routes)")
            self.conn.commit()

    # ---- misc -----------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with _lock:
            row = self.conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with _lock:
            self.conn.execute(
                "INSERT INTO meta (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (key, value),
            )
            self.conn.commit()
