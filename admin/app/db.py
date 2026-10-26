from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

_lock = threading.Lock()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with _lock:
            self.conn.executescript(
                """CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    upstream TEXT NOT NULL,
                    upstream_tls INTEGER NOT NULL DEFAULT 0,
                    tls_mode TEXT NOT NULL DEFAULT 'auto',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    note TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS hits_hourly (
                    host TEXT NOT NULL, hour INTEGER NOT NULL, n INTEGER NOT NULL DEFAULT 0,
                    s2 INTEGER NOT NULL DEFAULT 0, s3 INTEGER NOT NULL DEFAULT 0,
                    s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host, hour)
                );
                CREATE TABLE IF NOT EXISTS seen (
                    host TEXT PRIMARY KEY, ts REAL NOT NULL, total INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS recent (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, host TEXT NOT NULL,
                    ip TEXT, method TEXT, uri TEXT, status INTEGER, ms INTEGER
                );
                CREATE INDEX IF NOT EXISTS recent_host ON recent (host, id);
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);"""
            )
            self.conn.commit()

    # ---- routes ------------------------------------------------------------

    def list(self) -> list[dict]:
        with _lock:
            rows = self.conn.execute("SELECT * FROM routes ORDER BY domain").fetchall()
        return [dict(r) for r in rows]

    def get(self, route_id: int) -> dict | None:
        with _lock:
            row = self.conn.execute("SELECT * FROM routes WHERE id=?", (route_id,)).fetchone()
        return dict(row) if row else None

    def create(self, r: dict) -> dict:
        with _lock:
            cur = self.conn.execute(
                "INSERT INTO routes (domain, upstream, upstream_tls, tls_mode, enabled, note)"
                " VALUES (?,?,?,?,?,?)",
                (r["domain"], r["upstream"], int(r["upstream_tls"]), r["tls_mode"],
                 int(r["enabled"]), r["note"]),
            )
            self.conn.commit()
            new_id = cur.lastrowid
        return self.get(new_id)

    def update(self, route_id: int, r: dict) -> dict | None:
        with _lock:
            self.conn.execute(
                "UPDATE routes SET domain=?, upstream=?, upstream_tls=?, tls_mode=?,"
                " enabled=?, note=? WHERE id=?",
                (r["domain"], r["upstream"], int(r["upstream_tls"]), r["tls_mode"],
                 int(r["enabled"]), r["note"], route_id),
            )
            self.conn.commit()
        return self.get(route_id)

    def delete(self, route_id: int) -> bool:
        with _lock:
            cur = self.conn.execute("DELETE FROM routes WHERE id=?", (route_id,))
            self.conn.commit()
        return cur.rowcount > 0

    # ---- access statistics -------------------------------------------------

    def add_hits(self, hits: list[dict]) -> None:
        if not hits:
            return
        with _lock:
            for h in hits:
                hour = int(h["ts"] // 3600 * 3600)
                col = f"s{min(max(h['status'] // 100, 2), 5)}"
                self.conn.execute(
                    f"INSERT INTO hits_hourly (host, hour, n, {col}, bytes) VALUES (?,?,1,1,?)"
                    f" ON CONFLICT(host, hour) DO UPDATE SET n=n+1, {col}={col}+1, bytes=bytes+?",
                    (h["host"], hour, h["size"], h["size"]),
                )
                self.conn.execute(
                    "INSERT INTO seen (host, ts, total) VALUES (?,?,1)"
                    " ON CONFLICT(host) DO UPDATE SET ts=MAX(ts, excluded.ts), total=total+1",
                    (h["host"], h["ts"]),
                )
                self.conn.execute(
                    "INSERT INTO recent (ts, host, ip, method, uri, status, ms) VALUES (?,?,?,?,?,?,?)",
                    (h["ts"], h["host"], h["ip"], h["method"], h["uri"], h["status"], h["ms"]),
                )
            self.conn.execute("DELETE FROM recent WHERE id < (SELECT MAX(id) FROM recent) - 2000")
            self.conn.execute("DELETE FROM hits_hourly WHERE hour < ?", (time.time() - 31 * 86400,))
            self.conn.commit()

    def hourly_since(self, since: float) -> list[dict]:
        with _lock:
            rows = self.conn.execute(
                "SELECT * FROM hits_hourly WHERE hour >= ?", (int(since // 3600 * 3600),)
            ).fetchall()
        return [dict(r) for r in rows]

    def seen_all(self) -> dict[str, dict]:
        with _lock:
            rows = self.conn.execute("SELECT * FROM seen").fetchall()
        return {r["host"]: dict(r) for r in rows}

    def recent_count(self, since: float) -> dict[str, int]:
        with _lock:
            rows = self.conn.execute(
                "SELECT host, COUNT(*) AS c FROM recent WHERE ts >= ? GROUP BY host", (since,)
            ).fetchall()
        return {r["host"]: r["c"] for r in rows}

    def recent(self, host: str, limit: int = 50) -> list[dict]:
        with _lock:
            rows = self.conn.execute(
                "SELECT ts, ip, method, uri, status, ms FROM recent WHERE host=?"
                " ORDER BY id DESC LIMIT ?",
                (host, limit),
            ).fetchall()
        return [dict(r) for r in rows]

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
