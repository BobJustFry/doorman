from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

_lock = threading.Lock()

_COUNTERS = """n INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0,
    s3 INTEGER NOT NULL DEFAULT 0, s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0"""


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
                CREATE TABLE IF NOT EXISTS seen (
                    host TEXT PRIMARY KEY, ts REAL NOT NULL, total INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
                CREATE TABLE IF NOT EXISTS unknown (
                    host TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, ts REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS ignored (host TEXT PRIMARY KEY);
                DROP TABLE IF EXISTS recent;"""
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

    # ---- access counters (no per-request data is kept) -----------------------

    def add_hits(self, hits: list[dict]) -> None:
        if not hits:
            return
        with _lock:
            for h in hits:
                col = f"s{min(max(h['status'] // 100, 2), 5)}"
                for table, key, step in (("hits_hourly", "hour", 3600), ("hits_minute", "minute", 60)):
                    self.conn.execute(
                        f"INSERT INTO {table} (host, {key}, n, {col}, bytes) VALUES (?,?,1,1,?)"
                        f" ON CONFLICT(host, {key}) DO UPDATE SET n=n+1, {col}={col}+1, bytes=bytes+?",
                        (h["host"], int(h["ts"] // step * step), h["size"], h["size"]),
                    )
                self.conn.execute(
                    "INSERT INTO seen (host, ts, total) VALUES (?,?,1)"
                    " ON CONFLICT(host) DO UPDATE SET ts=MAX(ts, excluded.ts), total=total+1",
                    (h["host"], h["ts"]),
                )
            now = time.time()
            self.conn.execute("DELETE FROM hits_hourly WHERE hour < ?", (now - 31 * 86400,))
            self.conn.execute("DELETE FROM hits_minute WHERE minute < ?", (now - 3 * 3600,))
            self.conn.execute("DELETE FROM seen WHERE ts < ?", (now - 90 * 86400,))
            self.conn.commit()

    def counters_since(self, table: str, since: float) -> list[dict]:
        key = {"hits_hourly": "hour", "hits_minute": "minute"}[table]
        step = 3600 if key == "hour" else 60
        with _lock:
            rows = self.conn.execute(
                f"SELECT host, {key} AS t, n, s2, s3, s4, s5, bytes FROM {table} WHERE {key} >= ?",
                (int(since // step * step),),
            ).fetchall()
        return [dict(r) for r in rows]

    def seen_all(self) -> dict[str, dict]:
        with _lock:
            rows = self.conn.execute("SELECT * FROM seen").fetchall()
        return {r["host"]: dict(r) for r in rows}

    # ---- domains that reached Doorman without a route -----------------------

    def note_unknown(self, host: str) -> None:
        """Counts a TLS handshake for a name that has no route (reported by Caddy)."""
        now = time.time()
        with _lock:
            self.conn.execute("DELETE FROM unknown WHERE ts < ?", (now - 30 * 86400,))
            count = self.conn.execute("SELECT COUNT(*) FROM unknown").fetchone()[0]
            exists = self.conn.execute("SELECT 1 FROM unknown WHERE host=?", (host,)).fetchone()
            if count >= 1000 and not exists:
                return  # cap the table so scanners cannot grow it without bound
            self.conn.execute(
                "INSERT INTO unknown (host, n, ts) VALUES (?,1,?)"
                " ON CONFLICT(host) DO UPDATE SET n=n+1, ts=excluded.ts",
                (host, now),
            )
            self.conn.commit()

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
