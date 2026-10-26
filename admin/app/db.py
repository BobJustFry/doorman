import sqlite3
import threading
from pathlib import Path

_lock = threading.Lock()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with _lock:
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    upstream TEXT NOT NULL,
                    upstream_tls INTEGER NOT NULL DEFAULT 0,
                    tls_mode TEXT NOT NULL DEFAULT 'auto',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    note TEXT NOT NULL DEFAULT ''
                )"""
            )
            self.conn.commit()

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
