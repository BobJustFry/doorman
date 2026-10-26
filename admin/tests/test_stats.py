import json
import time

from app import stats
from app.db import Store


def line(host="a.example.com", status=200, ts=None, uri="/x?token=secret", ip="10.0.0.9"):
    e = {"ts": ts or time.time(), "status": status, "size": 100, "duration": 0.012,
         "request": {"host": host, "remote_ip": ip, "method": "GET", "uri": uri}}
    return (json.dumps(e) + "\n").encode()


def test_parse_strips_query_and_port():
    hit = stats.parse_line(line(host="A.example.com:443"))
    assert hit["host"] == "a.example.com"
    assert hit["uri"] == "/x"
    assert hit["ms"] == 12


def test_parse_garbage_is_ignored():
    assert stats.parse_line(b"not json\n") is None
    assert stats.parse_line(b'{"ts": 1}\n') is None


def test_step_counts_each_line_once_and_survives_rotation(tmp_path):
    store = Store(tmp_path / "t.db")
    log = tmp_path / "access.log"
    log.write_bytes(line() + line(status=502) + line(host="b.example.com", status=404))
    assert stats.step(store, log) == 3
    assert stats.step(store, log) == 0  # nothing new, nothing counted twice

    with open(log, "ab") as f:
        f.write(line())
        f.write(b'{"partial')  # incomplete line must wait for its newline
    assert stats.step(store, log) == 1

    seen = store.seen_all()
    assert seen["a.example.com"]["total"] == 3
    assert seen["b.example.com"]["total"] == 1

    log.write_bytes(line(host="c.example.com"))  # rotated: smaller new file
    assert stats.step(store, log) == 1
    assert store.seen_all()["c.example.com"]["total"] == 1


def test_stats_api(client_with_store):
    client, store = client_with_store
    store.add_hits([stats.parse_line(line(status=200)), stats.parse_line(line(status=503)),
                    stats.parse_line(line(host="ghost.example.com"))])
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4"})
    client.post("/api/routes", json={"domain": "quiet.example.com", "upstream": "1.2.3.5"})
    data = client.get("/api/stats?range=24h").json()
    by = {h["host"]: h for h in data["hosts"]}
    assert by["a.example.com"]["requests"] == 2
    assert by["a.example.com"]["server_errors"] == 1
    assert by["a.example.com"]["routed"] is True
    assert by["a.example.com"]["active_5m"] == 2
    assert by["quiet.example.com"]["requests"] == 0 and by["quiet.example.com"]["last_seen"] is None
    assert by["ghost.example.com"]["routed"] is False
    assert sum(by["a.example.com"]["series"]) == 2
    assert len(client.get("/api/stats/recent?host=a.example.com").json()) == 2
    assert client.get("/api/stats?range=1y").status_code == 422
