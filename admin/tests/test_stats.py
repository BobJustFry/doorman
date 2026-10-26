import json
import time

from app import stats
from app.db import Store


def line(host="a.example.com", status=200, ts=None, uri="/x?token=secret", ip="10.0.0.9"):
    e = {"ts": ts or time.time(), "status": status, "size": 100, "duration": 0.012,
         "request": {"host": host, "remote_ip": ip, "method": "GET", "uri": uri}}
    return (json.dumps(e) + "\n").encode()


def test_parse_keeps_only_counter_fields():
    hit = stats.parse_line(line(host="A.example.com:443"))
    assert hit["host"] == "a.example.com"
    assert set(hit) == {"ts", "host", "status", "size"}


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


def test_no_request_details_are_stored(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add_hits([stats.parse_line(line(uri="/secret/path?token=abc", ip="203.0.113.7"))])
    dump = "\n".join(store.conn.iterdump())
    assert "secret" not in dump and "203.0.113.7" not in dump


def test_dashboard_totals_and_timeline(client_with_store):
    client, store = client_with_store
    store.add_hits([stats.parse_line(line(status=200)), stats.parse_line(line(status=404)),
                    stats.parse_line(line(status=503)), stats.parse_line(line(host="ghost.example.com"))])
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4"})
    client.post("/api/routes", json={"domain": "quiet.example.com", "upstream": "1.2.3.5"})

    for rng in ("1h", "24h", "7d", "30d"):
        data = client.get(f"/api/stats?range={rng}").json()
        t = data["totals"]
        assert t["requests"] == 3 and t["s2"] == 1 and t["s4"] == 1 and t["s5"] == 1
        assert abs(t["error_rate"] - 2 / 3) < 1e-9
        assert t["last5"] == 3 and t["domains"] == 2 and t["active_domains"] == 1
        assert sum(b["ok"] + b["c4"] + b["c5"] for b in data["timeline"]) == 3
        by = {h["host"]: h for h in data["hosts"]}
        assert by["a.example.com"]["requests"] == 3 and by["a.example.com"]["errors"] == 2
        assert by["quiet.example.com"]["requests"] == 0 and by["quiet.example.com"]["active"] is False
        assert "ghost.example.com" not in by  # unrouted hosts are not part of the dashboard
        assert sum(by["a.example.com"]["series"]) == 3
    assert client.get("/api/stats?range=1y").status_code == 422


def test_unknown_domains_from_http_and_tls_attempts(client_with_store):
    client, store = client_with_store
    client.post("/api/routes", json={"domain": "known.example.com", "upstream": "1.2.3.4"})
    store.add_hits([stats.parse_line(line(host="new.example.com")),
                    stats.parse_line(line(host="new.example.com")),
                    stats.parse_line(line(host="known.example.com")),
                    stats.parse_line(line(host="192.168.12.24"))])  # bare IPs are noise

    assert client.get("/internal/ask?domain=tls-only.example.com").status_code == 403
    assert client.get("/internal/ask?domain=known.example.com").status_code == 403
    assert client.get("/internal/ask?domain=tls-only.example.com").status_code == 403
    assert client.get("/internal/ask?domain=bad%20name").status_code == 403

    unknown = {u["host"]: u for u in client.get("/api/stats").json()["unknown"]}
    assert set(unknown) == {"new.example.com", "tls-only.example.com"}
    assert unknown["new.example.com"]["requests"] == 2
    assert unknown["tls-only.example.com"]["attempts"] == 2

    client.post("/api/unknown/dismiss", json={"host": "new.example.com"})
    assert [u["host"] for u in client.get("/api/stats").json()["unknown"]] == ["tls-only.example.com"]

    client.post("/api/routes", json={"domain": "tls-only.example.com", "upstream": "1.2.3.9"})
    assert client.get("/api/stats").json()["unknown"] == []


def test_ask_endpoint_refuses_proxied_requests(client):
    r = client.get("/internal/ask?domain=x.example.com", headers={"X-Forwarded-For": "8.8.8.8"})
    assert r.status_code == 404
