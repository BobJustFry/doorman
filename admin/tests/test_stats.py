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
    assert set(hit) == {"ts", "host", "ip", "status", "size"}  # no path, query or method


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
    store.add_hits([stats.parse_line(line(uri="/secret/path?token=abc", ip="8.8.8.8"))])
    dump = "\n".join(store.conn.iterdump())
    assert "secret" not in dump and "token" not in dump


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

    # inside the zone of an existing route: allowed (and recorded)
    assert client.get("/internal/ask?domain=tls-only.example.com").status_code == 200
    assert client.get("/internal/ask?domain=known.example.com").status_code == 200
    assert client.get("/internal/ask?domain=doorman.local").status_code == 200  # stub certificate
    assert client.get("/internal/ask?domain=tls-only.example.com").status_code == 200
    # outside every known zone, or not a valid name: refused
    assert client.get("/internal/ask?domain=stranger.other.org").status_code == 403
    assert client.get("/internal/ask?domain=bad%20name").status_code == 403

    unknown = {u["host"]: u for u in client.get("/api/stats").json()["unknown"]}
    assert set(unknown) == {"new.example.com", "tls-only.example.com", "stranger.other.org"}
    assert unknown["new.example.com"]["requests"] == 2
    assert unknown["tls-only.example.com"]["attempts"] == 2

    client.post("/api/unknown/dismiss", json={"host": "new.example.com"})
    left = [u["host"] for u in client.get("/api/stats").json()["unknown"]]
    assert left == ["tls-only.example.com", "stranger.other.org"]

    client.post("/api/routes", json={"domain": "tls-only.example.com", "upstream": "1.2.3.9"})
    assert [u["host"] for u in client.get("/api/stats").json()["unknown"]] == ["stranger.other.org"]


def test_ask_endpoint_refuses_proxied_requests(client):
    r = client.get("/internal/ask?domain=x.example.com", headers={"X-Forwarded-For": "8.8.8.8"})
    assert r.status_code == 404


def test_clients_per_ip_for_routed_and_unrouted(client_with_store):
    client, store = client_with_store
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4"})
    store.add_hits([
        stats.parse_line(line(host="a.example.com", ip="192.168.1.5")),
        stats.parse_line(line(host="a.example.com", ip="192.168.1.5", status=404)),
        stats.parse_line(line(host="a.example.com", ip="8.8.8.8")),
        stats.parse_line(line(host="nope.example.com", ip="8.8.8.8")),
    ])
    rows = {(c["ip"], c["host"]): c for c in client.get("/api/stats?range=24h").json()["clients"]}
    lan = rows[("192.168.1.5", "a.example.com")]
    assert lan["requests"] == 2 and lan["errors"] == 1 and lan["lan"] is True and lan["routed"] is True
    assert rows[("8.8.8.8", "a.example.com")]["lan"] is False
    assert rows[("8.8.8.8", "nope.example.com")]["routed"] is False


def test_admin_domain_is_not_listed_as_unrouted(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add_hits([stats.parse_line(line(host="panel.example.com")),
                    stats.parse_line(line(host="other.example.com"))])
    data = stats.build_dashboard(store, "24h", system_hosts=frozenset({"panel.example.com"}))
    assert [u["host"] for u in data["unknown"]] == ["other.example.com"]


def test_firewall_ports_file_only_lists_enabled_routes(client_with_store):
    import json
    client, _ = client_with_store
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4",
                                     "ports": [{"port": 8444}, {"port": 9000}]})
    client.post("/api/routes", json={"domain": "off.example.com", "upstream": "1.2.3.5", "enabled": False,
                                     "ports": [{"port": 7000}]})
    from app import main
    data = json.loads((main.DATA_DIR / "firewall-ports.json").read_text())
    assert data == {"tcp": [8444, 9000]}  # disabled routes do not open ports
