"""Regression tests for the findings of the security audit: each one is an attack that worked before."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import bans, security, stats
from app.db import MAX_HOSTS, OTHER_HOST, RAW_IP_HOST, Store

PASSWORD = "test-password-1234"


def line(host="a.example.com", status=200, ip="8.8.4.4", uri="/", ts=None):
    e = {"ts": ts or time.time(), "status": status, "size": 10,
         "request": {"host": host, "client_ip": ip, "method": "GET", "uri": uri}}
    return (json.dumps(e) + "\n").encode()


# --- panel: authentication and request validation -------------------------------------------

def test_forged_x_forwarded_for_cannot_bypass_the_login_throttle(client):
    codes = [client.post("/login", json={"password": f"guess{i}"},
                         headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(8)]
    assert codes[:5] == [401] * 5 and 429 in codes  # the peer is "testclient": all attempts share one bucket


def test_forwarded_address_is_trusted_only_from_the_local_proxy():
    from starlette.requests import Request
    from app import main

    def req(peer, xff):
        scope = {"type": "http", "headers": [(b"x-forwarded-for", xff.encode())] if xff else [],
                 "client": (peer, 1234), "method": "GET", "path": "/", "query_string": b""}
        return Request(scope)

    assert main.client_ip(req("127.0.0.1", "203.0.113.9")) == "203.0.113.9"      # Caddy on this host
    assert main.client_ip(req("127.0.0.1", "not-an-ip")) == "127.0.0.1"
    assert main.client_ip(req("192.168.1.50", "203.0.113.9")) == "192.168.1.50"  # forged by a LAN client
    assert main.client_ip(req("8.8.8.8", "203.0.113.9")) == "8.8.8.8"


def test_foreign_host_header_is_refused_dns_rebinding(client):
    assert client.get("/login", headers={"Host": "evil.attacker.example"}).status_code == 400
    assert client.get("/login", headers={"Host": "localhost:8080"}).status_code == 200
    assert client.get("/login", headers={"Host": "192.168.1.5:8080"}).status_code == 200
    assert client.get("/login", headers={"Host": "[::1]:8080"}).status_code == 200


def test_cross_origin_state_changes_are_refused(client):
    client.post("/login", json={"password": PASSWORD})
    body = {"domain": "csrf.example.com", "upstream": "1.2.3.4"}
    assert client.post("/api/routes", json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/routes", json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/routes", json=body, headers={"Origin": "http://localhost"}).status_code == 200


def test_oversized_bodies_are_refused(client):
    r = client.post("/login", content=b"x" * 70000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_security_headers_on_every_page(client):
    for path in ("/login", "/static/style.css"):
        h = client.get(path).headers
        assert "default-src 'none'" in h["content-security-policy"] and "script-src 'self'" in h["content-security-policy"]
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer"
    assert client.get("/login").headers["cache-control"] == "no-store"
    assert "server" not in client.get("/login").headers


def test_pages_have_no_inline_scripts_which_the_csp_would_block():
    from pathlib import Path
    import re
    static = Path(__file__).resolve().parents[1] / "app" / "static"
    for page in ("index.html", "login.html"):
        html = (static / page).read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), page
        assert not re.search(r"\son\w+\s*=", html), page


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'{"password": 5}', b'{"password": null}', b""])
def test_malformed_login_bodies_do_not_crash(client, body):
    r = client.post("/login", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_session_cookie_flags(client):
    cookie = client.post("/login", json={"password": PASSWORD}).headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


@pytest.mark.parametrize("weak", ["", "short", "change-me-to-something-long", "Password", "administrator"])
def test_weak_admin_passwords_are_refused_at_startup(weak):
    from app import main
    with pytest.raises(RuntimeError):
        main.check_password(weak)
    main.check_password("a-long-enough-pass")


@pytest.mark.parametrize("domain", ["a.example.com\nhost: evil", "x.example.com}{evil", "a.b'; drop--.com",
                                     "a" * 300 + ".com", "-bad.example.com", "192.168.1.1"])
def test_domain_injection_is_refused(client, domain):
    client.post("/login", json={"password": PASSWORD})
    assert client.post("/api/routes", json={"domain": domain, "upstream": "1.2.3.4"}).status_code == 422


@pytest.mark.parametrize("upstream", ["1.2.3.4:80@evil.example", "evil.example:80/../x", "1.2.3.4:80;rm",
                                       "http://x:80", "a b:80", "1.2.3.4:0"])
def test_upstream_injection_is_refused(client, upstream):
    client.post("/login", json={"password": PASSWORD})
    assert client.post("/api/routes", json={"domain": "ok.example.com", "upstream": upstream}).status_code == 422


def test_everything_except_the_login_needs_a_session(client):
    for path in ("/api/routes", "/api/stats", "/api/config", "/api/system", "/api/status", "/api/bans",
                 "/api/ip?ip=8.8.8.8"):
        assert client.get(path).status_code == 401, path
    for path in ("/api/apply", "/api/stats/reset", "/api/bans", "/api/unknown/dismiss"):
        assert client.post(path, json={}).status_code == 401, path
    assert client.delete("/api/bans?ip=8.8.8.8").status_code == 401
    assert client.get("/", follow_redirects=False).status_code in (302, 307)


# --- database growth: a hostile client controls Host headers and addresses ------------------

def test_random_host_headers_cannot_grow_the_database_without_bound(tmp_path):
    store = Store(tmp_path / "t.db")
    hits = [stats.parse_line(line(host=f"scan{i}.example.com", ip="8.8.4.4")) for i in range(MAX_HOSTS + 300)]
    for h in hits:
        h["stub"] = True
    store.add_hits(hits)
    hosts = {r[0] for r in store.conn.execute("SELECT host FROM seen")}
    assert len(hosts) <= MAX_HOSTS + 1 and OTHER_HOST in hosts


def test_junk_and_ip_hosts_are_folded_into_buckets(tmp_path):
    store = Store(tmp_path / "t.db")
    hits = [stats.parse_line(line(host=h)) for h in ("10.1.2.3", "[::1]", "weird host!", "a" * 400)]
    store.add_hits(hits)
    hosts = {r[0] for r in store.conn.execute("SELECT host FROM seen")}
    assert hosts == {RAW_IP_HOST, OTHER_HOST}


# --- scanner paths: precise, no false positives for legitimate sites -------------------------

@pytest.mark.parametrize("uri,kind", [("/.env", ".env"), ("/.env.production", ".env"), ("/.git/config", ".git"),
                                       ("/.aws/credentials", ".aws"), ("/phpmyadmin/index.php", "phpmyadmin"),
                                       ("/vendor/phpunit/src/Util/PHP/eval-stdin.php", "vendor/phpunit"),
                                       ("/.DS_Store", ".ds_store"), ("/cgi-bin/luci", "cgi-bin")])
def test_scanner_paths_are_recognised(uri, kind):
    hit = stats.parse_line(line(uri=uri))
    assert hit["probe"] and hit["probe_kind"] == kind


@pytest.mark.parametrize("uri", ["/", "/.well-known/acme-challenge/x", "/.github/workflows/ci.yml", "/.environment",
                                  "/api/actuator/health", "/actuator/health", "/assets/app.js", "/environment"])
def test_legitimate_paths_are_not_flagged(uri):
    assert not stats.parse_line(line(uri=uri))["probe"]


# --- conclusion about an address and manual bans --------------------------------------------

def make_scanner(store, ip="93.123.109.214"):
    hits = [stats.parse_line(line(host="a.example.com", ip=ip, uri=u)) for u in ("/.env", "/.env", "/.git/config")]
    hits += [stats.parse_line(line(host="nope.example.com", ip=ip, status=404)) for _ in range(3)]
    stats.mark_stub(hits, {"a.example.com"})
    store.add_hits(hits)


def test_conclusion_explains_why_an_address_is_a_scanner(client_with_store):
    client, store = client_with_store
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4"})
    make_scanner(store)
    d = client.get("/api/ip?ip=93.123.109.214").json()
    assert d["level"] == "scanner" and d["can_ban"] is True and d["lan"] is False
    text = " ".join(d["reasons"])
    assert ".env" in text and "git" in text and "do not exist" in text
    assert d["requests"] == 6 and {x["host"] for x in d["domains"]} == {"a.example.com", "nope.example.com"}
    assert d["ban"]["state"] == "none"


def test_clean_and_lan_addresses_get_a_calm_conclusion(client_with_store):
    client, store = client_with_store
    store.add_hits([stats.parse_line(line(ip="192.168.1.5")), stats.parse_line(line(ip="8.8.4.5"))])
    lan = client.get("/api/ip?ip=192.168.1.5").json()
    assert lan["level"] == "clean" and lan["can_ban"] is False and lan["lan"] is True
    assert client.get("/api/ip?ip=8.8.4.5").json()["level"] == "clean"
    assert client.get("/api/ip?ip=not-an-ip").status_code == 422


def test_only_public_addresses_can_be_banned(client_with_store):
    client, _ = client_with_store
    for bad in ("192.168.1.5", "10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1",
                "100.64.0.1", "nonsense"):
        assert client.post("/api/bans", json={"ip": bad}).status_code == 422, bad
    assert client.get("/api/bans").json()["manual"] == []


def test_ban_request_is_queued_until_the_host_helper_confirms_it(client_with_store):
    from app import main
    client, _ = client_with_store
    r = client.post("/api/bans", json={"ip": "93.123.109.214", "note": "scanner"}).json()
    assert r["state"] == "queued" and r["helper_alive"] is False
    assert json.loads((main.DATA_DIR / "manual-bans.json").read_text())["bans"][0]["ip"] == "93.123.109.214"

    # the root helper on the host reports what fail2ban really blocks
    (main.DATA_DIR / "ban-status.json").write_text(json.dumps(
        {"updated": time.time(), "jails": {"doorman-manual": ["93.123.109.214"], "doorman-stub": ["8.8.4.4"]}}))
    assert client.get("/api/ip?ip=93.123.109.214").json()["ban"] == {
        "state": "banned", "jails": ["doorman-manual"], "helper_alive": True}
    listing = client.get("/api/bans").json()
    assert listing["helper_alive"] is True and listing["jails"]["doorman-stub"] == ["8.8.4.4"]

    client.delete("/api/bans?ip=93.123.109.214")
    assert client.get("/api/bans").json()["manual"] == []


def test_ban_list_is_capped(client_with_store):
    client, _ = client_with_store
    for i in range(bans.MAX_BANS):
        assert client.post("/api/bans", json={"ip": f"8.8.{i // 250}.{i % 250 + 1}"}).status_code == 200
    assert client.post("/api/bans", json={"ip": "9.9.9.9"}).status_code == 422


def test_failed_logins_become_evidence(client_with_store):
    client, store = client_with_store
    anon = TestClient(client.app, base_url="http://localhost")
    for _ in range(3):
        anon.post("/login", json={"password": "wrong"})
    ip = "testclient"  # the test client's peer is not an IP: it must not crash the conclusion
    assert store.evidence_for(ip) == [{"kind": "auth", "n": 3}]


# --- reset ------------------------------------------------------------------------------------

def seed(client, store):
    client.post("/api/routes", json={"domain": "known.example.com", "upstream": "1.2.3.4"})
    hits = [stats.parse_line(line(host="known.example.com", ip="8.8.4.4")),
            stats.parse_line(line(host="ghost.example.com", status=404, ip="8.8.4.5", uri="/.env"))]
    stats.mark_stub(hits, {"known.example.com"})
    store.add_hits(hits)
    store.note_unknown("tls-only.example.com")
    store.ignore("dismissed.example.com")


def test_reset_counters_keeps_the_lists(client_with_store):
    client, store = client_with_store
    seed(client, store)
    assert client.post("/api/stats/reset", json={"scope": "counters"}).status_code == 200
    d = client.get("/api/stats").json()
    assert d["totals"]["requests"] == 0 and d["clients"] == []
    assert store.evidence_for("8.8.4.5") == []
    assert [u["host"] for u in d["unknown"]] == ["tls-only.example.com"]  # still listed: its handshake count survives
    assert "dismissed.example.com" in store.ignored_all()
    assert client.get("/api/routes").json()[0]["domain"] == "known.example.com"  # routes are never touched


def test_reset_lists_keeps_the_counters(client_with_store):
    client, store = client_with_store
    seed(client, store)
    client.post("/api/stats/reset", json={"scope": "lists"})
    d = client.get("/api/stats").json()
    assert d["unknown"] == [] and store.ignored_all() == set()
    assert d["totals"]["requests"] == 1 and len(d["clients"]) == 2


def test_reset_all_and_validation(client_with_store):
    client, store = client_with_store
    seed(client, store)
    client.post("/api/stats/reset", json={"scope": "all"})
    d = client.get("/api/stats").json()
    assert d["totals"]["requests"] == 0 and d["unknown"] == [] and d["clients"] == []
    assert client.post("/api/stats/reset", json={"scope": "everything"}).status_code == 422


def test_reset_does_not_recount_old_log_lines(tmp_path):
    store = Store(tmp_path / "t.db")
    log = tmp_path / "access.log"
    log.write_bytes(line() + line())
    assert stats.step(store, log) == 2
    store.reset("all")
    assert stats.step(store, log) == 0  # the read position survives, nothing is counted twice
    assert store.seen_all() == {}


def test_unban_request_reaches_the_host_helper_for_every_doorman_jail(client_with_store):
    from app import main
    client, _ = client_with_store
    client.post("/api/bans", json={"ip": "93.123.109.214"})
    client.delete("/api/bans?ip=93.123.109.214")
    data = json.loads((main.DATA_DIR / "manual-bans.json").read_text())
    assert data["bans"] == [] and [u["ip"] for u in data["unban"]] == ["93.123.109.214"]
    # asking to block it again cancels the pending unban
    client.post("/api/bans", json={"ip": "93.123.109.214"})
    assert json.loads((main.DATA_DIR / "manual-bans.json").read_text())["unban"] == []
