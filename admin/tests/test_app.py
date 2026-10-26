import importlib
import os

import pytest
from fastapi.testclient import TestClient

from app import caddy


def route(**kw):
    base = {"domain": "a.example.com", "upstream": "10.0.0.5:8080", "upstream_tls": 0,
            "tls_mode": "auto", "enabled": 1, "note": ""}
    return {**base, **kw}


def test_build_config_routes_by_host():
    cfg = caddy.build_config([route()])
    r = cfg["apps"]["http"]["servers"]["doorman"]["routes"][0]
    assert r["match"] == [{"host": ["a.example.com"]}]
    assert r["handle"][0]["upstreams"] == [{"dial": "10.0.0.5:8080"}]
    policies = cfg["apps"]["tls"]["automation"]["policies"]
    assert policies[0]["subjects"] == ["a.example.com"]  # public name keeps its own ACME policy
    assert policies[-1]["on_demand"] is True and "subjects" not in policies[-1]


def test_disabled_routes_are_skipped():
    cfg = caddy.build_config([route(enabled=0)])
    assert cfg["apps"]["http"]["servers"]["doorman"]["routes"] == []


def test_internal_tls_policy_and_https_upstream():
    cfg = caddy.build_config([route(tls_mode="internal", upstream_tls=1)])
    policy = cfg["apps"]["tls"]["automation"]["policies"][0]
    assert policy["subjects"] == ["a.example.com"]
    assert policy["issuers"] == [{"module": "internal"}]
    handler = cfg["apps"]["http"]["servers"]["doorman"]["routes"][0]["handle"][0]
    assert handler["transport"]["tls"]["insecure_skip_verify"] is True


def test_admin_domain_route_first():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    first = cfg["apps"]["http"]["servers"]["doorman"]["routes"][0]
    assert first["handle"][0]["upstreams"] == [{"dial": "127.0.0.1:8080"}]


def login(c):
    assert c.post("/login", json={"password": "secret"}).status_code == 200


def test_api_requires_auth(client):
    assert client.get("/api/routes").status_code == 401


def test_wrong_password_and_lockout(client):
    for _ in range(5):
        assert client.post("/login", json={"password": "x"}).status_code == 401
    assert client.post("/login", json={"password": "secret"}).status_code == 429


def test_crud(client):
    login(client)
    body = {"domain": "App.Example.com", "upstream": "192.168.1.10:3000"}
    res = client.post("/api/routes", json=body).json()
    assert res["route"]["domain"] == "app.example.com"
    rid = res["route"]["id"]
    assert client.post("/api/routes", json=body).status_code == 409
    body["upstream"] = "192.168.1.11:3000"
    assert client.put(f"/api/routes/{rid}", json=body).json()["route"]["upstream"].endswith(".11:3000")
    assert client.delete(f"/api/routes/{rid}").status_code == 200
    assert client.get("/api/routes").json() == []


@pytest.mark.parametrize("bad", [
    {"domain": "not a domain", "upstream": "1.2.3.4:80"},
    {"domain": "a.example.com", "upstream": "1.2.3.4:99999"},
    {"domain": "a.example.com", "upstream": "1.2.3.4:80", "tls_mode": "bogus"},
])
def test_validation(client, bad):
    login(client)
    assert client.post("/api/routes", json=bad).status_code == 422


def test_system_and_config_endpoints(client):
    login(client)
    client.post("/api/routes", json={"domain": "a.example.com", "upstream": "1.2.3.4:80"})
    cfg = client.get("/api/config").json()
    assert cfg["apps"]["http"]["servers"]["doorman"]["routes"][0]["match"] == [{"host": ["a.example.com"]}]
    s = client.get("/api/system").json()
    assert s["routes_total"] == 1 and s["routes_enabled"] == 1 and s["caddy_ok"] is False


def test_admin_domain_internal_tls():
    cfg = caddy.build_config([], admin_domain="panel.corp.ru", admin_tls="internal")
    policy = cfg["apps"]["tls"]["automation"]["policies"][0]
    assert policy["subjects"] == ["panel.corp.ru"]


def test_default_ports(client):
    login(client)
    plain = client.post("/api/routes", json={"domain": "a.example.com", "upstream": "10.0.0.1"}).json()
    tls = client.post("/api/routes", json={"domain": "b.example.com", "upstream": "10.0.0.2",
                                           "upstream_tls": True}).json()
    assert plain["route"]["upstream"] == "10.0.0.1:80"
    assert tls["route"]["upstream"] == "10.0.0.2:443"


def test_admin_route_is_lan_only():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    routes = cfg["apps"]["http"]["servers"]["doorman"]["routes"]
    assert "remote_ip" in routes[0]["match"][0]
    assert "remote_ip" not in routes[1]["match"][0]


def test_access_log_configured():
    cfg = caddy.build_config([])
    assert cfg["apps"]["http"]["servers"]["doorman"]["logs"]["default_logger_name"] == "doorman"
    assert cfg["logging"]["logs"]["access"]["include"] == ["http.log.access.doorman"]


def test_extra_ports_are_forwarded_one_to_one():
    cfg = caddy.build_config([route(domain="alex.example.com", upstream="192.168.12.20:443",
                                    ports=[{"port": 8444, "tls": True}, {"port": 9000, "tls": False}])])
    servers = cfg["apps"]["http"]["servers"]
    assert servers["port_8444"]["listen"] == [":8444"]
    handler = servers["port_8444"]["routes"][0]["handle"][0]
    assert handler["upstreams"] == [{"dial": "192.168.12.20:8444"}]
    assert handler["transport"]["tls"]["insecure_skip_verify"] is True
    plain = servers["port_9000"]["routes"][0]["handle"][0]
    assert plain["upstreams"] == [{"dial": "192.168.12.20:9000"}] and "transport" not in plain
    assert servers["doorman"]["listen"] == [":80", ":443"]


def test_two_domains_can_share_an_extra_port():
    cfg = caddy.build_config([
        route(domain="a.example.com", ports=[{"port": 8444, "tls": False}]),
        route(domain="b.example.com", upstream="10.0.0.6:80", ports=[{"port": 8444, "tls": False}]),
    ])
    assert len(cfg["apps"]["http"]["servers"]["port_8444"]["routes"]) == 2


def test_ports_api_roundtrip_and_validation(client):
    login(client)
    body = {"domain": "alex.example.com", "upstream": "192.168.12.20", "ports": [{"port": 8444, "tls": True}]}
    res = client.post("/api/routes", json=body).json()
    assert res["route"]["ports"] == [{"port": 8444, "tls": True}]
    assert client.get("/api/routes").json()[0]["ports"] == [{"port": 8444, "tls": True}]
    for bad in ([{"port": 443}], [{"port": 80}], [{"port": 2019}], [{"port": 0}], [{"port": 70000}],
                [{"port": 8444}, {"port": 8444}]):
        r = client.post("/api/routes", json={**body, "domain": "x.example.com", "ports": bad})
        assert r.status_code == 422, bad
