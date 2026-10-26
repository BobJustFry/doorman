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
    assert "tls" not in cfg["apps"]


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
    assert first["handle"][0]["upstreams"] == [{"dial": "admin:8000"}]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD", "secret")
    from app import main
    importlib.reload(main)
    monkeypatch.setattr(main, "apply_config", lambda: None)
    with TestClient(main.app) as c:
        yield c


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
    {"domain": "a.example.com", "upstream": "1.2.3.4"},
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
