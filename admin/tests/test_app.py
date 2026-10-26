import pytest

from app import caddy

PASSWORD = "test-password-1234"


def route(**kw):
    base = {"domain": "a.example.com", "upstream": "10.0.0.5:8080", "upstream_tls": 0,
            "tls_mode": "auto", "enabled": 1, "note": ""}
    return {**base, **kw}


def proxy_routes(cfg, server="doorman"):
    """The reverse-proxy routes of a server (without the helper routes and the stub)."""
    routes = cfg["apps"]["http"]["servers"][server]["routes"]
    return [r for r in routes if any("host" in m for m in r.get("match", []))
            and r["handle"][0]["handler"] == "reverse_proxy"]


def test_build_config_routes_by_host():
    cfg = caddy.build_config([route()])
    r = proxy_routes(cfg)[0]
    assert r["match"] == [{"host": ["a.example.com"]}]
    assert r["handle"][0]["upstreams"] == [{"dial": "10.0.0.5:8080"}]
    policies = cfg["apps"]["tls"]["automation"]["policies"]
    assert policies[1]["subjects"] == ["a.example.com"]  # public name keeps its own ACME policy
    assert policies[-1]["on_demand"] is True and "subjects" not in policies[-1]


def test_disabled_routes_are_skipped():
    cfg = caddy.build_config([route(enabled=0)])
    assert proxy_routes(cfg) == []
    assert "match" not in cfg["apps"]["http"]["servers"]["doorman"]["routes"][-1]  # the stub is still there


def test_internal_tls_policy_and_https_upstream():
    cfg = caddy.build_config([route(tls_mode="internal", upstream_tls=1)])
    policy = cfg["apps"]["tls"]["automation"]["policies"][0]
    assert "a.example.com" in policy["subjects"]
    assert policy["issuers"] == [{"module": "internal"}]
    handler = proxy_routes(cfg)[0]["handle"][0]
    assert handler["transport"]["tls"]["insecure_skip_verify"] is True


def test_admin_domain_route_first():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    assert proxy_routes(cfg)[0]["handle"][0]["upstreams"] == [{"dial": "127.0.0.1:8080"}]


def login(c):
    assert c.post("/login", json={"password": PASSWORD}).status_code == 200


def test_api_requires_auth(client):
    assert client.get("/api/routes").status_code == 401


def test_wrong_password_and_lockout(client):
    for _ in range(5):
        assert client.post("/login", json={"password": "x"}).status_code == 401
    assert client.post("/login", json={"password": PASSWORD}).status_code == 429


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
    assert proxy_routes(cfg)[0]["match"] == [{"host": ["a.example.com"]}]
    s = client.get("/api/system").json()
    assert s["routes_total"] == 1 and s["routes_enabled"] == 1 and s["caddy_ok"] is False


def test_admin_domain_internal_tls():
    cfg = caddy.build_config([], admin_domain="panel.corp.ru", admin_tls="internal")
    policy = cfg["apps"]["tls"]["automation"]["policies"][0]
    assert "panel.corp.ru" in policy["subjects"]


def test_default_ports(client):
    login(client)
    plain = client.post("/api/routes", json={"domain": "a.example.com", "upstream": "10.0.0.1"}).json()
    tls = client.post("/api/routes", json={"domain": "b.example.com", "upstream": "10.0.0.2",
                                           "upstream_tls": True}).json()
    assert plain["route"]["upstream"] == "10.0.0.1:80"
    assert tls["route"]["upstream"] == "10.0.0.2:443"


def test_admin_route_is_lan_only():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    routes = proxy_routes(cfg)
    assert "remote_ip" in routes[0]["match"][0]
    assert "remote_ip" not in routes[1]["match"][0]


def test_access_log_configured():
    cfg = caddy.build_config([])
    assert cfg["apps"]["http"]["servers"]["doorman"]["logs"]["default_logger_name"] == "doorman"
    assert cfg["logging"]["logs"]["access"]["include"] == ["http.log.access.doorman"]


def test_extra_ports_are_forwarded_one_to_one():
    cfg = caddy.build_config([route(domain="alex.example.com", upstream="10.0.0.20:443",
                                    ports=[{"port": 8444, "tls": True}, {"port": 9000, "tls": False}])])
    servers = cfg["apps"]["http"]["servers"]
    assert servers["port_8444"]["listen"] == [":8444"]
    handler = proxy_routes(cfg, "port_8444")[0]["handle"][0]
    assert handler["upstreams"] == [{"dial": "10.0.0.20:8444"}]
    assert handler["transport"]["tls"]["insecure_skip_verify"] is True
    plain = proxy_routes(cfg, "port_9000")[0]["handle"][0]
    assert plain["upstreams"] == [{"dial": "10.0.0.20:9000"}] and "transport" not in plain
    assert servers["doorman"]["listen"] == [":80", ":443"]


def test_two_domains_can_share_an_extra_port():
    cfg = caddy.build_config([
        route(domain="a.example.com", ports=[{"port": 8444, "tls": False}]),
        route(domain="b.example.com", upstream="10.0.0.6:80", ports=[{"port": 8444, "tls": False}]),
    ])
    assert len(proxy_routes(cfg, "port_8444")) == 2


def test_ports_api_roundtrip_and_validation(client):
    login(client)
    body = {"domain": "alex.example.com", "upstream": "10.0.0.20", "ports": [{"port": 8444, "tls": True}]}
    res = client.post("/api/routes", json=body).json()
    assert res["route"]["ports"] == [{"port": 8444, "tls": True}]
    assert client.get("/api/routes").json()[0]["ports"] == [{"port": 8444, "tls": True}]
    for bad in ([{"port": 443}], [{"port": 80}], [{"port": 22}], [{"port": 1023}], [{"port": 2019}],
                [{"port": 0}], [{"port": 70000}], [{"port": 8444}, {"port": 8444}]):
        r = client.post("/api/routes", json={**body, "domain": "x.example.com", "ports": bad})
        assert r.status_code == 422, bad


def test_stub_is_the_last_route_and_has_fallback_certificate():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    servers = cfg["apps"]["http"]["servers"]
    last = servers["doorman"]["routes"][-1]
    assert "match" not in last  # catch-all: any host without a route
    body = last["handle"][0]
    assert body["handler"] == "static_response" and body["status_code"] == 404
    assert "Здесь никого нет" in body["body"]
    assert servers["doorman"]["tls_connection_policies"][0]["fallback_sni"] == caddy.FALLBACK_NAME
    tls = cfg["apps"]["tls"]
    assert caddy.FALLBACK_NAME in tls["certificates"]["automate"]
    assert caddy.FALLBACK_NAME in tls["automation"]["policies"][0]["subjects"]


def test_extra_port_servers_also_serve_the_stub():
    cfg = caddy.build_config([route(ports=[{"port": 8444, "tls": False}])])
    srv = cfg["apps"]["http"]["servers"]["port_8444"]
    assert "match" not in srv["routes"][-1] and "tls_connection_policies" in srv


def test_dead_upstream_gets_a_friendly_error_page():
    cfg = caddy.build_config([route(ports=[{"port": 8444, "tls": False}])])
    for name in ("doorman", "port_8444"):
        errors = cfg["apps"]["http"]["servers"][name]["errors"]["routes"][0]
        assert "502" in errors["match"][0]["expression"] and "504" in errors["match"][0]["expression"]
        h = errors["handle"][0]
        assert h["status_code"] == "{http.error.status_code}"  # keep the real status for monitoring
        assert "Сервис не отвечает" in h["body"]


def test_original_host_and_sni_are_sent_to_upstream():
    cfg = caddy.build_config([route(domain="webhook.example.com", upstream="10.0.0.20:443", upstream_tls=1)])
    handler = proxy_routes(cfg)[0]["handle"][0]
    assert handler["headers"]["request"]["set"]["Host"] == ["{http.request.host}"]
    assert handler["transport"]["tls"]["server_name"] == "webhook.example.com"
    plain = proxy_routes(caddy.build_config([route()]))[0]["handle"][0]
    assert plain["headers"]["request"]["set"]["Host"] == ["{http.request.host}"] and "transport" not in plain


def test_plain_http_is_redirected_and_servers_have_slowloris_limits():
    cfg = caddy.build_config([route()], admin_domain="panel.example.com")
    srv = cfg["apps"]["http"]["servers"]["doorman"]
    redirect = next(r for r in srv["routes"] if r.get("match") == [{"protocol": "http"}])
    assert redirect["handle"][0]["status_code"] == 308 and redirect["terminal"] is True
    assert redirect["handle"][0]["headers"]["Location"] == ["https://{http.request.host}{http.request.uri}"]
    # the redirect comes before every proxy route, so no content is ever served over plain HTTP
    assert srv["routes"].index(redirect) < srv["routes"].index(proxy_routes(cfg)[0])
    assert srv["read_header_timeout"] and srv["idle_timeout"] and srv["max_header_bytes"] <= 65536


def test_server_and_powered_by_headers_are_removed():
    cfg = caddy.build_config([route()])
    handler = proxy_routes(cfg)[0]["handle"][0]
    assert {"Server", "X-Powered-By"} <= set(handler["headers"]["response"]["delete"])
    first = cfg["apps"]["http"]["servers"]["doorman"]["routes"][0]["handle"][0]
    assert first["handler"] == "headers" and {"Server", "Via"} <= set(first["response"]["delete"])


def test_caddy_does_not_try_to_install_its_ca_into_the_container():
    cfg = caddy.build_config([route()])
    assert cfg["apps"]["pki"]["certificate_authorities"]["local"]["install_trust"] is False
