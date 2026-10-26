"""Builds Caddy JSON config from routes and pushes it via the Caddy admin API."""
import json
import urllib.error
import urllib.request
from pathlib import Path

ACCESS_LOG = "/var/log/caddy/access.log"
STUB_HTML = (Path(__file__).parent / "stub.html").read_text(encoding="utf-8")
# Shown when a route exists but the service behind it does not answer (502/503/504).
ERROR_HTML = (Path(__file__).parent / "error.html").read_text(encoding="utf-8")
# Served for every name that has no route. HTTPS clients asking for such a name (or for
# the bare IP) are handed a certificate for this internal name so the page can load.
FALLBACK_NAME = "doorman.local"
PRIVATE_RANGES = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "::1/128"]


def _stub_route() -> dict:
    return {"handle": [{
        "handler": "static_response",
        "status_code": 404,
        "headers": {"Content-Type": ["text/html; charset=utf-8"], "Cache-Control": ["no-store"]},
        "body": STUB_HTML,
    }]}


def _upstream_error_routes() -> dict:
    return {"routes": [{
        "match": [{"expression": "{http.error.status_code} in [502, 503, 504]"}],
        "handle": [{
            "handler": "static_response",
            "status_code": "{http.error.status_code}",
            "headers": {"Content-Type": ["text/html; charset=utf-8"], "Cache-Control": ["no-store"]},
            "body": ERROR_HTML,
        }],
    }]}


_FALLBACK_TLS = [{"default_sni": FALLBACK_NAME, "fallback_sni": FALLBACK_NAME}]


def _proxy_route(domain: str, upstream: str, tls: bool, lan_only: bool = False) -> dict:
    handler: dict = {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}
    if tls:
        handler["transport"] = {"protocol": "http", "tls": {"insecure_skip_verify": True}}
    match: dict = {"host": [domain]}
    if lan_only:
        match["remote_ip"] = {"ranges": PRIVATE_RANGES}
    return {"match": [match], "handle": [handler], "terminal": True}


def build_config(routes: list[dict], admin_domain: str = "", acme_email: str = "",
                 admin_tls: str = "auto", admin_port: int = 8080) -> dict:
    http_routes = []
    internal_hosts = []
    all_hosts = []
    extra: dict[int, list[dict]] = {}  # extra public port -> routes served on it

    if admin_domain:
        all_hosts.append(admin_domain)
        # The panel is never served to the internet, even if 80/443 are forwarded to this server.
        http_routes.append(_proxy_route(admin_domain, f"127.0.0.1:{admin_port}", False, lan_only=True))
        if admin_tls == "internal":
            internal_hosts.append(admin_domain)

    for r in routes:
        if not r["enabled"]:
            continue
        all_hosts.append(r["domain"])
        http_routes.append(_proxy_route(r["domain"], r["upstream"], bool(r["upstream_tls"])))
        if r["tls_mode"] == "internal":
            internal_hosts.append(r["domain"])
        # Extra ports are forwarded 1:1: public port N goes to port N of the upstream host.
        host = r["upstream"].rsplit(":", 1)[0]
        for p in r.get("ports", []):
            extra.setdefault(p["port"], []).append(
                _proxy_route(r["domain"], f"{host}:{p['port']}", bool(p["tls"])))

    servers: dict = {
        "doorman": {
            "listen": [":80", ":443"],
            "routes": http_routes + [_stub_route()],
            "errors": _upstream_error_routes(),
            "logs": {"default_logger_name": "doorman"},
            "tls_connection_policies": _FALLBACK_TLS,
        }
    }
    for port, port_routes in sorted(extra.items()):
        servers[f"port_{port}"] = {
            "listen": [f":{port}"],
            "routes": port_routes + [_stub_route()],
            "errors": _upstream_error_routes(),
            "logs": {"default_logger_name": "doorman"},
            "automatic_https": {"disable_redirects": True},
            "tls_connection_policies": _FALLBACK_TLS,
        }

    config: dict = {
        "admin": {"listen": "127.0.0.1:2019"},
        "logging": {
            "logs": {
                "default": {"exclude": ["http.log.access.doorman"]},
                "access": {
                    "writer": {
                        "output": "file", "filename": ACCESS_LOG, "mode": "0644",
                        "roll_size_mb": 10, "roll_keep": 3,
                    },
                    "encoder": {"format": "json"},
                    "include": ["http.log.access.doorman"],
                },
            }
        },
        "apps": {"http": {"servers": servers}},
    }

    public_hosts = [h for h in all_hosts if h not in internal_hosts]
    acme: dict = {"module": "acme"}
    if acme_email:
        acme["email"] = acme_email

    policies = [{"subjects": internal_hosts + [FALLBACK_NAME], "issuers": [{"module": "internal"}]}]
    if public_hosts:
        policies.append({"subjects": public_hosts, "issuers": [acme]})
    # Names without a route can never get a certificate: Caddy asks the admin app first,
    # which always says no but records the name so it can be turned into a route.
    policies.append({"on_demand": True, "issuers": [{"module": "internal"}]})
    config["apps"]["tls"] = {
        "certificates": {"automate": [FALLBACK_NAME]},
        "automation": {
            "policies": policies,
            "on_demand": {
                "permission": {"module": "http", "endpoint": f"http://127.0.0.1:{admin_port}/internal/ask"}
            },
        }
    }
    return config


def push(config: dict, base_url: str) -> None:
    req = urllib.request.Request(
        base_url.rstrip("/") + "/load",
        data=json.dumps(config).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Caddy rejected config: {e.read().decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Caddy is unreachable: {e.reason}") from e
