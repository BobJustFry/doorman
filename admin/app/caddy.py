"""Builds Caddy JSON config from routes and pushes it via the Caddy admin API."""
import json
import urllib.error
import urllib.request


def _proxy_route(domain: str, upstream: str, tls: bool) -> dict:
    handler: dict = {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}
    if tls:
        handler["transport"] = {"protocol": "http", "tls": {"insecure_skip_verify": True}}
    return {"match": [{"host": [domain]}], "handle": [handler], "terminal": True}


def build_config(routes: list[dict], admin_domain: str = "", acme_email: str = "") -> dict:
    http_routes = []
    internal_hosts = []

    if admin_domain:
        http_routes.append(_proxy_route(admin_domain, "admin:8000", False))

    for r in routes:
        if not r["enabled"]:
            continue
        http_routes.append(_proxy_route(r["domain"], r["upstream"], bool(r["upstream_tls"])))
        if r["tls_mode"] == "internal":
            internal_hosts.append(r["domain"])

    config: dict = {
        "admin": {"listen": ":2019", "origins": ["caddy:2019"]},
        "apps": {
            "http": {"servers": {"doorman": {"listen": [":80", ":443"], "routes": http_routes}}}
        },
    }

    policies = []
    if internal_hosts:
        policies.append({"subjects": internal_hosts, "issuers": [{"module": "internal"}]})
    if acme_email:
        policies.append({"issuers": [{"module": "acme", "email": acme_email}]})
    if policies:
        config["apps"]["tls"] = {"automation": {"policies": policies}}
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
