"""Builds Caddy JSON config from routes and pushes it via the Caddy admin API."""
import json
import urllib.error
import urllib.request

ACCESS_LOG = "/var/log/caddy/access.log"
ASK_URL = "http://admin:8000/internal/ask"


PRIVATE_RANGES = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "::1/128"]


def _proxy_route(domain: str, upstream: str, tls: bool, lan_only: bool = False) -> dict:
    handler: dict = {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}
    if tls:
        handler["transport"] = {"protocol": "http", "tls": {"insecure_skip_verify": True}}
    match: dict = {"host": [domain]}
    if lan_only:
        match["remote_ip"] = {"ranges": PRIVATE_RANGES}
    return {"match": [match], "handle": [handler], "terminal": True}


def build_config(routes: list[dict], admin_domain: str = "", acme_email: str = "",
                 admin_tls: str = "auto") -> dict:
    http_routes = []
    internal_hosts = []
    all_hosts = []

    if admin_domain:
        all_hosts.append(admin_domain)
        # The panel is never served to the internet, even if 80/443 are forwarded to this server.
        http_routes.append(_proxy_route(admin_domain, "admin:8000", False, lan_only=True))
        if admin_tls == "internal":
            internal_hosts.append(admin_domain)

    for r in routes:
        if not r["enabled"]:
            continue
        all_hosts.append(r["domain"])
        http_routes.append(_proxy_route(r["domain"], r["upstream"], bool(r["upstream_tls"])))
        if r["tls_mode"] == "internal":
            internal_hosts.append(r["domain"])

    config: dict = {
        "admin": {"listen": ":2019", "origins": ["caddy:2019"]},
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
        "apps": {
            "http": {
                "servers": {
                    "doorman": {
                        "listen": [":80", ":443"],
                        "routes": http_routes,
                        "logs": {"default_logger_name": "doorman"},
                    }
                }
            }
        },
    }

    public_hosts = [h for h in all_hosts if h not in internal_hosts]
    acme: dict = {"module": "acme"}
    if acme_email:
        acme["email"] = acme_email

    policies = []
    if internal_hosts:
        policies.append({"subjects": internal_hosts, "issuers": [{"module": "internal"}]})
    if public_hosts:
        policies.append({"subjects": public_hosts, "issuers": [acme]})
    # Names without a route can never get a certificate: Caddy asks the admin app first,
    # which always says no but records the name so it can be turned into a route.
    policies.append({"on_demand": True, "issuers": [{"module": "internal"}]})
    config["apps"]["tls"] = {
        "automation": {
            "policies": policies,
            "on_demand": {"permission": {"module": "http", "endpoint": ASK_URL}},
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
