import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import time
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator, model_validator
from starlette.middleware.sessions import SessionMiddleware

from . import bans, caddy, security, stats
from .common import DOMAIN_RE
from .db import Store

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_DOMAIN = os.environ.get("ADMIN_DOMAIN", "").strip().lower()
ACME_EMAIL = os.environ.get("ACME_EMAIL", "").strip()
ADMIN_TLS = os.environ.get("ADMIN_TLS", "auto").strip()
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8080"))
CADDY_URL = os.environ.get("CADDY_ADMIN_URL", "http://127.0.0.1:2019")
RESERVED_PORTS = {80, 443, 2019, ADMIN_PORT}  # standard ports, Caddy's admin API, this panel
STATIC = Path(__file__).parent / "static"

UPSTREAM_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:\d{1,5})?$")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_BODY = 64 * 1024
WEAK_PASSWORDS = {"change-me-to-something-long", "changeme", "password", "admin", "administrator", "12345678"}
MIN_PASSWORD_LENGTH = 12
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def _secret_key() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    f = DATA_DIR / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
        f.chmod(0o600)
    return f.read_text().strip()


def check_password(password: str) -> None:
    """The panel can open ports and reroute traffic: refuse to start with a guessable password."""
    if not password:
        raise RuntimeError("ADMIN_PASSWORD is not set")
    if len(password) < MIN_PASSWORD_LENGTH or password.lower() in WEAK_PASSWORDS:
        raise RuntimeError(f"ADMIN_PASSWORD is too weak: use at least {MIN_PASSWORD_LENGTH} characters "
                           "and not a well-known word")


store = Store(DATA_DIR / "doorman.db")
_fails: dict[str, list[float]] = {}


def client_ip(request: Request) -> str:
    """The address of the caller. X-Forwarded-For is believed only when it comes from Caddy on
    this very host (loopback); from anywhere else it is attacker-controlled and ignored."""
    peer = request.client.host if request.client else ""
    try:
        from_proxy = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        from_proxy = False
    if from_proxy:
        first = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(first))
        except ValueError:
            pass
    return peer


def current_config() -> dict:
    return caddy.build_config(store.list(), ADMIN_DOMAIN, ACME_EMAIL, ADMIN_TLS, ADMIN_PORT)


def write_firewall_ports() -> None:
    """Publishes the extra ports in use; a root helper on the host mirrors them into ufw."""
    ports = sorted({p["port"] for r in store.list() if r["enabled"] for p in r["ports"]})
    try:
        with open(DATA_DIR / "firewall-ports.json", "w", encoding="utf-8") as f:
            json.dump({"tcp": ports}, f)
    except OSError:
        pass


def apply_config() -> str | None:
    """Push current routes to Caddy. Returns an error message or None."""
    try:
        caddy.push(current_config(), CADDY_URL)
        return None
    except RuntimeError as e:
        return str(e)


@asynccontextmanager
async def lifespan(_: FastAPI):
    check_password(ADMIN_PASSWORD)
    for _attempt in range(15):  # Caddy may still be starting
        if apply_config() is None:
            break
        time.sleep(1)
    write_firewall_ports()
    stop_stats = stats.start(store)
    yield
    stop_stats.set()


app = FastAPI(title="Doorman", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=_secret_key(),
    same_site="strict",
    https_only=os.environ.get("COOKIE_SECURE", "true" if ADMIN_DOMAIN else "false") == "true",
    max_age=60 * 60 * 12,
)


def _host_allowed(host_header: str) -> bool:
    """Blocks DNS-rebinding: a web page cannot reach the panel through a name it controls.
    Allowed: localhost, the configured admin domain and plain IP addresses."""
    try:
        hostname = (urlsplit("//" + host_header).hostname or "").lower()
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname == "localhost" or (ADMIN_DOMAIN and hostname == ADMIN_DOMAIN):
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


@app.middleware("http")
async def guard(request: Request, call_next):
    host = request.headers.get("host", "")
    if not _host_allowed(host):
        return PlainTextResponse("Bad host", status_code=400)
    if request.method in UNSAFE_METHODS:
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc.lower() != host.lower():
            return JSONResponse({"detail": "Cross-origin request refused"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site request refused"}, status_code=403)
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > MAX_BODY:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
    response = await call_next(request)
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Frame-Options"] = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if not request.url.path.startswith("/static/"):
        h["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        h["Strict-Transport-Security"] = "max-age=31536000"
    if "server" in h:
        del h["server"]
    return response


class PortIn(BaseModel):
    """Extra port, forwarded 1:1: public port N goes to port N of the upstream host."""
    port: int
    tls: bool = False

    @field_validator("port")
    @classmethod
    def _port(cls, v: int) -> int:
        if not 1024 <= v <= 65535 or v in RESERVED_PORTS:
            raise ValueError(f"Port {v} is not allowed: use 1024-65535 (2019 and {ADMIN_PORT} are reserved)")
        return v


class RouteIn(BaseModel):
    domain: str
    upstream: str
    upstream_tls: bool = False
    tls_mode: str = "auto"
    enabled: bool = True
    note: str = ""
    ports: list[PortIn] = []

    @field_validator("ports")
    @classmethod
    def _unique_ports(cls, v: list[PortIn]) -> list[PortIn]:
        if len({p.port for p in v}) != len(v):
            raise ValueError("Duplicate port")
        if len(v) > 20:
            raise ValueError("At most 20 extra ports per route")
        return v

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_RE.match(v):
            raise ValueError("Invalid domain")
        return v

    @field_validator("upstream")
    @classmethod
    def _upstream(cls, v: str) -> str:
        v = v.strip()
        if not UPSTREAM_RE.match(v) or (":" in v and not 0 < int(v.rsplit(":", 1)[1]) < 65536):
            raise ValueError("Upstream must look like 192.168.1.10 or 192.168.1.10:8080")
        return v

    @model_validator(mode="after")
    def _default_port(self):
        # No port given: 80 for plain HTTP upstreams, 443 for HTTPS ones.
        if ":" not in self.upstream:
            self.upstream += ":443" if self.upstream_tls else ":80"
        return self

    @field_validator("tls_mode")
    @classmethod
    def _tls(cls, v: str) -> str:
        if v not in ("auto", "internal"):
            raise ValueError("tls_mode must be 'auto' or 'internal'")
        return v

    @field_validator("note")
    @classmethod
    def _note(cls, v: str) -> str:
        return v.strip()[:200]


def require_auth(request: Request) -> None:
    if not request.session.get("auth"):
        raise HTTPException(401, "Not authenticated")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html")


def _prune_fails(now: float) -> None:
    if len(_fails) > 5000:  # bound the memory a flood of source addresses can use
        for k in [k for k, v in _fails.items() if not v or now - v[-1] > 300]:
            del _fails[k]


@app.post("/login")
async def login(request: Request):
    ip = client_ip(request)
    now = time.time()
    _prune_fails(now)
    recent = [t for t in _fails.get(ip, []) if now - t < 300]
    if len(recent) >= 5:
        return JSONResponse({"detail": "Too many attempts, try again later"}, status_code=429)
    try:
        body = await request.json()
    except Exception:
        body = None
    password = body.get("password") if isinstance(body, dict) else None
    if not isinstance(password, str) or len(password) > 1024:
        return JSONResponse({"detail": "Bad request"}, status_code=400)
    if not hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
        security.emit("auth", ip)
        store.add_evidence(ip, "auth")
        _fails[ip] = recent + [now]
        return JSONResponse({"detail": "Wrong password"}, status_code=401)
    _fails.pop(ip, None)
    request.session.clear()
    request.session["auth"] = True
    return {"ok": True}


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/")
def index(request: Request):
    if not request.session.get("auth"):
        return RedirectResponse("/login")
    return FileResponse(STATIC / "index.html")


def _result(route: dict | None) -> dict:
    write_firewall_ports()
    err = apply_config()
    return {"route": route, "applied": err is None, "error": err}


@app.get("/api/routes", dependencies=[Depends(require_auth)])
def list_routes():
    return store.list()


@app.post("/api/routes", dependencies=[Depends(require_auth)])
def create_route(r: RouteIn):
    try:
        route = store.create(r.model_dump())
    except Exception:
        raise HTTPException(409, "Domain already exists")
    return _result(route)


@app.put("/api/routes/{route_id}", dependencies=[Depends(require_auth)])
def update_route(route_id: int, r: RouteIn):
    if not store.get(route_id):
        raise HTTPException(404, "Not found")
    try:
        route = store.update(route_id, r.model_dump())
    except Exception:
        raise HTTPException(409, "Domain already exists")
    return _result(route)


@app.delete("/api/routes/{route_id}", dependencies=[Depends(require_auth)])
def delete_route(route_id: int):
    if not store.delete(route_id):
        raise HTTPException(404, "Not found")
    return _result(None)


@app.post("/api/apply", dependencies=[Depends(require_auth)])
def apply_now():
    return _result(None)


def _reachable(upstream: str) -> bool:
    host, port = upstream.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=1.5):
            return True
    except OSError:
        return False


@app.get("/api/status", dependencies=[Depends(require_auth)])
def status():
    return {r["id"]: _reachable(r["upstream"]) for r in store.list() if r["enabled"]}


def _known_hosts() -> set[str]:
    return {r["domain"] for r in store.list()} | ({ADMIN_DOMAIN} - {""})


@app.get("/api/stats", dependencies=[Depends(require_auth)])
def get_stats(range: str = "24h"):
    if range not in stats.RANGES:
        raise HTTPException(422, "range must be one of " + ", ".join(stats.RANGES))
    return stats.build_dashboard(store, range, system_hosts=frozenset({ADMIN_DOMAIN} - {""}))


class ResetIn(BaseModel):
    scope: str


@app.post("/api/stats/reset", dependencies=[Depends(require_auth)])
def reset_stats(body: ResetIn):
    """counters = all numbers, lists = unrouted and dismissed names, all = both."""
    if body.scope not in ("counters", "lists", "all"):
        raise HTTPException(422, "scope must be counters, lists or all")
    store.reset(body.scope)
    return {"ok": True, "scope": body.scope}


class HostIn(BaseModel):
    host: str


@app.post("/api/unknown/dismiss", dependencies=[Depends(require_auth)])
def dismiss_unknown(body: HostIn):
    store.ignore(body.host.strip().lower())
    return {"ok": True}


def _valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(422, "Not an IP address")


@app.get("/api/ip", dependencies=[Depends(require_auth)])
def ip_details(ip: str):
    """The conclusion about one client address and whether it is blocked."""
    ip = _valid_ip(ip)
    out = stats.explain_ip(store, ip, _known_hosts())
    out["ban"] = bans.state_for(ip)
    return out


class BanIn(BaseModel):
    ip: str
    note: str = ""


@app.get("/api/bans", dependencies=[Depends(require_auth)])
def list_bans():
    st = bans.status()
    return {"helper_alive": st["helper_alive"],
            "manual": [{**b, **bans.state_for(b["ip"])} for b in bans.desired()],
            "jails": {j: ips for j, ips in st["jails"].items() if ips}}


@app.post("/api/bans", dependencies=[Depends(require_auth)])
def ban_ip(body: BanIn):
    try:
        bans.add(body.ip, body.note)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return bans.state_for(_valid_ip(body.ip))


@app.delete("/api/bans", dependencies=[Depends(require_auth)])
def unban_ip(ip: str):
    try:
        bans.remove(ip)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return bans.state_for(_valid_ip(ip))


@app.get("/internal/ask")
def tls_ask(request: Request, domain: str = ""):
    """Called by Caddy before it issues an on-demand certificate.

    Every asked name without a route is recorded for the "Unrouted domains" list. A
    certificate from the internal CA is allowed only for names inside the zones of
    existing routes (e.g. *.example.com when a route for app.example.com exists), and
    only while the table of recorded names has room: this keeps scanners that send
    random names from making the server mint certificates without bound. LAN clients
    that trust the internal CA then see the stub page without a warning.
    """
    if "x-forwarded-for" in request.headers:  # came through the proxy, not from Caddy itself
        raise HTTPException(404, "Not found")
    domain = domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        return JSONResponse({"allowed": False}, status_code=403)
    known = _known_hosts()
    if domain in known or domain == caddy.FALLBACK_NAME:  # the stub's own certificate name
        return JSONResponse({"allowed": True})
    zones = {d.split(".", 1)[1] for d in known if d.count(".") >= 2}
    in_zone = any(domain == z or domain.endswith("." + z) for z in zones)
    recorded = store.note_unknown(domain)
    allowed = in_zone and recorded
    return JSONResponse({"allowed": allowed}, status_code=200 if allowed else 403)


@app.get("/api/config", dependencies=[Depends(require_auth)])
def generated_config():
    return current_config()


@app.get("/api/system", dependencies=[Depends(require_auth)])
def system():
    routes = store.list()
    try:
        urllib.request.urlopen(CADDY_URL.rstrip("/") + "/config/", timeout=3).read()
        caddy_ok = True
    except OSError:
        caddy_ok = False
    return {
        "caddy_ok": caddy_ok,
        "routes_total": len(routes),
        "routes_enabled": sum(1 for r in routes if r["enabled"]),
        "admin_domain": ADMIN_DOMAIN,
        "acme_email": ACME_EMAIL,
        "ban_helper": bans.status()["helper_alive"],
    }


app.mount("/static", StaticFiles(directory=STATIC), name="static")
