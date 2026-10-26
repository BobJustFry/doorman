import hmac
import os
import re
import secrets
import socket
import time
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from starlette.middleware.sessions import SessionMiddleware

from . import caddy
from .db import Store

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_DOMAIN = os.environ.get("ADMIN_DOMAIN", "").strip().lower()
ACME_EMAIL = os.environ.get("ACME_EMAIL", "").strip()
ADMIN_TLS = os.environ.get("ADMIN_TLS", "auto").strip()
CADDY_URL = os.environ.get("CADDY_ADMIN_URL", "http://caddy:2019")
STATIC = Path(__file__).parent / "static"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
UPSTREAM_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}:\d{1,5}$")


def _secret_key() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    f = DATA_DIR / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
        f.chmod(0o600)
    return f.read_text().strip()


store = Store(DATA_DIR / "doorman.db")
_fails: dict[str, list[float]] = {}


def apply_config() -> str | None:
    """Push current routes to Caddy. Returns an error message or None."""
    try:
        caddy.push(caddy.build_config(store.list(), ADMIN_DOMAIN, ACME_EMAIL, ADMIN_TLS), CADDY_URL)
        return None
    except RuntimeError as e:
        return str(e)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_PASSWORD is not set")
    for _attempt in range(15):  # Caddy may still be starting
        if apply_config() is None:
            break
        time.sleep(1)
    yield


app = FastAPI(title="Doorman", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=_secret_key(),
    same_site="strict",
    https_only=os.environ.get("COOKIE_SECURE", "true" if ADMIN_DOMAIN else "false") == "true",
    max_age=60 * 60 * 12,
)


class RouteIn(BaseModel):
    domain: str
    upstream: str
    upstream_tls: bool = False
    tls_mode: str = "auto"
    enabled: bool = True
    note: str = ""

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
        if not UPSTREAM_RE.match(v) or not 0 < int(v.rsplit(":", 1)[1]) < 65536:
            raise ValueError("Upstream must look like 192.168.1.10:8080")
        return v

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


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html")


@app.post("/login")
async def login(request: Request):
    ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 300]
    if len(recent) >= 5:
        return JSONResponse({"detail": "Too many attempts, try again later"}, status_code=429)
    body = await request.json()
    ok = hmac.compare_digest(str(body.get("password", "")).encode(), ADMIN_PASSWORD.encode())
    if not ok:
        _fails[ip] = recent + [now]
        return JSONResponse({"detail": "Wrong password"}, status_code=401)
    _fails.pop(ip, None)
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


@app.get("/api/config", dependencies=[Depends(require_auth)])
def generated_config():
    return caddy.build_config(store.list(), ADMIN_DOMAIN, ACME_EMAIL)


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
    }


app.mount("/static", StaticFiles(directory=STATIC), name="static")
