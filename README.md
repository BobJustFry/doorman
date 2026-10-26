# 🚪 Doorman

**Self-hosted reverse proxy with a web admin panel.** Point many domains at one server on ports 80/443 and tell Doorman which internal `IP:port` each domain should go to. Certificates are issued and renewed automatically.

English · [Русский](README.ru.md)

```
app.example.com  ─┐
crm.example.com  ─┼─▶  Doorman :80/:443  ─▶  192.168.1.10:3000
wiki.example.com ─┘    (Caddy + admin UI)  ─▶  192.168.1.20:8080
                                           ─▶  192.168.1.30:80
```

## Features

- Add, edit, disable and delete `domain → IP:port` routes in a web UI
- Automatic HTTPS: Let's Encrypt for public domains, Caddy's internal CA for private ones
- Changes are applied live, with no restarts or dropped connections
- Upstream health dots (reachable / unreachable)
- Traffic dashboard: request counters, error rate, charts per domain. Only counters are kept: no IPs, URLs or per-request history.
- "Unrouted domains" list: names that reached the proxy without a route, with one-click route creation
- HTTP or HTTPS upstreams, WebSockets and HTTP/3 out of the box
- Config survives restarts; everything lives in two Docker volumes
- Tiny: Caddy plus a small FastAPI app (about 100 MB RAM in total)

## Quick start

```bash
git clone https://github.com/BobJustFry/doorman.git
cd doorman
cp .env.example .env      # set ADMIN_PASSWORD
docker compose up -d --build
```

Open the panel at <http://127.0.0.1:8080>. On a remote server, use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-server
```

Or set `ADMIN_DOMAIN=panel.example.com` in `.env` to serve the panel over HTTPS (the domain must point at the server).

## Requirements

- Docker with the Compose plugin
- Ports 80 and 443 free on the host
- For public certificates: your domains' DNS `A` records point at the server
- The server must be able to reach your upstreams. For offices behind NAT, connect the server to the LAN with a VPN such as WireGuard.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ADMIN_PASSWORD` | required | Password for the admin panel |
| `ADMIN_DOMAIN` | empty | Serve the panel on this domain over HTTPS |
| `ADMIN_TLS` | auto | `auto` (Let's Encrypt) or `internal` (Caddy CA) for the admin domain |
| `ACME_EMAIL` | empty | E-mail for Let's Encrypt notices |
| `HTTP_PORT` / `HTTPS_PORT` | 80 / 443 | Host ports for the proxy |
| `ADMIN_PORT` / `ADMIN_BIND` | 8080 / 127.0.0.1 | Port and interface for the panel (set `ADMIN_BIND=0.0.0.0` to open it on the LAN) |

## Extra ports

Besides 80/443, a route can be published on additional ports (for example `alex.example.com:8444`). Open **Routes → Edit → Advanced → Extra ports** and add the port. It is forwarded 1:1: public port `8444` goes to port `8444` of the upstream host. Tick *HTTPS upstream* if that port speaks TLS.

For every extra port also forward it on your router to the Doorman server.

The server firewall can follow your routes automatically. Install the small helper once (it needs `ufw` and root):

```bash
sudo bash deploy/install-firewall-sync.sh
```

From then on the panel publishes the ports in use and a systemd service opens or closes the matching `ufw` rules (tagged `doorman-route`; your other rules are never touched). Without the helper, open ports yourself: `sudo ufw allow 8444/tcp`.

Caddy runs with `network_mode: host`, which is why it can listen on any port without editing `docker-compose.yml`. This works on Linux hosts only (Docker Desktop on Windows/macOS is not supported for production). A side effect: upstreams on the Doorman server itself are reachable as `127.0.0.1:PORT`.

## Stub page and protection from scanners

Any host without a route gets a friendly "Nobody's home" page (HTTP 404) instead of an empty answer, on port 80 and on HTTPS, also when the server is opened by bare IP. For HTTPS, certificates for unknown names are issued by the internal CA only inside the zones of your routes (for example `*.example.com` when `app.example.com` has a route), up to 1000 names, so random scanner names cannot make the server mint certificates endlessly. Other names get a refused handshake.

The panel writes suspicious events (wrong panel password, requests for hosts without a route, scanner-only paths such as `/.env`) to `security.log` as `<epoch> doorman-<kind> ip=<address>`. Install the fail2ban jails once and offenders are banned through `ufw`:

```bash
sudo bash deploy/install-fail2ban.sh
```

| Jail | Trigger | Ban |
|---|---|---|
| `doorman-auth` | 5 wrong passwords in 10 min | 1 hour |
| `doorman-stub` | 15 requests for unknown hosts in 10 min | 12 hours |
| `doorman-probe` | 3 scanner-only paths in 10 min | 24 hours |

Private networks (`10/8`, `172.16/12`, `192.168/16`) and localhost are never banned. List bans with `sudo fail2ban-client status doorman-stub`.

## Security

What the audit looked at and what is in place:

- **Panel**: password with a minimum length (the container refuses to start with a weak one), login throttling that cannot be bypassed by forged headers, signed `HttpOnly` + `SameSite=Strict` session cookie, CSRF check (`Origin` / `Sec-Fetch-Site`), `Host` allow-list against DNS rebinding, strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, HSTS and `no-store` on every page. The panel listens on `127.0.0.1` only; with `ADMIN_DOMAIN` Caddy serves it, and only to private networks.
- **Proxy**: plain HTTP is redirected to HTTPS (308) and never serves content; slow-client limits (header timeout, idle timeout, header size); `Server`, `Via` and `X-Powered-By` are removed; the original `Host` and the public name as SNI go to the upstream; extra ports are limited to 1024-65535.
- **Scanners**: unknown names get the stub page, wrong passwords, scanner-only paths and unknown hosts are written to `security.log` and banned by fail2ban; every address has a "conclusion" dialog that explains why it is listed and lets you block it.
- **Data**: only counters and short evidence per address are stored (never paths, queries or passwords); the number of distinct hosts, addresses and evidence rows is capped, so hostile Host headers cannot fill the disk.
- **Containers**: unprivileged, all Linux capabilities dropped (Caddy keeps only `NET_BIND_SERVICE`), `no-new-privileges`, read-only root file system, process and memory limits; Caddy's admin API listens on `127.0.0.1` only. Dependencies are scanned with `pip-audit` (clean at release).
- **Host** (needs root, run once): `sudo bash deploy/harden-host.sh` disables SSH password logins (only if you already have an SSH key), root login, X11 forwarding, hardens kernel network settings, sets the firewall to deny incoming by default, installs pending updates and removes the login user from the root-equivalent `lxd` group.

Re-run `sudo bash deploy/install-fail2ban.sh` after updates: it also installs the helper behind the dashboard's **Block with fail2ban** and **Unblock** buttons. The panel itself never gets firewall rights; it only writes a request file that the helper validates (public addresses only) before acting.

**Reset statistics**: *Dashboard → Reset…* clears the counters, the lists (unrouted and dismissed names) or both. Routes, certificates and blocked addresses are never touched.

## Certificates

Each route has a certificate mode:

- **Let's Encrypt (public)**: for real domains that resolve to this server from the internet.
- **Internal CA**: for private names. Browsers will warn until you trust Caddy's root certificate (`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .`).

## Split DNS

Inside your office, point the same domains at Doorman as well (internal DNS, router or `hosts`), so every client uses the same certificates and routes.

## Security notes

- The Caddy admin API (`:2019`) is reachable only inside the Docker network and is never published.
- The panel is bound to `127.0.0.1` unless you set `ADMIN_DOMAIN`. Use a long `ADMIN_PASSWORD`; failed logins are rate limited.
- Upstream HTTPS certificates are not verified (typical for internal services with self-signed certs).

## Development

```bash
cd admin
python -m venv ../.venv && ../.venv/bin/pip install -r requirements-dev.txt
../.venv/bin/pytest
```

## License

[MIT](LICENSE)
