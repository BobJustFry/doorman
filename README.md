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
| `ACME_EMAIL` | empty | E-mail for Let's Encrypt notices |
| `HTTP_PORT` / `HTTPS_PORT` | 80 / 443 | Host ports for the proxy |
| `ADMIN_PORT` | 8080 | Local port (127.0.0.1 only) for the panel |

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
