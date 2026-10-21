# Vandros Gateway

Self-hosted window onto directories on the host. Sign in, browse, and download what is already there. Files are read live.

## First run

The first start creates the admin account from `VANDROS_ADMIN_USER` and `VANDROS_ADMIN_PASSWORD`. Open the app and sign in. Later starts ignore those two variables. The password then lives in the database.

## Docker

Image: `ghcr.io/tyesamson/vandros-gateway:latest`

Publishes port 24731 on the host so Nginx Proxy Manager can reach it by the machine’s IP. No shared Docker network is required. The data directory can be empty; the container creates the database on first start. It has to be writable by uid 10001. Each library is mounted at the same path written in the config.

Write `/mnt/docker/vandros-gateway/config.yaml`:

```yaml
listen: ":24731"

session:
  ttl: 12h
  secure: false

database:
  path: /var/lib/vandros/portal.db

branding:
  name: Vandros Gateway

mounts:
  - id: library
    name: Library
    path: /mnt/example
```

```bash
mkdir -p /mnt/docker/vandros-gateway/data
chown 10001:10001 /mnt/docker/vandros-gateway/data

docker run --restart=unless-stopped -d \
  --name vandros \
  --read-only --tmpfs /tmp --stop-timeout 15 \
  --user 10001:10001 \
  -p 24731:24731 \
  -v /etc/localtime:/etc/localtime:ro \
  -v /mnt/docker/vandros-gateway/config.yaml:/etc/vandros/config.yaml:ro \
  -v /mnt/docker/vandros-gateway/data:/var/lib/vandros \
  -v /mnt/example:/mnt/example \
  -e TZ="Pacific/Auckland" \
  -e VANDROS_SESSION_SECRET="at least 32 characters" \
  -e VANDROS_ADMIN_USER=admin \
  -e VANDROS_ADMIN_PASSWORD="choose one for the first start" \
  ghcr.io/tyesamson/vandros-gateway:latest
```

Add one `-v` for each mount, host path and container path the same. The example is writable, so upload and delete follow the permissions in Settings. uid 10001 has to be able to write to that directory. Add `:ro` to a mount that must not change; the app cannot override a read-only mount, and then uid 10001 only needs to read it. A missing mount path stops the container from starting. Vandros Gateway leaves their ownership alone.

`--read-only` locks the container’s own filesystem. The data volume stays writable for the database. Uploads are written into the library, not into `/tmp`.

Or build locally:

```bash
docker build -t vandros-gateway .
```

Use `vandros-gateway` as the image name in the command above.

## Nginx Proxy Manager

This app should sit behind NPM. It does not terminate TLS itself.

1. DNS for the portal should point at the NPM host (`A` / `AAAA` / `CNAME`).
2. In NPM, add a **Proxy Host**:
   - Domain: the portal host
   - Scheme: `http`
   - Forward hostname / IP: this machine’s IP (on the same Docker host, `172.17.0.1` usually works)
   - Forward port: `24731`
   - Forward Hostname: on
   - SSL: request a certificate, enable **Force SSL**
3. Set `session.secure: true` in `config.yaml` and restart the container. That marks the cookies Secure, uses the `__Host-` prefix, and sends HSTS.

Leave port 24731 off any WAN / router forward; NPM already has 80 and 443. The login limiter counts the address it sees. Behind NPM that address is the proxy, so failures share one limit: 20 per 10 minutes, and 10 per username.

Changing a password or a role signs that user out.

## Settings

- **Users & Scope** — clients see only the mounts and directories you grant. Read is browse and download. Write is upload. Delete removes files. An empty directory means the whole mount. Admins can browse, upload, and delete on every mount.
- **Branding** — name, logo, favicon, colours, background image

Downloads support HTTP Range. A zip is the current folder only.

## Environment

| Variable | Purpose |
| --- | --- |
| `VANDROS_SESSION_SECRET` | Cookie signing key. Required, at least 32 characters. |
| `VANDROS_ADMIN_USER` | First admin username when the database has no users (default `admin`) |
| `VANDROS_ADMIN_PASSWORD` | First admin password when the database has no users. Ignored after that. |
| `TZ` | Container timezone |

## Run locally

```bash
export VANDROS_SESSION_SECRET='at least 32 characters'
export VANDROS_ADMIN_USER=admin
export VANDROS_ADMIN_PASSWORD='choose one'
go run . -config config.yaml
```

Open [http://127.0.0.1:24731](http://127.0.0.1:24731). Copy `config.example.yaml` to `config.yaml` and point `database.path` and each mount at directories that exist on this machine.
