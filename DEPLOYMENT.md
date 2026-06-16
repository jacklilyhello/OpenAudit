# OpenAudit Deployment

## Local `go run`

```bash
go run ./cmd/server
# or
go run ./cmd/server --config ./config.example.yml
```

The default address is `:8080`.

## Docker

```bash
docker build -t openaudit:local .
docker run --rm -p 8080:8080 \
  -v "$PWD/data:/app/data" \
  -v "$PWD/storage:/app/storage" \
  -v "$PWD/config.example.yml:/app/config.yml:ro" \
  openaudit:local --config /app/config.yml
```

## Docker Compose

`docker-compose.yml` is for local/development use:

```bash
docker compose up --build
```

It mounts rules from `./data`, runtime storage from `./storage`, and config from `./config.example.yml`.

## systemd outline

Build `/opt/openaudit/openaudit`, store config at `/etc/openaudit/config.yml`, and run as an unprivileged user. Bind to `127.0.0.1:8080` or a private reverse-proxy listener for production.

```ini
[Service]
User=openaudit
WorkingDirectory=/opt/openaudit
Environment=OPENAUDIT_ENV=production
ExecStart=/opt/openaudit/openaudit --config /etc/openaudit/config.yml
Restart=on-failure
```

## Future Cloudflare Tunnel production model

Production admin access must not be public. Recommended flow:

```text
User -> Cloudflare Access -> Cloudflare Tunnel -> 127.0.0.1:8080 on VPS -> OpenAudit
```

Do not expose `/admin` directly to the public internet. Do not point the admin domain directly to the VPS origin IP with normal public A/AAAA records. Phase 5 documents this requirement; code-level Cloudflare Access verification is reserved for Phase 6.

## Production API key strategy

Use environment variables or secrets for real keys. Never commit production keys.

- `OPENAUDIT_ENV=production`
- `OPENAUDIT_API_KEYS`
- `OPENAUDIT_ADMIN_API_KEY`

A development key may exist in `config.example.yml`; production must not rely on it.

## Data, config, and storage

Mount or persist:

- `data/` for committed demo and approved local rule files.
- external rules directories such as `external-rules/` outside git.
- `storage/` for audit logs and runtime state.
- config files from `/etc/openaudit` or secret-managed locations.

## Backup and retention

Back up `data/` if it contains local rule edits and `storage/` if audit history matters. JSONL logs can grow over time; configure OS log rotation or application retention policies. Do not back up or publish secrets in config snapshots.
