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

OpenAudit-created runtime directories use `0750`, and generated/runtime files use `0600`. This applies to audit logs, rule history JSONL files, import batch files, generated/imported rules, import reports, and atomic temp files. Symlink roots for high-risk import and runtime write paths are rejected.

## Backup and retention

Back up `data/` if it contains local rule edits and `storage/` if audit history matters. JSONL logs can grow over time; configure OS log rotation or application retention policies. Do not back up or publish secrets in config snapshots.

## Phase 6 recommended production model

Run OpenAudit on a VPS with `OPENAUDIT_ENV=production`, real API keys in environment variables, and a Cloudflare Tunnel or tightly controlled reverse proxy in front of the service. Do not expose `/admin` directly to the public internet, and do not point an admin DNS name directly at the VPS origin IP. Put Cloudflare Access in front of the admin route and keep origin firewall rules restrictive.

Example systemd environment:

```ini
Environment=OPENAUDIT_ENV=production
Environment=OPENAUDIT_CONFIG=/etc/openaudit/config.yml
Environment=OPENAUDIT_API_KEYS=replace-with-secret-1,replace-with-secret-2
Environment=OPENAUDIT_ADMIN_API_KEY=replace-with-admin-secret
Environment=OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=false
```

Configure `server.trusted_proxies` for the local reverse proxy or tunnel source addresses only. OpenAudit trusts `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` only when the TCP peer is in trusted proxy CIDRs; spoofed forwarded headers from public clients are ignored.

## Rule History Operations

Back up `storage/rule-history/` with the rule data directory. Custom-rule rollback depends on the stored history entries and previous YAML snapshots embedded in those entries. Plan retention for `history.jsonl`, `import-batches.jsonl`, and snapshot files according to operational and compliance needs; losing these files does not stop the engine, but it removes rollback/change-audit context.

## Imported rules operations

Back up `data/imported/`, `storage/imports/`, and `storage/rule-history/import-batches.jsonl` with other operational state. Keep `external-rules/` operator-managed and out of git; it may contain large or private upstream rulesets.

For local scanner review, run `$(go env GOPATH)/bin/gosec ./...`. CodeQL may still require manual review for path-flow findings that pass through `internal/safepath`; review those against the documented root-constrained path invariant instead of relying on scanner output alone.

## Phase 10 SQLite persistence

OpenAudit now starts with a local SQLite persistence backend by default. The backend is intended for long-term, pageable local query storage while keeping YAML rule files as the rule source of truth. PostgreSQL is intentionally deferred to a later phase; Phase 10 only adds the storage boundary needed for future backends.

Default configuration:

```yaml
storage:
  backend: sqlite
  root: ./storage
  sqlite_path: data/openaudit.db
  legacy_jsonl_fallback: true
  auto_migrate: true
```

The database path is resolved under `storage.root` through the Phase 9 safepath helpers. Runtime directories are created with `0750` permissions and the database file is chmodded to `0600` where the platform allows it. In production, SQLite initialization or migration failures stop startup. In development, `legacy_jsonl_fallback: true` allows the existing JSONL audit and history files to continue operating if SQLite cannot be opened.

SQLite migrations create `schema_migrations`, `audit_logs`, `rule_hits`, `rule_changes`, `import_batches`, and `admin_operations`. Migrations run in deterministic order inside a transaction and are safe to repeat.

Queryable storage endpoints include:

* `GET /storage/audit_logs?limit=50&offset=0`
* `GET /storage/import_batches?limit=50&offset=0`
* `GET /storage/rule_changes?limit=50&offset=0`
* `GET /storage/admin_operations?limit=50&offset=0`
* `GET /storage/export/audit_logs?format=json|csv&limit=1000`
* `GET /storage/export/import_batches?format=json|csv&limit=1000`
* `GET /storage/export/rule_changes?format=json|csv&limit=1000`
* `GET /storage/export/admin_operations?format=json|csv&limit=1000`

Pagination parameters are validated and capped. SQL filters use parameterized arguments, and export targets are selected from fixed route values rather than request-controlled SQL identifiers. CSV output is generated through Go's `encoding/csv` package.

Legacy JSONL files remain compatible for audit logs, rule history, and import batch history. Phase 10 mirrors new writes into SQLite where practical but does not remove JSONL files and does not move YAML rules into the database.

Scanner policy: fix real gosec findings where practical. CodeQL may still require manual review for custom safepath sanitizer flows around database/export paths; the invariant is that database paths are relative names resolved beneath a safepath-validated storage root, and SQL WHERE/ORDER fragments are assembled only from fixed code constants with request values passed as parameters. Run gosec locally with:

```sh
$(go env GOPATH)/bin/gosec ./...
```

## Phase 11 release state operations

Back up `data/` and `storage/` together. Phase 11 stores draft/staged rule YAML, ruleset snapshots, and JSON release metadata under `data/.openaudit-release/`; SQLite mirrors lifecycle, release, validation, and admin metadata when the SQLite backend is available. Losing the hidden release directory does not stop live audits, but it removes ruleset rollback targets and draft/staged work.

Before production publishes, use `POST /rules/prepublish-test` and `POST /rules/simulate` against staged rules. Use `GET /rules/releases` to verify version records after publish. Whole-ruleset rollback should be treated as an administrative operation and performed only from trusted admin networks or Cloudflare Access-protected sessions.

## Phase 13 variant operations

Variant detection is local and deterministic. Traditional/Simplified conversion uses compact phrase and character maps; pinyin and homophone support uses bounded local tables plus authored YAML mapping rules. No external service, remote dictionary, PostgreSQL, MySQL, Redis, AI, OCR, or benchmark service is required.

For production rules, enable pinyin and homophone variants gradually and prefer `variant.action: review`. Use `POST /rules/simulate` and `POST /rules/prepublish-test` before publish; simulation responses include variant type, score, risk level, category, and explanation fields. Expansion caps are validated by rule loading, and generated pinyin/homophone-only matches are review-first by default.

Local scanner validation remains:

```sh
go fmt ./...
go test ./...
go vet ./...
$(go env GOPATH)/bin/gosec ./...
```

CodeQL may require manual review for custom safepath and variant-sanitizer flows. The variant invariant is that runtime variant data is compiled in or loaded as ordinary YAML rules through the existing safepath-constrained rule root; API requests cannot choose dictionary files.

## Phase 15 review queue operations

The internal review queue uses the SQLite backend when available. Back up `storage/data/openaudit.db` with other operational state if review cases, operator decisions, review policy versions, and admin operation logs matter for auditability. The queue is not a customer support system and should not be connected to user messaging, appeals, replies, or feedback flows.

Production deployments should treat `/review/*` the same way as `/admin`: keep it behind private networks, Cloudflare Tunnel/Access, or a trusted reverse proxy, and require production API key protection for management APIs. Do not expose review queue routes directly to the public internet.

Review policy controls uncertain AI and variant routing:

```yaml
review_policy:
  uncertain_default_action: temporary_allow
  allow_ai_hard_block: false
  content_excerpt_max_bytes: 2048
  retention_days: 30
  max_export_rows: 10000
```

The queue stores capped content excerpts, hashes, compact metadata, temporary action, status, priority, and operator notes. Full raw content is not stored by default. If audit logs are configured to store request text, treat those logs as more sensitive than review cases and protect backups accordingly.

Use `GET /review/stats` for operational monitoring and `GET /review/export?format=csv|json` for capped exports. Bulk decisions are limited and transactional; failed validation leaves cases unchanged. Retention cleanup can use `expires_at` and the `expired` status in future maintenance jobs.

Local scanner validation remains:

```sh
go fmt ./...
go test ./...
go vet ./...
$(go env GOPATH)/bin/gosec ./...
```

CodeQL zero findings are not required for this phase. Review SQL scanner findings against the invariant that filters and sort fields are allowlisted and request values are passed as SQL parameters; review filesystem findings against the existing safepath storage-root invariant.
