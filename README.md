# OpenAudit

OpenAudit is an open-source content moderation and risk audit engine for policy-based content review, anti-spam, anti-fraud, compliance testing, and safety research.

It provides a local Go service with YAML rules, keyword/regex/domain/pinyin/homophone matching, normalization, risk scoring, API key middleware, audit logs, rule management APIs, an admin dashboard, CI checks, security scanning workflows, Docker support, and release build foundations.

## Quick start

```bash
go run ./cmd/server
```

The default server address remains `:8080`. Visit `http://localhost:8080/health` or the development admin dashboard at `http://localhost:8080/admin`.

Run with an explicit config file:

```bash
go run ./cmd/server --config ./config.example.yml
```

`OPENAUDIT_CONFIG=./config.example.yml` is also supported. The CLI flag has priority.

## Common development commands

```bash
make help
make fmt
make vet
make test
make build
make smoke
make ci
```

`make build` writes `./bin/openaudit`. `make run` runs `go run ./cmd/server`.

## Docker

Build and run with Docker:

```bash
make docker-build
make docker-run
```

Or use Compose for local development:

```bash
docker compose up --build
```

The compose file maps `8080:8080`, mounts `./data`, `./storage`, and `./config.example.yml`, and runs `/app/openaudit --config /app/config.yml`.

## Configuration and API keys

`config.example.yml` is development-safe and includes a local `dev-key`. Production deployments must provide real API keys from environment variables or secret stores, not committed files. Future production variables are documented as:

```bash
OPENAUDIT_ENV=production
OPENAUDIT_API_KEYS=replace-with-secret-values
OPENAUDIT_ADMIN_API_KEY=replace-with-admin-secret
```

See `.env.example` for development-only examples.

## Admin security warning

`/admin` is for local/development use unless protected externally. In production, do **not** expose `/admin` directly to the public internet. The planned production model is:

```text
Cloudflare Access -> Cloudflare Tunnel -> 127.0.0.1:8080 on VPS -> OpenAudit
```

Do not point an admin domain directly at the VPS origin IP with ordinary public A/AAAA records. Code-level Cloudflare Access verification is reserved for a later phase.

## Rules and imports

Only a small demo ruleset is committed under `data/`. OpenAudit also supports external imported rulesets, local external rule directories, and Sensitive-lexicon-compatible imports through `cmd/importer`.

See [IMPORTING.md](IMPORTING.md) for cloning external rules, dry-run/import commands, reload steps, and warnings about not committing large/private imported rule files.

## API documentation

See [API.md](API.md) for endpoints, API key usage, request limits, audit options, and example requests/responses.

## Deployment and security

- [DEPLOYMENT.md](DEPLOYMENT.md) documents local, Docker, Compose, systemd, VPS, Cloudflare Tunnel, backup, storage, and log-retention guidance.
- [SECURITY.md](SECURITY.md) documents vulnerability reporting, supported versions, scanner status, API key policy, and safe configuration notes.

## CI and security scanning

GitHub workflows include:

- CI: gofmt check, `go vet ./...`, `go test ./...`, `go build ./...`, and smoke test.
- Govulncheck: CLI-based reachable vulnerability scanning on push, PR, weekly schedule, and manual dispatch.
- Gosec: SARIF-producing non-blocking security scan for early development visibility.
- CodeQL: Go analysis with security and quality query suites.
- Release build: manual Linux amd64 and arm64 artifact builds.

Dependabot and GitHub secret scanning should be enabled in repository settings where available.

## Roadmap

- Phase 6: code-level production admin restrictions and Cloudflare Access verification.
- Environment-backed production API key loading and stronger admin key separation.
- Cloudflare Tunnel/VPS deployment hardening and origin exposure checks.
- Larger external ruleset import workflows without committing private/local data.
- Release packaging, checksums, and optional GitHub Release publication.
- Optional future AI/OCR/database features behind existing interfaces.

## Phase 6 production access security

OpenAudit now has explicit environment modes. `app.env` defaults to `development`; set `OPENAUDIT_ENV=production` for production and `OPENAUDIT_ENV=test` for test automation. Unknown modes fail startup. In production, management APIs must be protected by API keys unless `OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true` is deliberately set.

Production API keys should come from environment/secret configuration: `OPENAUDIT_API_KEYS` accepts comma-separated keys and `OPENAUDIT_ADMIN_API_KEY` adds one more administrative key. Development sample keys such as `dev-key` are accepted only for development or test and are rejected as production-only credentials.

The `/admin` dashboard is intended for local/private/tunnel access only. In production, direct public access is denied unless traffic arrives from configured `admin.allowed_cidrs`, Cloudflare Access header mode is enabled and headers are present, or the unsafe production override is explicitly enabled. The recommended public deployment model is a VPS origin behind Cloudflare Tunnel/Access rather than exposing `/admin` or an admin DNS record directly to the VPS origin IP.

## Phase 7 Rule Versioning

OpenAudit includes local file-backed rule change history for API-managed custom rules. Rule create, update, enable/disable, delete, and rollback operations can be recorded under `storage/rule-history/`, and import runs can record batch metadata without committing full external rulesets. Rollback is supported for API-managed custom rules under `data/custom/<rule_id>.yml` only. See [API.md](API.md) for history, diff, rollback, import batch, and change stats endpoints.

## Phase 8 external ruleset imports

OpenAudit supports committed demo rules under `data/` and operator-managed external rulesets imported into `data/imported/`. Large/private sources such as Sensitive-lexicon should be cloned into `external-rules/` and imported locally; do not commit generated private rulesets. See [IMPORTING.md](IMPORTING.md).

## Phase 9 filesystem safety

High-risk filesystem operations now use a shared `internal/safepath` abstraction. Import paths, generated reports, custom rule writes, rollback restores, rule history, import batch history, audit logs, and rule loading are constrained under validated roots with symlink rejection where relevant. Runtime directories use `0750`, and generated/runtime files use `0600`. See [SECURITY.md](SECURITY.md), [IMPORTING.md](IMPORTING.md), and [API.md](API.md).

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
