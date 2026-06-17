# OpenAudit

OpenAudit is an open-source content moderation and risk audit engine for policy-based content review, anti-spam, anti-fraud, compliance testing, and safety research.

It provides a local Go service with YAML rules, keyword/regex/domain/pinyin/homophone matching, normalization, risk scoring, API key middleware, audit logs, auxiliary AI review providers, rule management APIs, an admin dashboard, CI checks, security scanning workflows, Docker support, and release build foundations.

OpenAudit is designed for high-performance local content auditing, with benchmark evidence for keyword, regex, domain, batch, reload, memory, and selected latency behavior. See [BENCHMARK.md](BENCHMARK.md) for reproducible reference measurements and caveats; benchmark results are not universal production guarantees.

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
* `GET /storage/ai_audit_logs?limit=50&offset=0`
* `GET /storage/import_batches?limit=50&offset=0`
* `GET /storage/rule_changes?limit=50&offset=0`
* `GET /storage/admin_operations?limit=50&offset=0`
* `GET /storage/export/audit_logs?format=json|csv&limit=1000`
* `GET /storage/export/import_batches?format=json|csv&limit=1000`
* `GET /storage/export/rule_changes?format=json|csv&limit=1000`
* `GET /storage/export/admin_operations?format=json|csv&limit=1000`

Pagination parameters are validated and capped. SQL filters use parameterized arguments, and export targets are selected from fixed route values rather than request-controlled SQL identifiers. CSV output is generated through Go's `encoding/csv` package.

Legacy JSONL files remain compatible for audit logs, rule history, and import batch history. Phase 10 mirrors new writes into SQLite where practical but does not remove JSONL files and does not move YAML rules into the database.

## Phase 14 AI review providers

AI review is an optional auxiliary layer. It is disabled by default, the deterministic rule engine runs first, and top-level audit decisions do not depend on provider success. AI metadata is returned as `ai_review` when enabled; unavailable providers, timeouts, circuit-open states, and provider errors are reported there without failing the normal audit response.

Provider adapters are modular and environment-keyed: OpenAI, DeepSeek, Qwen, Gemini, Claude, and an OpenAI-compatible local endpoint placeholder. Normal tests use fake providers and never require real API keys. Provider requests use bounded text excerpts, per-request timeouts, bounded retries, and a simple circuit breaker. AI cache keys are deterministic hashes of provider/model, prompt template version, text excerpt hash, rule context, and relevant config; raw text is not used as the key.

By default AI can recommend `review`, `allow`, `warn`, or `block_recommended`. AI hard-block behavior is intentionally not enabled by default; `ai.hard_block_enabled` must be explicitly opted into before a provider action of `block` is preserved as a hard block recommendation. Prompt/raw response logging is disabled by default, and SQLite AI audit logs store compact metadata such as provider, model, status, recommendation, token usage, estimated cost, latency, cache hit, and error class.

Scanner policy: fix real gosec findings where practical. CodeQL may still require manual review for custom safepath sanitizer flows around database/export paths; the invariant is that database paths are relative names resolved beneath a safepath-validated storage root, and SQL WHERE/ORDER fragments are assembled only from fixed code constants with request values passed as parameters. Run gosec locally with:

```sh
$(go env GOPATH)/bin/gosec ./...
```

## Phase 15 internal review queue

OpenAudit now includes an internal platform moderation review queue for uncertain AI and variant results. This is not a customer support ticket, appeal, feedback, reply, or user messaging workflow. It is a one-way operator console for platform-side review of cases the engine already detected.

The deterministic rule engine remains primary. Clear rule blocks remain blocks, clear rule allows remain allows unless review policy routes uncertain AI or variant metadata into the internal queue, and AI does not hard block by default. AI-only block output is treated as `block_recommended` unless explicit hard-block behavior is enabled outside the default review-first posture.

Default review policy:

```yaml
review_policy:
  enabled: true
  ai_review_enabled: true
  variant_review_enabled: true
  ai_score_review_threshold: 0.70
  ai_score_temporary_block_threshold: 0.90
  ai_score_log_only_below: 0.40
  variant_score_review_threshold: 0.70
  uncertain_default_action: temporary_allow
  allow_ai_hard_block: false
  retention_days: 30
  content_excerpt_max_bytes: 2048
  max_export_rows: 10000
```

Uncertain cases can be temporarily allowed, temporarily blocked, routed as review-only, or logged only. Persistent `review_cases` store capped content excerpts, content/context hashes, compact matched rule/AI/variant metadata, temporary action, status, priority, and operator decision data. Full raw content is not stored by default. Operator actions are internal-only: approve, reject, ignore, escalate, reopen, and add note. Decisions and policy changes are logged through the review event trail and `admin_operations` where available.

Review APIs are protected admin/management APIs:

* `GET /review/cases`
* `GET /review/cases/:case_id`
* `POST /review/cases/:case_id/decide`
* `POST /review/cases/:case_id/note`
* `POST /review/cases/:case_id/reopen`
* `POST /review/cases/bulk/decide`
* `GET /review/stats`
* `GET /review/policy`
* `PUT /review/policy`
* `GET /review/export`

Pagination, filters, sort fields, bulk operations, excerpts, and exports are capped or allowlisted. Review exports include only compact case fields and capped excerpts.

## Phase 11 rule release workflow

OpenAudit now supports a rule lifecycle around the existing YAML source of truth:

* `draft` rules are editable and inactive.
* `staged` rules are publish candidates and can be validated or simulated.
* `published` rules are the active live audit ruleset. Existing YAML rules default to `published`.

Draft and staged YAML plus release snapshots are stored under `data/.openaudit-release/`, which is constrained by `internal/safepath` and ignored by the live loader. Successful publishes create monotonic versions (`v1`, `v2`, ...), write release metadata, reload the active matcher, and persist release/lifecycle/validation rows into SQLite where configured. Whole-ruleset rollback restores a prior snapshot and creates a new rollback release.

Phase 11 also adds bulk enable/disable, conflict detection, staged/draft/published hit simulation, pre-publish validation, and import batch rollback when batch metadata includes generated files. See [API.md](API.md) for endpoint details.

## Phase 13 variant normalization

OpenAudit now has a formal variant layer for Traditional/Simplified Chinese, pinyin, initials, and homophone detection. The implementation uses deterministic local maps and phrase overrides inspired by OpenCC behavior, but it is not a full OpenCC dictionary clone. The local tables cover common moderation terms and can be expanded later without external services or opaque binary dictionaries.

Keyword matching indexes normalized Traditional/Simplified forms while preserving the original rule keyword in hit metadata. Opt-in keyword `variant` config can generate bounded pinyin and homophone mappings with caps such as `max_pinyin_variants` and `max_homophone_variants`. Pinyin matching normalizes tone marks, tone numbers, spaces, hyphens, dots, underscores, apostrophes, and zero-width characters before matching. Polyphonic characters use phrase-level readings first, then bounded character-level expansion; ambiguous readings are lower confidence through review-first scoring.

Generated pinyin and homophone-only matches default to `review` unless a rule explicitly configures another action. Variant hits add `variant_type`, `source_text`, `normalized_match`, `matched_rule_name`, `risk_level`, `score`, `category`, and `explanation` fields while preserving existing response fields. SQLite stores the compact hit metadata in existing `metadata_json`; no new columns are required.

Example rule:

```yaml
id: sensitive_variant_001
type: keyword
category: political
risk_level: high
action: block
keywords: [法轮功]
variant:
  enabled: true
  traditional_simplified: true
  pinyin: true
  pinyin_initials: true
  homophone: true
  min_score: 0.75
  action: review
  risk_level: medium
  initial_min_length: 3
  max_pinyin_variants: 8
  max_homophone_variants: 16
```
