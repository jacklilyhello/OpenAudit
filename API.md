# OpenAudit API

Base URL for local development: `http://localhost:8080`.

## API keys

When configured, protected endpoints accept either:

```http
Authorization: Bearer dev-key
X-API-Key: dev-key
```

`/health` is normally public. Rule management and log endpoints may be protected by config.

## Error format

```json
{"error":{"code":"invalid_request","message":"text is required"}}
```

## Request limits

Defaults are configured in `config.example.yml`: maximum text runes, batch items, and returned hits. Oversized requests return `413` with `request_too_large`.

## Audit options

```json
{
  "normalize": true,
  "pinyin": true,
  "homophone": true,
  "ai": false,
  "include_explanations": true,
  "include_normalized_text": true,
  "include_positions": true,
  "max_hits": 100
}
```

## Endpoints

### GET `/health`

```bash
curl http://localhost:8080/health
```

```json
{"service":"OpenAudit","status":"ok"}
```

### GET `/version`

```bash
curl http://localhost:8080/version
```

```json
{"service":"OpenAudit","version":"dev","commit":"unknown","build_time":"unknown"}
```

### GET `/config`

Returns sanitized runtime configuration. Secret API key values are not exposed.

```bash
curl http://localhost:8080/config
```

### POST `/audit/text`

```bash
curl -X POST http://localhost:8080/audit/text \
  -H 'Content-Type: application/json' \
  -d '{"text":"demo epochtimes.com 法輪功","options":{"normalize":true,"max_hits":10}}'
```

Response includes `matched`, `risk_score`, `action`, `hits`, and optional normalized text/risk detail fields.

When `ai.enabled: true` or request option `"ai": true` is used with a configured provider, responses may include additive `ai_review` metadata. The deterministic rule engine still runs first and remains authoritative: AI failures do not fail the audit request, and AI-only block decisions are reported as `block_recommended` by default rather than changing the top-level `action`.

```json
{
  "matched": true,
  "action": "block",
  "risk_score": 100,
  "hits": [],
  "ai_review": {
    "enabled": true,
    "provider": "openai",
    "model": "gpt-4o-mini",
    "status": "success",
    "action": "review",
    "confidence": 0.82,
    "risk_level": "high",
    "category": "policy",
    "explanation": "Supplementary semantic review recommends operator review.",
    "reasons": ["context requires human review"],
    "cache_hit": false,
    "latency_ms": 350,
    "token_usage": {"prompt_tokens": 120, "completion_tokens": 50, "total_tokens": 170},
    "estimated_cost": 0.0
  }
}
```

AI statuses include `success`, `cached`, `skipped`, `timeout`, `error`, and `circuit_open`.

Variant-capable hits preserve the existing fields and may include additional metadata:

```json
{
  "type": "pinyin",
  "variant_type": "pinyin",
  "rule_id": "sensitive_variant_001",
  "matched_rule_name": "Variant rule",
  "category": "political",
  "risk_level": "medium",
  "action": "review",
  "match": "falungong",
  "normalized_match": "falungong",
  "source_text": "法轮功",
  "canonical": "法轮功",
  "variant": "falungong",
  "start": 0,
  "end": 11,
  "position_approximate": true,
  "score": 75,
  "explanation": "Pinyin variant matched \"falungong\" for canonical text \"法轮功\"; tone and separator differences are normalized. Risk is medium and action is review to control false positives."
}
```

Generated pinyin, initials, and homophone-only matches are intended for review-first workflows and default to `review` when enabled through keyword `variant` config. Exact keyword, regex, and domain rules keep their authored action.

When review policy creates or logs an internal case, audit responses may include additive review fields without removing existing fields:

```json
{
  "review_status": "pending",
  "review_case_id": "rc_...",
  "temporary_action": "temporary_allow",
  "review_reason": "ai_score_above_review_threshold",
  "review_priority": "medium",
  "review_policy_version": "phase15-review-policy-v1"
}
```

`temporary_action` can be `temporary_allow`, `temporary_block`, `review_only`, `log_only`, or `none`. `log_only` adds review metadata without creating a queue row. AI and variant review routing is internal platform moderation only; there are no public ticket, appeal, feedback, reply, or customer messaging APIs.

### POST `/audit/batch`

```bash
curl -X POST http://localhost:8080/audit/batch \
  -H 'Content-Type: application/json' \
  -d '{"items":["first text","second text"],"options":{"normalize":true}}'
```

```json
{"results":[{"matched":false,"hits":[]}]}
```

### POST `/audit/url`

Uses the same request and response shape as `/audit/text`, intended for URL inputs.

```bash
curl -X POST http://localhost:8080/audit/url -H 'Content-Type: application/json' -d '{"text":"https://example.com/path"}'
```

### POST `/audit/domain`

Uses the same request and response shape as `/audit/text`, intended for domain inputs.

```bash
curl -X POST http://localhost:8080/audit/domain -H 'Content-Type: application/json' -d '{"text":"www.example.com"}'
```

### GET `/rules/stats`

```bash
curl http://localhost:8080/rules/stats
```

Returns counts by rule type, category, risk level, action, and source.

### POST `/rules/reload`

Atomically reloads rules. Invalid new rules do not replace the active ruleset.

```bash
curl -X POST http://localhost:8080/rules/reload -H 'Authorization: Bearer dev-key'
```

### GET `/rules`

List rules with filters: `type`, `category`, `risk_level`, `action`, `source`, `enabled`, `q`, `limit`, `offset`.

```bash
curl 'http://localhost:8080/rules?type=keyword&limit=50&offset=0'
```

Rule-level variant config is optional. Missing config preserves existing rule behavior. Invalid actions, risk levels, score ranges, and expansion caps are rejected by rule validation and pre-publish validation.

```json
{
  "id": "sensitive_variant_001",
  "type": "keyword",
  "category": "political",
  "risk_level": "high",
  "action": "block",
  "keywords": ["法轮功"],
  "variant": {
    "enabled": true,
    "traditional_simplified": true,
    "pinyin": true,
    "pinyin_initials": true,
    "homophone": true,
    "min_score": 0.75,
    "action": "review",
    "risk_level": "medium",
    "initial_min_length": 3,
    "max_pinyin_variants": 8,
    "max_homophone_variants": 16
  }
}
```

### GET `/rules/:id`

```bash
curl http://localhost:8080/rules/political_keyword_demo
```

Returns `404` if missing.

### POST `/rules/create`

Creates an API-managed custom YAML rule under `data/custom/` and reloads rules.

```bash
curl -X POST http://localhost:8080/rules/create \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-key' \
  -d '{"rule":{"id":"custom_keyword_001","type":"keyword","category":"custom","risk_level":"medium","action":"review","score":60,"keywords":["demo"]}}'
```

### PATCH `/rules/update/:id`

Updates API-managed custom rules only.

```bash
curl -X PATCH http://localhost:8080/rules/update/custom_keyword_001 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-key' \
  -d '{"patch":{"enabled":false}}'
```

### DELETE `/rules/delete/:id`

Deletes API-managed custom rules only.

```bash
curl -X DELETE http://localhost:8080/rules/delete/custom_keyword_001 -H 'Authorization: Bearer dev-key'
```

### GET `/logs/recent`

Filters include `limit`, `action`, `matched`, `category`, and `q`.

```bash
curl 'http://localhost:8080/logs/recent?limit=50&matched=true'
```

### GET `/logs/stats`

### Review Queue APIs

Review queue APIs are protected internal admin/management endpoints. They expose capped content excerpts and compact metadata only.

#### GET `/review/cases`

Filters: `status`, `priority`, `category`, `source`, `temporary_action`, `ai_risk_level`, `variant_risk_level`, `min_score`, `max_score`, `created_from`, `created_to`, `limit`, `offset`.

Sort allowlist: `created_at`, `updated_at`, `priority`, `ai_score`, `variant_score`, `status`.

```bash
curl 'http://localhost:8080/review/cases?status=pending&sort=created_at&limit=50' \
  -H 'Authorization: Bearer dev-key'
```

#### GET `/review/cases/:case_id`

Returns the review case plus internal event history.

#### POST `/review/cases/:case_id/decide`

Allowed actions: `approve`, `reject`, `ignore`, `escalate`, `reopen`, `add_note`.

```bash
curl -X POST http://localhost:8080/review/cases/rc_example/decide \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-key' \
  -d '{"action":"approve","note":"Internal review completed."}'
```

`POST /review/cases/:case_id/note`, `POST /review/cases/:case_id/reopen`, and `POST /review/cases/:case_id/escalate` are convenience endpoints for internal notes, reopening, and escalation.

#### POST `/review/cases/bulk/decide`

Bulk decisions are capped at 100 case IDs and validate all IDs before committing.

```bash
curl -X POST http://localhost:8080/review/cases/bulk/decide \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-key' \
  -d '{"case_ids":["rc_a","rc_b"],"action":"ignore","note":"No action needed."}'
```

#### GET `/review/stats`

Returns pending cases, critical pending, temporary blocked, temporary allowed, reviewed today, average pending age, and total cases.

#### GET `/review/policy`

Returns the active review policy and persisted version when available.

#### PUT `/review/policy`

Updates review policy thresholds and temporary action behavior. Thresholds must be between 0 and 1, and the temporary block threshold must be greater than or equal to the review threshold.

#### GET `/review/export`

Exports review cases as `json` or `csv`. Export rows are capped by policy and storage limits.

```bash
curl http://localhost:8080/logs/stats
```

Returns aggregate counts from the in-memory recent audit log window.

## AI review providers

AI review is disabled by default. Provider credentials are read only from configured environment variable names and are not exposed by `/config`. Normal tests use fake providers and do not require real API keys.

Supported provider adapters:

* `openai` uses OpenAI-compatible chat completions.
* `deepseek` uses DeepSeek's OpenAI-compatible chat completions.
* `qwen` uses Alibaba Cloud Model Studio's OpenAI-compatible Qwen interface.
* `gemini` uses Google Gemini `generateContent`.
* `claude` uses Anthropic Messages.
* `local` is an OpenAI-compatible local endpoint placeholder, defaulting to `http://127.0.0.1:11434/v1`.

Relevant config:

```yaml
ai:
  enabled: false
  default_action: review
  hard_block_enabled: false
  provider: openai
  timeout_ms: 8000
  max_retries: 2
  retry_backoff_ms: 250
  circuit_breaker_failure_threshold: 5
  circuit_breaker_cooldown_ms: 30000
  max_excerpt_runes: 2000
  cache:
    enabled: true
    ttl_seconds: 3600
  cost_tracking:
    enabled: true
  audit_logs:
    enabled: true
    store_prompts: false
    store_raw_response: false
```

Prompt templates are configured as static config strings under `ai.prompt`; API requests cannot select arbitrary prompt template files. Cache keys are SHA-256 hashes over provider, model, template version/hash, text excerpt hash, rule-hit context, and relevant AI config. Full prompt/raw provider response logging is off by default.

## Phase 6 access control and error behavior

Protected management endpoints include `POST /rules/reload`, `POST /rules/create`, `PATCH /rules/update/:id`, `DELETE /rules/delete/:id`, `GET /logs/recent`, `GET /logs/stats`, and `GET /config`. In production these require an API key unless the unsafe production override is set. Send keys with `Authorization: Bearer <key>` or `X-API-Key: <key>`.

Common security errors:

- `401` — missing or invalid API key.
- `403` — admin access denied by CIDR/Cloudflare Access guard.
- `429` — per-client-IP in-memory rate limit exceeded. Audit, management, and admin endpoints have separate per-minute buckets.
- `413` — body or configured text/batch limits exceeded.

`/health` and `/version` remain public by default. `/audit/text`, `/audit/url`, `/audit/domain`, and `/audit/batch` remain public unless `security.protect_audit_api` is enabled.

## Rule History and Versioning APIs

In production, these are protected management APIs and require the configured API key.

### `GET /rules/history`

Query: `rule_id`, `action`, `actor`, `source`, `import_batch_id`, `limit`, `offset`.

Response:

```json
{"items": [], "count": 0, "limit": 50, "offset": 0}
```

### `GET /rules/history/:change_id`

Returns one change entry including `before`, `after`, `diff`, reload status, actor, remote address, and user agent.

### `GET /rules/:id/history`

Returns history filtered to one rule.

### `GET /rules/:id/diff`

Optional query: `from_change_id`, `to_change_id`. Without IDs, returns the latest stored diff for the rule.

### `POST /rules/rollback/:id`

Request:

```json
{"change_id":"change_...","note":"rollback bad rule update"}
```

Restores the selected entry's previous rule YAML, reloads rules atomically, and writes a new `rollback` history entry. Phase 7 rollback is supported only for API-managed custom rules under `data/custom/`; other rules return `rollback is only supported for API-managed custom rules in Phase 7`.

### `GET /imports/batches`

Query: `source`, `status`, `limit`, `offset`. Lists import batch records from `storage/rule-history/import-batches.jsonl`.

### `GET /imports/batches/:batch_id`

Returns one import batch record.

### `GET /rules/changes/stats`

Returns aggregate rule change counts by action, actor, and source plus recent changes.

## External import APIs

Management endpoints are protected by the API-key middleware in production:

* `POST /imports/preview` previews an import and returns `{ "ok": true, "preview": {...} }` without writing rule YAML.
* `POST /imports/run` writes imported rules, writes a report, optionally records history/reloads, and returns `{ "ok": true, "batch_id": "...", "report": {...}, "reload": {...} }`.

Request fields include `input_path`, `output_path`, `source`, `type` (`auto`, `keyword`, `domain`, `regex`), `category`, `risk_level`, `action`, `strict`, `max_keywords_per_file`, plus `reload_after_import` and `record_history` for run. Unsafe empty/NUL/escaping paths and invalid strict imports return `400` with `ok:false`.

Import path policy:

- Empty `input_path` uses `importer.default_input_dir`.
- Relative `input_path` resolves under `importer.default_input_dir`.
- Absolute `input_path` is accepted only when it remains under `importer.default_input_dir`.
- Empty, relative, and absolute `output_path` follow the same policy under `importer.default_output_dir`.
- Symlink roots and symlink files/directories during traversal are rejected.
- API callers cannot choose exact report file paths; `/imports/run` writes reports under `importer.report_dir` with server-generated batch file names.

Custom rule, rollback, history, audit log, import batch, generated rule, and report files are written through the root-constrained safepath layer. Runtime directories use `0750`; generated/runtime files use `0600`.

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

Scanner policy: gosec is a SARIF-producing blocking Phase 16 release-baseline security gate. Fix real gosec findings where practical. False positives should be handled only with narrow, local documentation of the exact invariant; broad suppressions should be avoided. CodeQL may still require manual review for custom safepath sanitizer flows around database/export paths; the invariant is that database paths are relative names resolved beneath a safepath-validated storage root, and SQL WHERE/ORDER fragments are assembled only from fixed code constants with request values passed as parameters. Run gosec locally with:

```sh
$(go env GOPATH)/bin/gosec ./...
```

## Phase 11 rule release workflow

Phase 11 keeps YAML rule files as the source of truth and adds lifecycle metadata around them. Existing loaded YAML rules are treated as `published`. Draft and staged rule YAML is stored under the hidden safepath-constrained release root `data/.openaudit-release/`, which is ignored by the live rule loader. Successful publishes create monotonic versions such as `v1`, `v2`, and write snapshots under `data/.openaudit-release/snapshots/<version>/`.

Management endpoints are protected like the existing rule APIs in production.

### Lifecycle

* `GET /rules/drafts`
* `POST /rules/drafts`
* `PUT /rules/drafts/:id`
* `DELETE /rules/drafts/:id`
* `POST /rules/drafts/:id/stage`
* `GET /rules/staged`

Draft create/update request:

```json
{"rule":{"id":"candidate_001","type":"keyword","category":"custom","risk_level":"medium","action":"review","keywords":["candidate"]}}
```

Drafts and staged rules do not affect live audits until published.

### Pre-publish and publish

* `POST /rules/prepublish-test`
* `POST /rules/publish`
* `POST /rules/staged/:id/publish`

Optional request:

```json
{"sample_text":"text to simulate before publish"}
```

Pre-publish validation loads the candidate ruleset, compiles regex rules, runs conflict detection, and optionally runs sample simulation. Critical conflicts block publish and failed validation does not mutate active rules.

### Release versions

* `GET /rules/releases?limit=50&offset=0`
* `GET /rules/releases/:version`
* `GET /rules/releases/:from/:to/diff`
* `POST /rules/releases/:version/rollback`

Rollback validates the target snapshot, replaces the active YAML ruleset from that snapshot, reloads rules, and records a new release with status `rollback`.

### Bulk operations

* `POST /rules/bulk/enable`
* `POST /rules/bulk/disable`

Request:

```json
{"ids":["custom_keyword_001"],"category":"custom","severity":"medium","state":"published"}
```

`state` defaults to `published`. Explicit IDs are validated before writes. Published bulk changes reload the live matcher; draft/staged changes remain inactive until publish.

### Conflict detection

`POST /rules/conflicts?scope=published`

Returns structured conflicts with `type`, `severity`, `affected_rule_ids`, `message`, and `suggested_action`. Detection includes duplicate IDs, duplicate keyword/domain/regex patterns, invalid regex, and draft/staged/published version drift for the same rule ID.

### Hit simulation

`POST /rules/simulate`

```json
{"text":"candidate text","scope":"staged","rule_ids":["candidate_001"],"max_hits":20}
```

Scopes: `published`, `staged`, `draft`, or `version` with `version:"v1"`. Sample text is not persisted by default and is capped to 10000 runes. The response includes matched rule IDs, hit positions, matched text, normalized match data, and decision summary.

### Import batch rollback

`POST /imports/batches/:batch_id/rollback`

Rollback is available only when the stored batch metadata contains generated rule file paths. The endpoint removes only those safepath-validated YAML files, reloads rules, and records history/admin metadata. Older or incomplete batches return a clear `rollback unavailable` error instead of guessing.

### Phase 11 SQLite tables

The Phase 11 migration adds:

* `rule_lifecycle`
* `rule_releases`
* `rule_release_items`
* `rule_validation_runs`

All SQL writes use parameters. Query pagination is capped through the shared storage limits.
