# OpenAudit Development Log

This file preserves useful phase-by-phase implementation history that previously lived in the README. For the concise product entrypoint, see [README.md](README.md).

## Phase 6 production access security

OpenAudit has explicit environment modes. `app.env` defaults to `development`; set `OPENAUDIT_ENV=production` for production and `OPENAUDIT_ENV=test` for test automation. Unknown modes fail startup. In production, management APIs must be protected by API keys unless `OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true` is deliberately set.

Production API keys should come from environment or secret configuration. `OPENAUDIT_API_KEYS` accepts comma-separated keys, and `OPENAUDIT_ADMIN_API_KEY` adds one more administrative key. Development sample keys such as `dev-key` are accepted only for development or test and are rejected as production-only credentials.

The `/admin` dashboard is intended for local, private, or tunnel access only. In production, direct public access is denied unless traffic arrives from configured `admin.allowed_cidrs`, Cloudflare Access header mode is enabled and headers are present, or the unsafe production override is explicitly enabled. The recommended production model is a VPS origin behind Cloudflare Tunnel and Cloudflare Access rather than exposing `/admin` or an admin DNS record directly to the VPS origin IP.

## Phase 7 rule versioning and history

OpenAudit includes local file-backed rule change history for API-managed custom rules. Rule create, update, enable/disable, delete, and rollback operations can be recorded under `storage/rule-history/`, and import runs can record batch metadata without committing full external rulesets.

Rollback is supported for API-managed custom rules under `data/custom/<rule_id>.yml` only. History, diff, rollback, import batch, and change stats endpoints are documented in [API.md](API.md).

## Phase 8 external ruleset imports

OpenAudit supports committed demo rules under `data/` and operator-managed external rulesets imported into `data/imported/`. Large or private sources such as Sensitive-lexicon should be cloned into `external-rules/` and imported locally; generated private rulesets should not be committed.

The importer supports dry runs, generated reports, Sensitive-lexicon-compatible text imports, optional history recording, and reload hooks. See [IMPORTING.md](IMPORTING.md) for import workflows and safety guidance.

## Phase 9 filesystem safety

High-risk filesystem operations use the shared `internal/safepath` abstraction. Import paths, generated reports, custom rule writes, rollback restores, rule history, import batch history, audit logs, and rule loading are constrained under validated roots with symlink rejection where relevant.

Runtime directories use `0750`, and generated/runtime files use `0600`. These safepath constraints remain part of the security baseline and are documented further in [SECURITY.md](SECURITY.md), [IMPORTING.md](IMPORTING.md), and [API.md](API.md).

## Phase 10 SQLite persistence

OpenAudit starts with a local SQLite persistence backend by default. The backend is intended for long-term, pageable local query storage while keeping YAML rule files as the rule source of truth. PostgreSQL was intentionally deferred; this phase added the storage boundary needed for future backends.

Default configuration:

```yaml
storage:
  backend: sqlite
  root: ./storage
  sqlite_path: data/openaudit.db
  legacy_jsonl_fallback: true
  auto_migrate: true
```

The database path is resolved under `storage.root` through safepath helpers. Runtime directories are created with `0750` permissions, and the database file is chmodded to `0600` where the platform allows it. In production, SQLite initialization or migration failures stop startup. In development, `legacy_jsonl_fallback: true` allows existing JSONL audit and history files to continue operating if SQLite cannot be opened.

SQLite migrations create `schema_migrations`, `audit_logs`, `rule_hits`, `rule_changes`, `import_batches`, and `admin_operations`. Migrations run in deterministic order inside a transaction and are safe to repeat. Queryable storage and export endpoints are documented in [API.md](API.md). Pagination parameters are validated and capped; SQL filters use parameterized arguments; export targets are selected from fixed route values rather than request-controlled SQL identifiers.

Legacy JSONL files remain compatible for audit logs, rule history, and import batch history. New writes are mirrored into SQLite where practical, but YAML rules remain file-backed.

## Phase 11 rule release workflow

OpenAudit supports a rule lifecycle around the existing YAML source of truth:

- `draft` rules are editable and inactive.
- `staged` rules are publish candidates and can be validated or simulated.
- `published` rules are the active live audit ruleset. Existing YAML rules default to `published`.

Draft and staged YAML plus release snapshots are stored under `data/.openaudit-release/`, which is constrained by `internal/safepath` and ignored by the live loader. Successful publishes create monotonic versions (`v1`, `v2`, ...), write release metadata, reload the active matcher, and persist release, lifecycle, validation, and admin rows into SQLite where configured. Whole-ruleset rollback restores a prior snapshot and creates a new rollback release.

This phase also added bulk enable/disable, conflict detection, staged/draft/published hit simulation, pre-publish validation, and import batch rollback when batch metadata includes generated files. See [API.md](API.md) for endpoint details.

## Phase 13 variant normalization

OpenAudit has a formal variant layer for Traditional/Simplified Chinese, pinyin, initials, and homophone detection. The implementation uses deterministic local maps and phrase overrides inspired by OpenCC behavior, but it is not a full OpenCC dictionary clone. The local tables cover common moderation terms and can be expanded later without external services or opaque binary dictionaries.

Keyword matching indexes normalized Traditional/Simplified forms while preserving the original rule keyword in hit metadata. Opt-in keyword `variant` config can generate bounded pinyin and homophone mappings with caps such as `max_pinyin_variants` and `max_homophone_variants`. Pinyin matching normalizes tone marks, tone numbers, spaces, hyphens, dots, underscores, apostrophes, and zero-width characters before matching.

Generated pinyin and homophone-only matches default to `review` unless a rule explicitly configures another action. Variant hits add compact metadata such as `variant_type`, `source_text`, `normalized_match`, `matched_rule_name`, `risk_level`, `score`, `category`, and `explanation` while preserving existing response fields. SQLite stores compact hit metadata in existing `metadata_json`; no new columns are required.

## Phase 14 AI review providers

AI review is an optional auxiliary layer. It is disabled by default, the deterministic rule engine runs first, and top-level audit decisions do not depend on provider success. AI metadata is returned as `ai_review` when enabled; unavailable providers, timeouts, circuit-open states, and provider errors are reported there without failing the normal audit response.

Provider adapters are modular and environment-keyed: OpenAI, DeepSeek, Qwen, Gemini, Claude, and an OpenAI-compatible local endpoint placeholder. Normal tests use fake providers and never require real API keys. Provider requests use bounded text excerpts, per-request timeouts, bounded retries, and a simple circuit breaker. AI cache keys are deterministic hashes of provider/model, prompt template version, text excerpt hash, rule context, and relevant config; raw text is not used as the key.

AI can recommend `review`, `allow`, `warn`, or `block_recommended`. AI hard-block behavior is intentionally not enabled by default; `ai.hard_block_enabled` must be explicitly opted into before a provider action of `block` is preserved as a hard block recommendation. Prompt/raw response logging is disabled by default, and SQLite AI audit logs store compact metadata such as provider, model, status, recommendation, token usage, estimated cost, latency, cache hit, and error class.

## Phase 15 internal review queue

OpenAudit includes an internal platform moderation review queue for uncertain AI and variant results. This is not a customer support ticket, appeal, feedback, reply, or user messaging workflow. It is a one-way operator console for platform-side review of cases the engine already detected.

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

Persistent `review_cases` store capped content excerpts, content/context hashes, compact matched rule/AI/variant metadata, temporary action, status, priority, and operator decision data. Full raw content is not stored by default. Operator actions include approve, reject, ignore, escalate, reopen, and add note. Decisions and policy changes are logged through the review event trail and `admin_operations` where available.

Review APIs are protected admin/management APIs. Pagination, filters, sort fields, bulk operations, excerpts, and exports are capped or allowlisted, and exports include only compact case fields and capped excerpts.

## Phase 16 release hardening

Phase 16 hardened release validation and production examples:

- The Go toolchain was aligned to Go 1.25.11.
- Gosec was made a blocking release-baseline security gate.
- Production deployment examples were added, including production Compose, production config, systemd, and Cloudflare Access/Tunnel guidance.
- Production-safe logging defaults were added so raw request text and AI prompt/raw provider response logging are not enabled by default.
- Deterministic E2E verification was added with `scripts/e2e.sh` and `make e2e`.

Scanner policy remains that real gosec findings should be fixed where practical. False positives should be handled only with narrow, local documentation of the exact invariant, and broad `#nosec` suppressions should be avoided. CodeQL may still require manual review for custom safepath sanitizer flows around database/export paths. The SQL invariant is that SQL fragments come from fixed code allowlists and request values are passed as parameters.
