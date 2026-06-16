# OpenAudit

OpenAudit is an open-source content moderation and audit engine built in Go. Phase 2 strengthens the Phase 1 MVP with richer YAML rules, validation, atomic hot reload, pinyin/homophone foundations, improved stats, a txt importer foundation, and tests.

## Quick Start

```bash
go mod tidy
go run ./cmd/server
```

The server listens on `:8080`. Open the admin dashboard at <http://localhost:8080/admin>.

## Phase 2 Features

- Extended rule metadata: `description`, `source`, `tags`, `enabled`, and `mapping`.
- Backward-compatible YAML loading for Phase 1 rules.
- Rule validation with defaults for `action`, `risk_level`, and `score`.
- Atomic rule reload: invalid new rules do not replace the active ruleset.
- Rich `/rules/stats` output for counts, categories, risk levels, actions, and sources.
- Keyword, regex, domain, pinyin, and homophone matching through matcher interfaces.
- Normalization with lowercase, full-width conversion, demo Traditional-to-Simplified mapping, whitespace handling, and conservative CJK separator removal.
- Sensitive-lexicon-compatible txt importer foundation.

## Rule Format

```yaml
id: political_001
type: keyword
category: political
risk_level: high
action: block
score: 90
description: Political sensitive keyword demo rule
source: local
tags: [political, demo]
enabled: true
keywords:
  - 法轮功
```

Supported `type` values are `keyword`, `regex`, `domain`, `pinyin`, and `homophone`. Pinyin and homophone rules use `mapping` values as additional keyword variants linked to a canonical term.

Rules with `enabled: false` are counted but not loaded into active matchers. If `enabled` is omitted, it defaults to active.

## Validation and Hot Reload

Rules require `id`, `type`, and `category`. Empty `action` defaults to `review`, empty `risk_level` defaults to `medium`, and empty `score` defaults to `high=90`, `medium=60`, or `low=30`. Invalid regex patterns return clear load errors. `POST /rules/reload` validates and compiles into a temporary ruleset first, then swaps only after success.

## APIs

```bash
curl http://localhost:8080/health
curl http://localhost:8080/rules/stats
curl -X POST http://localhost:8080/rules/reload
curl -X POST http://localhost:8080/audit/text -H 'Content-Type: application/json' -d '{"text":"这个网站 epochtimes.com 有法輪功内容","options":{"normalize":true}}'
curl -X POST http://localhost:8080/audit/batch -H 'Content-Type: application/json' -d '{"items":["第一段文本","第二段 t.me/test"],"options":{"normalize":true}}'
curl -X POST http://localhost:8080/audit/url -H 'Content-Type: application/json' -d '{"text":"https://epochtimes.com/path","options":{"normalize":true}}'
curl -X POST http://localhost:8080/audit/domain -H 'Content-Type: application/json' -d '{"text":"www.epochtimes.com","options":{"normalize":true}}'
```

## Importer Usage

```bash
go run ./cmd/importer \
  --input ./examples/sensitive-lexicon-demo \
  --output ./data/imported \
  --category political \
  --risk high \
  --action block \
  --source sensitive-lexicon
```

The importer recursively scans `.txt` files, ignores blank/comment lines, deduplicates keywords, and writes OpenAudit YAML keyword rules.

## Admin Dashboard

The dashboard displays rule totals, enabled/disabled counts, keyword/regex/domain counts, pinyin/homophone variants, category/risk/action/source stats, reload status, normalized test text, and a hits table.

## Development Roadmap

- Full Aho-Corasick keyword matcher for large dictionaries.
- URL-specific parsing and normalization pipeline.
- Rule file watcher for automatic hot reload.
- Batch performance tuning and streaming import tools.
- Optional AI moderation providers behind the checker interface.

## Phase 3 matching engine update

Phase 3 upgrades OpenAudit with an internal Unicode-aware Aho-Corasick keyword matcher, deterministic hit sorting/deduplication, stronger normalization/index mapping, normalized regex/domain matching, pinyin and homophone variant hits, and richer risk metadata.

### Positions and normalization

Audit hits use rune offsets (`start` inclusive, `end` exclusive). When text is normalized, hits are mapped back through `NormalizedText.IndexMap`; if separators or collapsed characters make the source span approximate, `position_approximate` is returned. Examples: `法-轮-功`, `法_轮_功`, `法*轮*功`, and `法 輪 功` normalize to `法轮功`; full-width domains such as `Ｔ．ＭＥ/test` normalize to `t.me/test`.

### Audit options

Request options are backward compatible and default to:

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

### Risk detail

Responses include `risk_detail` while preserving `risk_score` and `action`:

```json
{"strategy":"max","max_score":90,"hit_count":3,"block_count":1,"review_count":2}
```

### Domain, regex, pinyin, and homophone examples

Domain rules safely match `example.com`, `www.example.com`, `a.b.example.com`, `https://www.example.com/path?a=1`, `WWW.EXAMPLE.COM`, `ｗｗｗ．ｅｘａｍｐｌｅ．ｃｏｍ`, `example.com:443`, and `https://example.com:443/path`, but not `fakeexample.com`. Regex rules are precompiled on rule load and run against normalized text. Pinyin and homophone rules compile mapping variants into the same efficient matching infrastructure and return `canonical` and `variant` fields.

### Importer flags

`go run ./cmd/importer --input examples/sensitive-lexicon-demo --output data/imported --risk medium --action review --source sensitive-lexicon --max-keywords-per-file 10000 --dry-run`

Supported flags: `--input`, `--output`, `--category`, `--risk`, `--action`, `--source`, `--max-keywords-per-file`, and `--dry-run`. Without `--category`, the importer infers categories from relative directory names such as `政治 -> political`, `色情 -> porn`, `赌博 -> gambling`, `诈骗 -> scam`, `毒品 -> drugs`, `广告 -> spam`, and `网址 -> domain`.

## Phase 4: Operational local audit service

Phase 4 turns OpenAudit into an operable local service while keeping the existing audit APIs backward compatible.

### Configuration

OpenAudit uses safe defaults when no config file is provided. A documented starter file is included at `config.example.yml`.

Run with defaults:

```bash
go run ./cmd/server
```

Run with a config file:

```bash
go run ./cmd/server --config ./config.example.yml
```

`OPENAUDIT_CONFIG` is also supported. The `--config` CLI flag has priority over `OPENAUDIT_CONFIG`.

Important config areas:

- `server`: address and HTTP timeouts. The default address remains `:8080`.
- `rules`: rule data directory, default `./data`.
- `security`: API key protection for management endpoints.
- `audit_log`: JSONL audit logging and in-memory recent log retention.
- `limits`: request limits for text length, batch size, and maximum hits.

### API key protection

When `security.api_key_enabled` is `true`, protected endpoints require either:

```http
Authorization: Bearer dev-key
```

or:

```http
X-API-Key: dev-key
```

By default, `/health` is not protected. The admin page can remain accessible without a key when `allow_admin_without_key` is true, while the browser stores the API key in `localStorage` for protected API calls.

### Audit logs

When `audit_log.enabled` is true, audit requests are appended to the configured JSONL file, default `./storage/audit.log`, and the latest `audit_log.max_entries` entries are retained in memory. Runtime log files under `storage/` are ignored by git.

If `log_request_text` is false, OpenAudit stores only `text_sha256` and `text_length`. If `log_hits` is false, OpenAudit stores `hit_count` without full hit details.

Recent logs:

```bash
curl 'http://localhost:8080/logs/recent?limit=50'
curl 'http://localhost:8080/logs/recent?action=block'
curl 'http://localhost:8080/logs/recent?matched=true'
curl 'http://localhost:8080/logs/recent?category=political'
```

Log stats:

```bash
curl http://localhost:8080/logs/stats
```

### Rule browser APIs

List rules with deterministic ordering and filters:

```bash
curl 'http://localhost:8080/rules?type=keyword&category=custom&limit=50&offset=0'
```

Get a rule:

```bash
curl http://localhost:8080/rules/custom_keyword_001
```

Inspect categories and sources:

```bash
curl http://localhost:8080/rules/categories
curl http://localhost:8080/rules/sources
```

These APIs return the YAML-level rule model and do not expose compiled matcher internals.

### Custom rule management APIs

Phase 4 uses a safer single-rule-per-file strategy for API-managed custom rules. Created rules are written to:

```text
data/custom/<rule_id>.yml
```

Create a custom rule:

```bash
curl -X POST http://localhost:8080/rules/create \
  -H 'Content-Type: application/json' \
  -d '{"rule":{"id":"custom_keyword_001","type":"keyword","category":"custom","risk_level":"medium","action":"review","score":60,"enabled":true,"keywords":["测试词"]}}'
```

Update a custom rule:

```bash
curl -X PATCH http://localhost:8080/rules/update/custom_keyword_001 \
  -H 'Content-Type: application/json' \
  -d '{"patch":{"enabled":false,"score":30,"keywords":["测试词","新增词"]}}'
```

Delete a custom rule:

```bash
curl -X DELETE http://localhost:8080/rules/delete/custom_keyword_001
```

Bundled/imported rules outside `data/custom/` are read-only in Phase 4. Updating or deleting them returns: `only custom API-managed rules can be updated or deleted in Phase 4`.

### Admin dashboard

The vanilla HTML/CSS/JS dashboard at `/admin` now includes:

- service config summary
- rule browser and rule detail viewer
- custom rule creation
- custom rule enable/disable and delete actions
- recent audit logs and log stats
- API key field saved in browser `localStorage`
- improved management-operation error display
- the existing text test panel

### Request limits

Configured limits are enforced for audit requests:

- `/audit/text` rejects text longer than `limits.max_text_runes` with HTTP 413.
- `/audit/batch` rejects batches larger than `limits.max_batch_items` with HTTP 413.
- request `options.max_hits` is capped to `limits.max_hits`.

### Operational endpoints

Version metadata:

```bash
curl http://localhost:8080/version
```

Sanitized runtime config, without API keys:

```bash
curl http://localhost:8080/config
```

### Security notes

OpenAudit remains a local-first service. For shared or exposed deployments, enable API keys, keep rule directories writable only by trusted users, disable raw text logging if request content is sensitive, and place the service behind TLS or a trusted reverse proxy.

### Phase 5 roadmap

Planned Phase 5 work includes deeper AI moderation integration, OCR/image audit pipelines, database-backed audit history, richer RBAC, and multi-node operational features.
