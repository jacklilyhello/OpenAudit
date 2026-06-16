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

```bash
curl http://localhost:8080/logs/stats
```

Returns aggregate counts from the in-memory recent audit log window.

## Future endpoints

No AI, OCR, database, or Cloudflare Access verification endpoints are implemented in Phase 5. Those features are reserved for later phases.

## Phase 6 access control and error behavior

Protected management endpoints include `POST /rules/reload`, `POST /rules/create`, `PATCH /rules/update/:id`, `DELETE /rules/delete/:id`, `GET /logs/recent`, `GET /logs/stats`, and `GET /config`. In production these require an API key unless the unsafe production override is set. Send keys with `Authorization: Bearer <key>` or `X-API-Key: <key>`.

Common security errors:

- `401` — missing or invalid API key.
- `403` — admin access denied by CIDR/Cloudflare Access guard.
- `429` — per-client-IP in-memory rate limit exceeded. Audit, management, and admin endpoints have separate per-minute buckets.
- `413` — body or configured text/batch limits exceeded.

`/health` and `/version` remain public by default. `/audit/text`, `/audit/url`, `/audit/domain`, and `/audit/batch` remain public unless `security.protect_audit_api` is enabled.
