# OpenAudit

OpenAudit is an open-source content moderation and audit engine built in Go. Phase 1 provides a runnable MVP with YAML rules, text and batch audit APIs, risk scoring, hot reload, and a static admin dashboard.

## Quick Start

```bash
go mod tidy
go run ./cmd/server
```

The server listens on `:8080`.

Open the admin dashboard at <http://localhost:8080/admin>.

## APIs

### Health

```bash
curl http://localhost:8080/health
```

### Audit Text

```bash
curl -X POST http://localhost:8080/audit/text \
  -H 'Content-Type: application/json' \
  -d '{"text":"这个网站 kkkkk.com 有法輪功内容","options":{"normalize":true}}'
```

### Batch Audit

```bash
curl -X POST http://localhost:8080/audit/batch \
  -H 'Content-Type: application/json' \
  -d '{"items":["第一段文本","第二段 t.me/test"],"options":{"normalize":true}}'
```

### Rule Stats

```bash
curl http://localhost:8080/rules/stats
```

### Reload Rules

```bash
curl -X POST http://localhost:8080/rules/reload
```

## Rules

Rules are stored under `data/` as YAML files. Phase 1 supports keyword, regex, and domain rules. Regex patterns are precompiled when rules load. Domain rules match exact hosts and subdomain suffixes, so `example.com`, `www.example.com`, and `a.b.example.com` match while `fakeexample.com` does not.

## Normalization

The MVP normalizer lowercases text, converts full-width ASCII to half-width, applies a small Traditional Chinese to Simplified Chinese demo map, and removes common interference symbols such as `-`, `_`, `*`, and spaces.
