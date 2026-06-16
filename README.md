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
