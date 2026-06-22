# Bundled rules Phase A

Phase A adds a local-only foundation for future bundled providers. It does not load or activate bundled packs at runtime, does not add PCRE2 native dependencies, and does not bundle the complete NetEase databases or generated packs.

## Configuration

All providers and datasets are disabled by default:

```yaml
bundled_rules:
  enabled: false
  data_dir: ./data/bundled
  netease:
    enabled: false
    mode: re2
    datasets:
      g79: false
      x19: false
    groups:
      shield: true
      intercept: true
      replace: false
      nickname: false
      remind: false
```

`re2` uses Go `regexp` for partial compatibility analysis. `pcre2` is a reserved configuration value for a later optional matcher; Phase A records `not_checked` for PCRE2 and does not enforce PCRE2 availability.

## Local conversion

Use local upstream JSON files only; the CLI performs no network requests:

```bash
go run ./cmd/bundled-rules convert \
  --input ./SensitiveWords/G79SensitiveWords.json \
  --output ./data/bundled/netease-g79.json.gz \
  --dataset g79 \
  --source-repository https://github.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject \
  --source-commit <40-char-sha> \
  --source-file-path SensitiveWords/G79SensitiveWords.json \
  --timestamp 2026-01-01T00:00:00Z

go run ./cmd/bundled-rules validate --input ./data/bundled/netease-g79.json.gz
```

The converter validates before atomic replacement, emits a concise summary, and preserves previous output on failure.

## Pack and report format

Packs contain provenance (`source_repository`, pinned `source_commit`, `source_file_path`, source input SHA-256), deterministic timestamp, generator identity, counts, and rules. Rule entries preserve generated ID, provider, dataset, canonical group, upstream ID, original regex, OpenAudit moderation mapping, tags, metadata, RE2 status/error, and PCRE2 status/error.

The external import report contains the generated pack SHA-256, source and output sizes, counts by dataset and all five groups, unknown groups, duplicate identities, duplicate regex content, and compatibility failures identified by rule ID and pattern SHA-256 rather than full regex text.

## Group mappings

* `shield` -> `block`, `netease_shield`, enabled by default.
* `intercept` -> `block`, `netease_intercept`, enabled by default.
* `replace` -> `review`, `netease_replace`, disabled by default.
* `nickname` -> `review`, `nickname`, disabled by default.
* `remind` -> `review`, `netease_remind`, disabled by default.

`replace` and `remind` are OpenAudit moderation mappings and do not fully emulate upstream replacement or reminder behavior. Replacement text is not invented.

## Reproducibility and safety

Generation uses stable ordering, deterministic JSON, fixed gzip compression and header timestamp, no wall-clock timestamps in pack bytes, and `SOURCE_DATE_EPOCH` or an explicit timestamp for provenance. The pack does not contain its own output SHA-256; the report carries the pack SHA-256.

Conservative limits cover input JSON bytes, compressed and uncompressed pack bytes, rule count, pattern bytes, and metadata bytes. Gzip validation uses limited readers, rejects truncated gzip, rejects unsupported schema versions, and avoids unbounded decompression.

## Future runtime position contract

OpenAudit currently exposes rune-based match positions mapped through the normalization index map. A future PCRE2 integration may return UTF-8 byte offsets internally, but it must convert those offsets through the existing normalization and rune-position pipeline. Phase A adds no ambiguous runtime byte-position behavior.
