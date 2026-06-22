# Bundled rules Phase A

Phase A adds a local-only foundation for future bundled providers. It does not load or activate bundled packs at runtime, does not add PCRE2 native dependencies, and does not bundle complete NetEase databases or generated packs.

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

`re2` uses Go `regexp` for partial compatibility analysis. `pcre2` is reserved for a later optional matcher; Phase A records `not_checked` and does not enforce PCRE2 availability.

## Local conversion

Use local upstream JSON files only; the CLI performs no network requests. Non-dry-run conversion requires both a pack path and a report path:

```bash
go run ./cmd/bundled-rules convert \
  --input ./SensitiveWords/G79SensitiveWords.json \
  --output ./data/bundled/netease-g79.json.gz \
  --report ./data/bundled/netease-g79.report.json \
  --dataset g79 \
  --source-repository https://github.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject \
  --source-commit <40-char-sha> \
  --source-file-path SensitiveWords/G79SensitiveWords.json \
  --timestamp 2026-01-01T00:00:00Z \
  --license GPL-3.0-only

go run ./cmd/bundled-rules validate \
  --input ./data/bundled/netease-g79.json.gz \
  --report ./data/bundled/netease-g79.report.json
```

`--dry-run` writes neither pack nor report. It prints only a concise human summary unless `--json` is supplied, in which case the machine-readable report JSON is printed to stdout. Non-dry-run conversion validates the generated pack and report before replacement and uses a rollback-capable two-output commit helper. The pack and report paths must be different and must share the same parent directory; staged temporary files are validated before replacement, previous targets are backed up, and handled failures attempt to restore both previous files. Failed backup restoration preserves the backup for manual recovery and returned errors identify retained pack/report backup paths. Temporary files and safely disposable backups are cleaned; backups that could not be restored or removed are preserved. If both new files install successfully but old backup cleanup fails, the new consistent pair remains active and the stale backup cleanup error is reported. This is not advertised as crash-proof multi-file filesystem transactionality. After backup and replacement renames, the parent directory is synced where the platform supports directory sync; unsupported directory sync results such as EINVAL/ENOTSUP are tolerated without claiming stronger durability than the filesystem provides.

## Strict parsing policy

The upstream JSON is treated as untrusted data. The parser requires one complete JSON document, rejects trailing objects/tokens/non-whitespace data, requires `regex` to be an object, and uses structured JSON decoding. Duplicate top-level keys, case-insensitive duplicate group names such as `Shield` and `shield`, and duplicate upstream IDs inside a group are rejected as malformed input with the duplicate path in the error. Duplicate regex content under different upstream IDs remains valid and is reported separately.

Empty records are `null`, an empty string, or a whitespace-only string. Malformed records are non-string values such as numbers, booleans, arrays, or objects; reports include dataset, group, upstream ID, value type, and reason, but never complete sensitive regex content. Unknown groups are reported with group name and record count. Total source records include recognized imported, empty, malformed, and unknown records.

## Pack validation, report verification, and limits

`ValidatePack` is the central validation gate for generated and decoded packs. It checks schema version, provider, dataset, source repository, 40-character source commit SHA, safe source file path, 64-character source input SHA-256, license, generator fields, rule count, per-rule provider/dataset/group/type/ID uniqueness, pattern size, metadata size, PCRE2 status, RE2 error consistency, centralized group mapping consistency, and recomputed counts by dataset/group/status.

The declared limits are enforced during conversion and validation: input JSON bytes, compressed pack bytes, uncompressed pack bytes, report bytes, rule count, pattern bytes, and metadata bytes. CLI validation also uses bounded reads for pack and report files. Metadata size is the serialized size of rule metadata, tags, description, category, and source. Defaults are sized for the current upstream files while staying conservative: 4 MiB input JSON, 4 MiB compressed pack, 16 MiB uncompressed pack, 20,000 rules, 256 KiB pattern bytes, and 64 KiB metadata bytes.

Reports carry the generated pack SHA-256 and pack size. `validate --report` verifies the pack hash, pack size, provider, dataset, provenance, and counts against the pack.

## Pack and report format

Packs contain provenance (`source_repository`, pinned `source_commit`, `source_file_path`, source input SHA-256), deterministic timestamp, generator identity, counts, and rules. Rule entries preserve generated ID, provider, dataset, canonical group, upstream ID, original regex, OpenAudit moderation mapping, tags, metadata, RE2 status/error, and PCRE2 status/error.

The external import report contains the generated pack SHA-256, source and output sizes, counts by dataset and all five groups, unknown groups with record counts, empty, malformed, and unknown counts, duplicate identities, duplicate regex content, and compatibility failures identified by rule ID and pattern SHA-256 rather than full regex text.

## Group mappings

* `shield` -> `block`, `netease_shield`, enabled by default.
* `intercept` -> `block`, `netease_intercept`, enabled by default.
* `replace` -> `review`, `netease_replace`, disabled by default.
* `nickname` -> `review`, `nickname`, disabled by default.
* `remind` -> `review`, `netease_remind`, disabled by default.

`replace` and `remind` are OpenAudit moderation mappings and do not fully emulate upstream replacement or reminder behavior. Replacement text is not invented.

## Reproducibility and gzip policy

Generation uses stable ordering, deterministic JSON, fixed gzip compression and header timestamp, no wall-clock timestamps in pack bytes, and either an explicit timestamp or `SOURCE_DATE_EPOCH`; pack timestamps are serialized and validated as canonical UTC RFC3339 with a `Z` suffix. Invalid `SOURCE_DATE_EPOCH` is an error. Different explicit timestamps intentionally change provenance bytes. The pack does not contain its own output SHA-256; the report carries the pack SHA-256.

Phase A accepts exactly one complete gzip member. Concatenated gzip streams, arbitrary trailing bytes, truncated gzip data, CRC errors, oversized compressed input, and oversized decompressed output are rejected.

## Future runtime position contract

OpenAudit currently exposes rune-based match positions mapped through the normalization index map. A future PCRE2 integration may return UTF-8 byte offsets internally, but it must convert those offsets through the existing normalization and rune-position pipeline. Phase A adds no ambiguous runtime byte-position behavior.
