# NetEase bundled rules runtime (Phase B)

Phase B makes locally supplied Phase A NetEase Pack files participate in audits and hot reloads. It remains default-disabled, local-only, and does not bundle the complete upstream G79/X19 databases.

## Pack filenames

When enabled, OpenAudit looks under `bundled_rules.data_dir` for deterministic filenames:

- `netease-g79.json.gz`
- `netease-x19.json.gz`

Reports such as `netease-g79.report.json` are conversion/audit artifacts and are not required at runtime. Runtime validates the Pack itself.

## Generate packs

```sh
go run ./cmd/bundled-rules convert \
  --dataset g79 \
  --input ./external-rules/SensitiveWords/G79SensitiveWords.json \
  --output ./data/bundled/netease-g79.json.gz \
  --report ./data/bundled/netease-g79.report.json \
  --source-repository https://github.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject \
  --source-commit <40-character-upstream-commit> \
  --source-file-path SensitiveWords/G79SensitiveWords.json \
  --timestamp 2026-01-01T00:00:00Z \
  --license GPL-3.0-only
```

For X19, use the same required flags with the X19 dataset, input, output, report, and source file path:

```sh
go run ./cmd/bundled-rules convert \
  --dataset x19 \
  --input ./external-rules/SensitiveWords/X19SensitiveWords.json \
  --output ./data/bundled/netease-x19.json.gz \
  --report ./data/bundled/netease-x19.report.json \
  --source-repository https://github.com/daijunhaoMinecraft/NeteaseSensitiveWordsProject \
  --source-commit <40-character-upstream-commit> \
  --source-file-path SensitiveWords/X19SensitiveWords.json \
  --timestamp 2026-01-01T00:00:00Z \
  --license GPL-3.0-only
```

`--timestamp` must be a canonical reproducible UTC RFC3339 value with a `Z` suffix. Replace the sample timestamp with the source snapshot timestamp used by your release process.

## Enable runtime loading

```yaml
bundled_rules:
  enabled: true
  data_dir: ./data/bundled
  netease:
    enabled: true
    mode: re2
    regex_engine: re2
    datasets:
      g79: true
      x19: false
    groups:
      shield: true
      intercept: true
      replace: false
      nickname: false
      remind: false
```

Global or provider disablement performs no Pack filesystem reads. An enabled provider with no enabled datasets loads no Pack and does not fail. An explicitly enabled dataset fails startup/reload if its Pack is missing, corrupt, oversized, invalid, or has the wrong provider/dataset.

Group activation is deployment-controlled. `replace`, `nickname`, and `remind` can be explicitly enabled even though Phase A marks those mappings disabled by default in Pack metadata.

## Matching and compatibility

RE2 remains the default runtime regex backend. In `re2` mode, RE2-compatible Pack rules in enabled datasets and groups are converted to ordinary regex rules and merged before matcher compilation. RE2-incompatible rules, including lookahead, lookbehind, and backreference patterns, are skipped and counted in runtime statistics; patterns are not rewritten.

Phase D adds optional PCRE2 support. Enable it only in a binary built with `CGO_ENABLED=1 go build -tags pcre2 ./...` and system `libpcre2-8` headers/library installed (for example Debian/Ubuntu `libpcre2-dev`). Then set:

```yaml
bundled_rules:
  netease:
    regex_engine: pcre2
```

Default builds do not import PCRE2 or require CGO, and `CGO_ENABLED=0 go build ./...` remains supported. If `regex_engine: pcre2` is requested in a default build, startup/reload fails clearly before changing active engine state. Disabled NetEase configuration does not fail merely because PCRE2 is configured. OpenAudit uses direct cgo bindings to the PCRE2 8-bit API (BSD-licensed PCRE2 project), compiles patterns during startup/reload rather than per request, frees compiled code through Go finalizers, and applies hardcoded PCRE2 match/depth limits to reduce catastrophic backtracking risk. Operators should treat PCRE2 as more expressive and potentially more expensive than RE2.

## Atomic reload and validation

Reload loads local YAML, loads and validates enabled Packs with bounded reads and safe-path checks, applies dataset/group selection, detects duplicate IDs, compiles matchers, and only then atomically replaces engine state. A failed reload leaves prior rules, matchers, matches, and bundled statistics active.

Runtime rejects traversal, symlink escape, unexpected file types, oversized compressed/decompressed data, concatenated gzip streams, invalid Pack schemas, wrong provider/dataset, duplicate IDs, and un-compilable activated regexes.

## Statistics

Rules statistics remain backward-compatible and add `bundled_rules` with provider status, selected mode, selected `regex_engine`, dataset enabled/loaded state, total examined and activated counts, configuration-disabled counts, backend-unavailable skipped counts, RE2-compatible/incompatible counts, PCRE2-compatible/incompatible counts, group counts, source commit, source input SHA-256, and license identifier. Compatibility counters cover all examined Pack rules from enabled datasets before group filtering; `configuration_disabled_rules` counts rules skipped only because their deployment group is disabled. Complete regex content and raw unsafe validation errors are not exposed.

## Distribution and license scope

Phase B does not ship complete NetEase databases, generated Packs, release archives, network synchronization, or Docker distribution changes. Operator-supplied NetEase content retains its upstream GPL-3.0 obligations. Do not claim complete NetEase semantic compatibility; Phase B is RE2 partial compatibility only.
