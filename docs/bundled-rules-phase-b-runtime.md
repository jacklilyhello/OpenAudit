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
  --source-repo https://github.com/netease-im/NIM_iOS_UIKit \
  --source-commit <40-character-upstream-commit>
```

Repeat with `--dataset x19` and `--output ./data/bundled/netease-x19.json.gz` for X19.

## Enable runtime loading

```yaml
bundled_rules:
  enabled: true
  data_dir: ./data/bundled
  netease:
    enabled: true
    mode: re2
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

Phase B supports Go RE2-compatible regex matching only. In `re2` mode, RE2-compatible Pack rules in enabled datasets and groups are converted to ordinary regex rules and merged before matcher compilation. RE2-incompatible rules, including lookahead, lookbehind, and backreference patterns, are skipped and counted in runtime statistics; patterns are not rewritten.

`mode: pcre2` returns a clear unsupported-mode error when NetEase is effectively enabled. Disabled NetEase configuration does not fail merely because `mode` is `pcre2`. Phase B adds no CGO or PCRE2 dependency and preserves `CGO_ENABLED=0` builds.

## Atomic reload and validation

Reload loads local YAML, loads and validates enabled Packs with bounded reads and safe-path checks, applies dataset/group selection, detects duplicate IDs, compiles matchers, and only then atomically replaces engine state. A failed reload leaves prior rules, matchers, matches, and bundled statistics active.

Runtime rejects traversal, symlink escape, unexpected file types, oversized compressed/decompressed data, concatenated gzip streams, invalid Pack schemas, wrong provider/dataset, duplicate IDs, and un-compilable activated regexes.

## Statistics

Rules statistics remain backward-compatible and add `bundled_rules` with provider status, selected mode, dataset enabled/loaded state, examined and activated rule counts, configuration-disabled counts, RE2-compatible/incompatible counts, group counts, source commit, source input SHA-256, and license identifier. Complete regex content and raw unsafe validation errors are not exposed.

## Distribution and license scope

Phase B does not ship complete NetEase databases, generated Packs, release archives, network synchronization, or Docker distribution changes. Operator-supplied NetEase content retains its upstream GPL-3.0 obligations. Do not claim complete NetEase semantic compatibility; Phase B is RE2 partial compatibility only.
