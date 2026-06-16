# Importing Rules

OpenAudit commits only a small built-in demo ruleset under `data/` for development and tests. Production and research deployments should import or mount external rulesets separately.

## External rules strategy

Supported approaches:

- Keep approved local rules under `data/custom/`.
- Clone external rules into `external-rules/` or another path ignored by git.
- Import Sensitive-lexicon-compatible text files with `cmd/importer`.
- Reload rules through `POST /rules/reload` after import.

Do not commit large, private, licensed, or locally generated imported rules unless they are intentionally part of the public demo set.

## Sensitive-lexicon-compatible clone flow

```bash
git clone https://github.com/konsheng/Sensitive-lexicon external-rules/Sensitive-lexicon
```

## Dry run

```bash
go run ./cmd/importer \
  --input ./external-rules/Sensitive-lexicon \
  --output ./data/imported \
  --source sensitive-lexicon \
  --risk medium \
  --action review \
  --dry-run
```

## Import

```bash
go run ./cmd/importer \
  --input ./external-rules/Sensitive-lexicon \
  --output ./data/imported \
  --source sensitive-lexicon \
  --risk medium \
  --action review \
  --max-keywords-per-file 10000
```

If `--category` is omitted, the importer infers categories from directory names where possible.

## Reload rules

```bash
curl -X POST http://localhost:8080/rules/reload
```

If API key protection is enabled:

```bash
curl -X POST http://localhost:8080/rules/reload -H 'Authorization: Bearer dev-key'
```

## Storage guidance

Use `external-rules/` for clones and `data/imported/` for generated rules only when you intentionally want the service to load them. Runtime import reports can go under `storage/imports/`; generated JSON/log files there are ignored by git.

Importer filesystem paths are root-constrained. Input roots must exist, must not be symlink roots, and traversal/NUL paths are rejected. Output roots and report roots are validated before writes. Generated directories use `0750`, and generated YAML/report/history files use `0600`.

## Import Batch History

The importer can record local JSONL batch metadata without committing large external rulesets:

```bash
go run ./cmd/importer --input ./Sensitive-lexicon --output ./data/imported --record-history --history-path ./storage/rule-history/import-batches.jsonl
```

Flags:

- `--record-history` writes an import batch record.
- `--history-path` sets the JSONL file path; default is `./storage/rule-history/import-batches.jsonl`.
- `--report-dir` sets the report root; explicit `--report` paths are validated under this root.
- `--reload-url` optionally calls a reload endpoint after import, for example `http://localhost:8080/rules/reload`.
- `--api-key` sends `X-API-Key` for optional reload requests.
- `--dry-run` records status `dry_run` when history recording is enabled and does not write output files.

Generated import metadata is stored under `storage/rule-history/`. Full external rulesets should not be committed; keep generated/runtime rule files and history artifacts out of Git unless intentionally curated.

## Phase 8 external ruleset import

Clone Sensitive-lexicon outside committed rules:

```sh
git clone https://github.com/konsheng/Sensitive-lexicon ./external-rules/Sensitive-lexicon
```

Preview without writing YAML:

```sh
go run ./cmd/importer --input ./external-rules/Sensitive-lexicon --output ./data/imported --source sensitive-lexicon --type auto --risk medium --action review --dry-run --report ./storage/imports/reports/preview.json
```

Run an import, record batch history, and optionally reload a running server:

```sh
go run ./cmd/importer --input ./external-rules/Sensitive-lexicon --output ./data/imported --source sensitive-lexicon --type auto --risk medium --action review --record-history --reload-after-import --reload-url http://127.0.0.1:8080/rules/reload --api-key dev-key
```

The importer infers categories from Sensitive-lexicon-compatible directory/file names, maps common Chinese categories to safe English names, infers `keyword`, `domain`, and `regex` rules, removes duplicates by normalized line, skips comments/blanks, reports invalid regex/NUL/overlong lines, and writes deterministic files under `data/imported/<source>/<category>/<type>/`. Use `--strict` to fail on invalid lines, `--dedupe-scope batch|file`, and `--max-line-runes` to tune validation. Reports are JSON by default and batch records are JSONL. `external-rules/`, runtime reports, and private generated artifacts should not be committed.

For `/imports/preview` and `/imports/run`, an empty `input_path` uses `importer.default_input_dir`; a relative `input_path` resolves under that root; an absolute `input_path` is accepted only when it remains under that root. `output_path` follows the same policy under `importer.default_output_dir`. API callers cannot choose exact report file paths; reports are generated under `importer.report_dir` using server-generated batch names.
