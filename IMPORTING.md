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

## Phase 10 SQLite persistence

OpenAudit now starts with a local SQLite persistence backend by default. The backend is intended for long-term, pageable local query storage while keeping YAML rule files as the rule source of truth. PostgreSQL is intentionally deferred to a later phase; Phase 10 only adds the storage boundary needed for future backends.

Default configuration:

```yaml
storage:
  backend: sqlite
  root: ./storage
  sqlite_path: data/openaudit.db
  legacy_jsonl_fallback: true
  auto_migrate: true
```

The database path is resolved under `storage.root` through the Phase 9 safepath helpers. Runtime directories are created with `0750` permissions and the database file is chmodded to `0600` where the platform allows it. In production, SQLite initialization or migration failures stop startup. In development, `legacy_jsonl_fallback: true` allows the existing JSONL audit and history files to continue operating if SQLite cannot be opened.

SQLite migrations create `schema_migrations`, `audit_logs`, `rule_hits`, `rule_changes`, `import_batches`, and `admin_operations`. Migrations run in deterministic order inside a transaction and are safe to repeat.

Queryable storage endpoints include:

* `GET /storage/audit_logs?limit=50&offset=0`
* `GET /storage/import_batches?limit=50&offset=0`
* `GET /storage/rule_changes?limit=50&offset=0`
* `GET /storage/admin_operations?limit=50&offset=0`
* `GET /storage/export/audit_logs?format=json|csv&limit=1000`
* `GET /storage/export/import_batches?format=json|csv&limit=1000`
* `GET /storage/export/rule_changes?format=json|csv&limit=1000`
* `GET /storage/export/admin_operations?format=json|csv&limit=1000`

Pagination parameters are validated and capped. SQL filters use parameterized arguments, and export targets are selected from fixed route values rather than request-controlled SQL identifiers. CSV output is generated through Go's `encoding/csv` package.

Legacy JSONL files remain compatible for audit logs, rule history, and import batch history. Phase 10 mirrors new writes into SQLite where practical but does not remove JSONL files and does not move YAML rules into the database.

Scanner policy: fix real gosec findings where practical. CodeQL may still require manual review for custom safepath sanitizer flows around database/export paths; the invariant is that database paths are relative names resolved beneath a safepath-validated storage root, and SQL WHERE/ORDER fragments are assembled only from fixed code constants with request values passed as parameters. Run gosec locally with:

```sh
$(go env GOPATH)/bin/gosec ./...
```

## Phase 11 import batch rollback

`POST /imports/batches/:batch_id/rollback` can remove imported YAML files only when the recorded batch metadata includes generated file paths. The rollback path is safepath-constrained under the rule data root and refuses non-YAML targets. Older batches without generated file metadata return a clear rollback-unavailable error; OpenAudit does not guess which rules to delete and does not remove unrelated files.

For safer release operations, import into draft/staged workflows where practical, run `POST /rules/prepublish-test`, then publish staged rules to create a ruleset version. Whole-ruleset rollback remains available through release snapshots even when an import batch itself cannot be exactly rolled back.
