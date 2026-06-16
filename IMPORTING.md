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
