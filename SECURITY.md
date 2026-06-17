# Security Policy

## Reporting vulnerabilities

Please report vulnerabilities privately through the repository owner's preferred private contact channel. Do not open public issues containing exploit details, real API keys, private rulesets, audit logs, or user content.

## Supported versions

During early development, security support targets the current `main` branch. Tagged release support will be documented when stable releases begin.

## Scanning status

- CI runs formatting, vet, tests, build, and smoke checks.
- Govulncheck runs on push, pull request, weekly schedule, and manual dispatch. Failures may indicate reachable vulnerabilities and should be triaged against fixed versions.
- Gosec runs in non-blocking `-no-fail` mode and uploads SARIF so findings stay visible without blocking Phase 5 development. Remove `-no-fail` later to make it blocking.
- CodeQL analyzes Go with security and quality query suites.
- Dependabot should be enabled in repository settings for dependency update PRs.
- Secret scanning should be enabled in repository settings where available.

Run local gosec with:

```bash
$(go env GOPATH)/bin/gosec ./...
```

Some CodeQL path-flow findings may require manual review because OpenAudit uses a project-level root-constrained path abstraction. A filesystem sink is considered safe only when it receives a path produced by `internal/safepath.Root` after validation that rejects NUL bytes, parent traversal for user-controlled paths, absolute escapes, and symlink roots where relevant, and constrains the path under a configured root using `filepath.Clean`, `filepath.Abs`, and `filepath.Rel`. Runtime directories use `0750` and generated files use `0600`.

## API key policy

Development may use `dev-key` in examples. Production API keys must come from environment variables or secret stores and must never be committed. Future production variables include `OPENAUDIT_ENV=production`, `OPENAUDIT_API_KEYS`, and `OPENAUDIT_ADMIN_API_KEY`.

## Admin production warning

`/admin` must not be publicly exposed in production. Protect it with Cloudflare Access in front of Cloudflare Tunnel, and avoid direct public DNS records pointing to the origin VPS. Code-level Access verification is planned for a later phase.

## Scope

OpenAudit is a policy-based content review and risk audit engine for lawful moderation, anti-spam, anti-fraud, compliance testing, and safety research. Security support covers the OpenAudit codebase and documented deployment guidance, not third-party rule content.

## Safe configuration notes

Use least-privilege filesystem permissions, store logs in protected locations, avoid logging sensitive request text when not needed, rotate audit logs, and keep private or large rulesets outside git.

## Filesystem path safety baseline

OpenAudit centralizes high-risk filesystem operations in `internal/safepath`. The abstraction stores validated absolute roots and paths with unexported fields, rejects NUL bytes, rejects parent traversal for API/CLI paths, rejects absolute paths outside the configured root, rejects symlink roots by default, and uses `filepath.Rel` for containment checks instead of string prefix checks.

Runtime directories created by OpenAudit use `0750`. Generated/runtime files, including JSONL history, import batch files, audit logs, generated rules, imported rules, reports, and atomic temp files, use `0600`. Full Sensitive-lexicon content and other large/private external rulesets must not be committed.

## Phase 6 production security controls

Production startup safety checks reject unsafe combinations by default: invalid `app.env`, wildcard production CORS, missing non-development API keys when API key auth is enabled, disabled management API protection, and unguarded admin exposure fail startup. `OPENAUDIT_ALLOW_UNSAFE_PRODUCTION=true` exists only as an emergency/development escape hatch and should not be used for internet-facing deployments.

API keys are normalized by trimming whitespace, empty values are ignored, and presented keys are compared using constant-time comparison. Raw keys are not returned by `/config`; only configuration state is exposed.

`/admin` is protected by a code-level guard. Production deployments should use Cloudflare Access at the edge or narrow trusted tunnel/private CIDRs. Cloudflare Access JWT cryptographic verification is not implemented in Phase 6; when `verify_jwt=false`, OpenAudit checks Access identity headers only as defense in depth and relies on Cloudflare Access policy enforcement at the edge. If `verify_jwt=true`, startup fails rather than accepting unverified JWTs.

## Rule History Security

Rule history and rollback endpoints are protected management APIs in production. History entries must not contain API keys, secrets, or authorization headers; OpenAudit records actor metadata, remote address, user agent, rule YAML, diffs, and reload status only. API keys must not be logged. Rollback can restore API-managed custom rules and should be limited to trusted operators. Cloudflare Access/admin protection guidance remains applicable; when the Cloudflare Access email header is present it is used as the rule-change actor.

## External ruleset import security

The importer validates local paths through `internal/safepath`, rejects NUL/empty/traversal paths, prevents generated output from escaping the configured output directory, rejects symlink roots and symlink traversal, and uses restricted directory/file permissions. API import paths are constrained under configured importer roots; API reports are generated by the server under the configured report root using server-generated names. External rules are trusted operator input: review sources before import, use dry-run reports, and enable `--strict` for CI. Regex rules can be malicious or expensive; invalid regex is reported and skipped unless strict mode fails the import. Import APIs are protected management APIs and remote clone support remains disabled by default.

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

## Phase 11 rule release security

Rule release files are identified by rule IDs and release versions, not caller-supplied paths. Drafts, staged rules, release metadata, and snapshots live under `data/.openaudit-release/` and are accessed through `internal/safepath`; traversal, NUL bytes, absolute escapes, and symlink escapes are rejected by the shared path model. The live loader skips hidden directories so staged rules and snapshots cannot become active accidentally.

Publish validates the candidate ruleset before modifying active YAML. Failed validation does not mutate active rules. Publish writes snapshots and active custom rules with atomic file writes where practical, then reloads the matcher. Whole-ruleset rollback validates the target snapshot before activation and records a new release. Import batch rollback only removes generated YAML files listed in stored batch metadata; batches without sufficient metadata are rejected.

Simulation caps sample text at 10000 runes and does not persist the sample by default. SQLite lifecycle, release, release item, and validation writes use parameterized SQL only. Scanner policy for Phase 11 remains: fix real issues, document precise safepath/SQL invariants for custom sanitizer false positives, and do not weaken the architecture for scanner-only zero findings.

## Phase 13 variant detection safety

Traditional/Simplified conversion, pinyin normalization, initials, polyphonic readings, and homophone detection are deterministic local features. Phase 13 does not accept dictionary paths from API requests and does not load remote rule data. The current compatibility approach uses small documented Go maps and phrase overrides inspired by OpenCC behavior; it is intentionally not a full OpenCC clone.

False-positive controls are built into rule validation and matcher generation. Keyword rules must opt into generated pinyin or homophone variants with `variant.enabled`; generated pinyin, initials, and homophone-only matches default to `review` unless the rule explicitly configures another action. `min_score`, `min_length`, `initial_min_length`, `max_pinyin_variants`, and `max_homophone_variants` are validated and capped. Pinyin input normalization handles tone marks, tone numbers, repeated separators, apostrophes, dots, underscores, hyphens, and zero-width characters before matching.

Resource safety invariant: variant expansion is bounded per rule and uses phrase-level pinyin mappings before character-level polyphonic expansion. Homophone variants come from compact local groups or authored YAML mapping rules. SQLite stores compact hit metadata through existing `metadata_json` fields with parameterized SQL; no new request-controlled SQL or filesystem sink is introduced.

Scanner policy remains: fix real findings, document custom sanitizer invariants, and do not damage the architecture for CodeQL zero findings. Expected manual-review invariant for variant code is that runtime variant data is compiled into the binary or authored as normal safepath-loaded YAML rules under the rule root; API requests can enable/disable pinyin and homophone matching but cannot select filesystem dictionary paths.
