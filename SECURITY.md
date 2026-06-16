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
