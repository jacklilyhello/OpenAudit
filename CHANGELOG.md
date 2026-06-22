# Changelog

Release-note style changes for OpenAudit. For detailed historical implementation notes, see [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md). For the project overview, see [README.md](README.md).

## v0.1.0-alpha (Unreleased)

### Added

- Open-source content audit API for text moderation and risk scoring, including normalized matching, optional explanations, batching, request limits, and health/version endpoints.
- Rule management capabilities for YAML-backed rules, including create/update/delete, enable/disable, reload, validation, history, diffs, and rollback for API-managed custom rules.
- External rule import workflow with Sensitive-lexicon-compatible imports, dry-run reports, import batch metadata, local reload hooks, and safeguards against committing large or private generated rulesets.
- Rule release workflow with draft, staged, and published rule states; simulation; pre-publish validation; monotonic release versions; snapshots; and whole-ruleset rollback.
- SQLite persistence for audit logs, rule hits, rule changes, import batches, admin operations, AI audit metadata, and internal review queue state while retaining YAML rules as the source of truth.
- Internal review queue for uncertain AI and variant findings with capped excerpts, hashes, compact metadata, operator decisions, notes, policy controls, and capped exports.
- AI review provider abstraction for optional auxiliary review using configured providers, deterministic cache keys, bounded excerpts, timeouts, retries, and review-first semantics.
- Variant detection for Traditional/Simplified Chinese, pinyin, initials, homophones, and bounded normalization-driven matches with review-first defaults for generated pinyin and homophone-only hits.
- Production hardening for environment modes, management API protection, admin exposure safeguards, production-safe logging defaults, and Cloudflare Access/Tunnel deployment guidance.
- Security scanning baseline with CI format/vet/test/build/smoke checks, blocking gosec release gate, govulncheck, CodeQL, and documented safepath/SQL invariants.
- Deterministic E2E validation through `scripts/e2e.sh` and `make e2e` for manual release validation.

### Security

- `/admin` and review/management APIs are documented as production-protected surfaces and must not be directly exposed to the public internet.
- Filesystem operations for imports, history, release state, audit logs, and generated files use root-constrained safepath handling and restrictive runtime permissions.
- SQL request values are parameterized, and dynamic export/filter choices are restricted to fixed code allowlists.
- Production API keys and provider secrets are expected to come from environment variables or secret stores and must not be committed.


## Unreleased

- Implement Phase B runtime loading for local NetEase Phase A Packs, including safe bounded Pack reads, validation, dataset/group selection, RE2-compatible activation, incompatible-rule statistics, duplicate-ID detection, atomic reload integration, and server configuration wiring.
- Document expected `netease-g79.json.gz` / `netease-x19.json.gz` filenames, RE2 partial compatibility, unsupported PCRE2 runtime mode, failure semantics, and GPL/operator distribution scope.

- Add Phase A foundation for default-disabled NetEase bundled rule conversion, deterministic internal packs, machine-readable import reports, and local validation CLI. Runtime loading and PCRE2 matching are deferred.
