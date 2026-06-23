OpenAudit

OpenAudit is an open source content moderation and audit engine.

The goal of this project is to build a high performance, extensible content moderation system inspired by large-scale internet audit systems.

OpenAudit is NOT a simple sensitive-word API.

OpenAudit is a complete audit engine.

⸻

Core Features

Current and future features include:

* Keyword matching
* Regex matching
* Domain matching
* URL matching
* Simplified / Traditional Chinese conversion
* Lowercase normalization
* Full-width / Half-width normalization
* Symbol and whitespace interference removal
* Unicode homoglyph normalization
* Pinyin matching
* Homophone matching
* Risk scoring
* Batch audit
* Rule hot reload
* Admin dashboard
* AI moderation
* OCR moderation
* Image moderation

⸻

Tech Stack

Backend:

* Go
* Gin

Rule format:

* YAML (preferred)
* JSON (optional)

Frontend:

* HTML
* CSS
* Vanilla JavaScript

Storage:

* Local rule files
* No database in MVP

⸻

Rule Source

The project should be compatible with:

https://github.com/konsheng/Sensitive-lexicon

The directory structure and categories should be compatible whenever possible.

⸻

Project Philosophy

This project is:

* Fast
* Extensible
* Maintainable
* Transparent
* API-first

Avoid:

* Hardcoded rules
* Monolithic files
* Global mutable state
* Complex dependencies

⸻

Project Structure

OpenAudit/

cmd/

internal/

web/

data/

README.md

CODEX.md

⸻

Matching Pipeline

Input

↓

Normalizer

↓

Keyword Matcher

↓

Regex Matcher

↓

Domain Matcher

↓

Pinyin Matcher

↓

Homophone Matcher

↓

AI Checker

↓

Risk Scoring

↓

Response

⸻

Keyword Matching

Use:

Aho-Corasick

Requirements:

* High performance
* Multiple pattern matching
* Unicode support
* Return matched text and positions

⸻

Regex Matching

Use:

Go regexp

Requirements:

* Precompile all regex at startup
* Return matched text and positions
* Support hot reload

⸻

Domain Matching

Support:

example.com

www.example.com

a.b.example.com

Should NOT match:

fakeexample.com

Support:

* exact match
* suffix match

⸻

Normalization

Must support:

Simplified / Traditional Chinese

Example:

法輪功

↓

法轮功

⸻

Lowercase

Example:

ABC.COM

↓

abc.com

⸻

Full-width / Half-width

Example:

ａｂｃ．ｃｏｍ

↓

abc.com

⸻

Symbol interference

Example:

法-轮-功

法_轮_功

法轮功

↓

法轮功

⸻

Unicode homoglyph

Example:

аbc.com

↓

abc.com

Ｇoogle

↓

google

⸻

Risk Scoring

Risk levels:

high

medium

low

Default scores:

high = 90

medium = 60

low = 30

Action priority:

block

review

pass

⸻

API Design

Required APIs:

GET

/health

POST

/audit/text

POST

/audit/batch

POST

/audit/url

POST

/audit/domain

GET

/rules/stats

POST

/rules/reload

GET

/admin

⸻

Admin Dashboard

The admin page should provide:

* Service status
* Rule statistics
* Text testing
* Batch testing
* Risk score
* Match result display
* Rule reload button
* API health

No authentication in MVP.

⸻

AI Moderation

AI moderation must be abstracted.

Provide interface:

Checker

Do NOT tightly couple any provider.

Potential providers:

* OpenAI
* DeepSeek
* Gemini
* Qwen
* Claude

⸻

Development Rules

IMPORTANT:

Always read CODEX.md before starting work.

NEVER modify existing Development Log entries.

NEVER delete Development Log entries.

After finishing ANY task:

Append a new Development Log section.

Unless explicitly requested:

Do NOT rewrite history.

Only append.

⸻

Development Log

This section is append-only.

Never edit previous entries.

Append new entries only.


## Commit pending

Date: 2026-06-16

Summary:
- Created the Phase 1 MVP Go project foundation with health, audit, batch, rule stats, reload, and admin dashboard endpoints.
- Added YAML rule loading, normalization, keyword matching, regex precompilation, domain suffix matching, risk scoring, and action priority handling.
- Added sample rules, README quick start instructions, and API examples.

Files:
- cmd/server/main.go
- internal/api/health.go
- internal/api/audit.go
- internal/api/batch.go
- internal/api/rules.go
- internal/admin/admin.go
- internal/engine/engine.go
- internal/engine/result.go
- internal/matcher/keyword.go
- internal/matcher/regex.go
- internal/matcher/domain.go
- internal/normalizer/normalizer.go
- internal/rules/loader.go
- internal/rules/model.go
- internal/rules/hotreload.go
- internal/risk/score.go
- internal/ai/checker.go
- internal/model/api.go
- data/keywords/test.yml
- data/regex/test.yml
- data/domains/test.yml
- web/admin/index.html
- web/admin/app.js
- web/admin/style.css
- README.md
- CODEX.md

Notes:
- Phase 1 uses local YAML files only and includes a lightweight Gin-compatible local module for this MVP environment.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 2 rule model enhancement
- Add safer atomic rule hot reload
- Add Sensitive-lexicon-compatible txt importer foundation
- Add pinyin and homophone mapping support
- Improve normalization and stats
- Add tests

Files:
- internal/rules/...
- internal/importer/...
- internal/matcher/...
- internal/normalizer/...
- internal/api/...
- web/admin/...
- README.md
- CODEX.md

Notes:
- Append-only log entry for Phase 2.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 3 high-performance matching foundation
- Add real Aho-Corasick keyword matcher
- Improve normalized-to-original position mapping
- Strengthen regex and domain matching
- Improve pinyin/homophone variant hits
- Add deterministic hit sorting and deduplication
- Add risk_detail response metadata
- Enhance Sensitive-lexicon-compatible importer
- Improve admin dashboard and tests

Files:
- internal/matcher/...
- internal/normalizer/...
- internal/engine/...
- internal/risk/...
- internal/importer/...
- internal/api/...
- web/admin/...
- README.md
- CODEX.md

Notes:
- Append-only log entry for Phase 3.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 4 operational management layer
- Add configuration system
- Add local audit logging and log APIs
- Add rule inspection APIs
- Add API-managed custom rule create/update/delete
- Add API key middleware and request limits
- Improve admin dashboard for rule and log management
- Add version/config endpoints
- Add tests and documentation

Files:
- internal/config/...
- internal/logstore/...
- internal/security/...
- internal/api/...
- internal/admin/...
- internal/rules/...
- web/admin/...
- config.example.yml
- storage/.gitkeep
- README.md
- CODEX.md

Notes:
- Append-only log entry for Phase 4.
- Existing Phase 1/2/3 APIs remain backward compatible.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 5 engineering and deployment foundation
- Stabilize CI/security scanning workflows
- Add Makefile
- Add Dockerfile and docker-compose.yml
- Add release artifact workflow
- Add smoke test script
- Add deployment, security, API, and import documentation
- Update README with neutral project description and production admin warnings
- Preserve future Cloudflare Access, API key, VPS tunnel, and external ruleset requirements

Files:
- .github/workflows/...
- Makefile
- Dockerfile
- .dockerignore
- docker-compose.yml
- scripts/smoke.sh
- DEPLOYMENT.md
- SECURITY.md
- IMPORTING.md
- API.md
- README.md
- .env.example
- .gitignore
- CODEX.md

Notes:
- Append-only log entry for Phase 5.
- Production Cloudflare Access enforcement is documented in Phase 5 and reserved for implementation in Phase 6.
- Existing Phase 1/2/3/4 APIs remain backward compatible.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 6 production access security controls
- Add environment mode support
- Enforce production API key safety
- Add admin access guard for local/private/Cloudflare Access header mode
- Add trusted proxy client IP extraction
- Harden management API protection
- Add security headers, CORS controls, rate limiting, and request body limits
- Update config examples, environment examples, docs, and tests

Files:
- internal/config/...
- internal/security/...
- internal/api/...
- internal/admin/...
- internal/logstore/...
- config.example.yml
- .env.example
- README.md
- SECURITY.md
- DEPLOYMENT.md
- API.md
- CODEX.md

Notes:
- Append-only log entry for Phase 6.
- Cloudflare Access JWT cryptographic verification is explicitly marked as not implemented.
- Existing Phase 1/2/3/4/5 APIs remain backward compatible.
- Production /admin must not be exposed directly to the public internet.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 7 rule versioning and rollback foundation
- Add rule history store and change records
- Add rule diff support
- Integrate history with custom rule create/update/delete
- Add rollback API for API-managed custom rules
- Add import batch tracking
- Add rule history and import batch APIs
- Improve admin dashboard with rule history, diffs, import batches, and rollback UI
- Update config, documentation, and tests

Files:
- internal/rulehistory/...
- internal/api/...
- internal/rules/...
- internal/importer/...
- web/admin/...
- config.example.yml
- README.md
- API.md
- IMPORTING.md
- DEPLOYMENT.md
- SECURITY.md
- CODEX.md
- storage/rule-history/.gitkeep
- .gitignore

Notes:
- Append-only log entry for Phase 7.
- Rule rollback is supported for API-managed custom rules only in Phase 7.
- No SQLite/database migration is introduced in this phase.
- Existing Phase 1/2/3/4/5/6 APIs remain backward compatible.

## Commit pending

Date: 2026-06-16

Summary:
- Implement Phase 8 external ruleset import system
- Add deep Sensitive-lexicon-compatible category and type inference
- Add import preview and report generation
- Add duplicate and invalid line handling
- Add safe deterministic imported rule output layout
- Add optional reload-after-import integration
- Add import batch reporting integration
- Add import APIs and admin UI support if implemented
- Update importing, API, deployment, security, and README documentation
- Add tests for importer mapping, preview, reports, output, and safety

Files:
- internal/importer/...
- internal/api/...
- internal/config/...
- internal/rulehistory/...
- cmd/importer/...
- web/admin/...
- config.example.yml
- README.md
- IMPORTING.md
- API.md
- DEPLOYMENT.md
- SECURITY.md
- CODEX.md
- .gitignore
- storage/imports/.gitkeep
- storage/imports/reports/.gitkeep

Notes:
- Append-only log entry for Phase 8.
- Full external Sensitive-lexicon content is not committed to the repository.
- Imported rules should be generated locally by the operator.
- Existing Phase 1/2/3/4/5/6/7 APIs remain backward compatible.

## Commit pending

Date: 2026-06-17

Summary:
* Implement Phase 9 filesystem security baseline
* Add reusable root-constrained safepath package
* Harden importer path validation, traversal, reports, and output writes
* Harden rule history, rollback, custom rule, config, and logstore filesystem operations where practical
* Standardize runtime directory permissions to 0750 and generated file permissions to 0600
* Add atomic write helpers with explicit close-error handling
* Reduce security scanner findings where practical without requiring CodeQL zero findings
* Add tests for path safety, symlink rejection, permissions, and existing feature preservation
* Update security/import/deployment/API documentation

Files:
* internal/safepath/...
* internal/importer/...
* internal/api/...
* internal/rulehistory/...
* internal/config/...
* internal/logstore/...
* cmd/importer/...
* README.md
* SECURITY.md
* IMPORTING.md
* DEPLOYMENT.md
* API.md
* CODEX.md

Notes:
* Append-only log entry for Phase 9.
* Existing Phase 1/2/3/4/5/6/7/8 APIs remain backward compatible.
* CodeQL clean output is not required for this phase; remaining path-flow findings should be documented with validated-path invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

Commit e08069755c8e9787aab64273cb2eb917a81a6fc8

Date: 2026-06-16

Summary:

* Implement Phase 10 SQLite persistence backend
* Add local SQLite storage layer with schema migrations
* Add persistent tables for audit logs, rule hits, rule changes, import batches, and admin operations
* Add paginated query support for audit logs and import batches
* Preserve JSONL as fallback or legacy compatibility where practical
* Add JSON and CSV export support for persisted records
* Keep YAML rule files as the rule source of truth while tracking rule changes in SQLite
* Use Phase 9 safepath protections for database and generated file paths
* Add tests for migrations, pagination, persistence, exports, and compatibility
* Update API, deployment, importing, security, README, and CODEX documentation
* Apply the Phase 10 scanner policy: fix real issues, document custom sanitizer invariants, and do not damage architecture for CodeQL zero findings

Files:

* internal/storage/...
* internal/storage/sqlite/...
* internal/storage/migrations/...
* internal/logstore/...
* internal/rulehistory/...
* internal/importer/...
* internal/api/...
* internal/config/...
* cmd/server/...
* cmd/importer/...
* README.md
* SECURITY.md
* IMPORTING.md
* DEPLOYMENT.md
* API.md
* CODEX.md

Notes:

* Append-only log entry for Phase 10.
* Existing Phase 1-9 APIs remain backward compatible.
* SQLite is implemented first; PostgreSQL is intentionally deferred.
* JSONL remains available as fallback or legacy compatibility where practical.
* CodeQL clean output is not required for this phase; remaining custom sanitizer findings should be reviewed against documented invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

## Commit pending

Date: 2026-06-17

Summary:

* Implement Phase 11 rule versioning and release workflow
* Add draft/staged/published rule lifecycle support
* Add pre-publish validation and rule conflict detection
* Add ruleset version tracking and release metadata
* Add whole-ruleset rollback to previous published versions
* Add import batch rollback where sufficient metadata exists
* Add bulk enable/disable operations
* Add rule hit simulation against published/staged/draft scopes where practical
* Persist lifecycle/release metadata through the Phase 10 SQLite backend where practical
* Preserve existing YAML rule source-of-truth behavior and existing APIs
* Preserve Phase 9 safepath protections and Phase 10 SQLite/JSONL compatibility
* Update API, security, deployment, importing, README, and CODEX documentation
* Apply the Phase 11 scanner policy: fix real issues, document custom sanitizer invariants, and do not damage architecture for CodeQL zero findings

Files:

* internal/api/...
* internal/rules/...
* internal/rulerelease/...
* internal/rulehistory/...
* internal/importer/...
* internal/storage/...
* internal/storage/sqlite/...
* internal/storage/migrations/...
* internal/safepath/...
* cmd/server/...
* web/admin/...
* README.md
* SECURITY.md
* IMPORTING.md
* DEPLOYMENT.md
* API.md
* CODEX.md

Notes:

* Append-only log entry for Phase 11.
* Existing Phase 1-10 APIs remain backward compatible.
* YAML rule files remain the source of truth for rule content.
* SQLite stores lifecycle, release, validation, rollback, and admin operation metadata where practical.
* CodeQL clean output is not required for this phase; remaining custom sanitizer findings should be reviewed against documented invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

## Commit pending

Date: 2026-06-17

Summary:

* Implement Phase 13 full Traditional/Simplified, pinyin, and homophone variant enhancement
* Add improved Traditional/Simplified conversion and OpenCC-compatible mapping strategy where practical
* Add pinyin normalization, tone handling, initials support, and symbol-interference handling
* Add bounded polyphonic-character strategy
* Add enhanced homophone configuration and false-positive controls
* Add variant risk scoring with risk_level, score, category, and explanation
* Add review-first behavior for pinyin/homophone-only matches
* Integrate variant metadata into engine/API/storage/release validation where practical
* Preserve exact keyword/regex/domain matcher behavior
* Preserve YAML source-of-truth and Phase 11 release workflow compatibility
* Update API, security, deployment, importing, README, and CODEX documentation
* Apply the Phase 13 scanner policy: fix real issues, document custom sanitizer invariants, and do not damage architecture for CodeQL zero findings

Files:

* internal/normalizer/...
* internal/rules/...
* internal/engine/...
* internal/matcher/...
* internal/variant/...
* internal/rulerelease/...
* internal/storage/...
* web/admin/...
* data/keywords/...
* README.md
* SECURITY.md
* IMPORTING.md
* DEPLOYMENT.md
* API.md
* CODEX.md

Notes:

* Append-only log entry for Phase 13.
* Phase 12 benchmark work is intentionally skipped and not implemented here.
* Existing Phase 1-11 APIs remain backward compatible.
* YAML rule files remain the source of truth for rule content.
* Pinyin and homophone-only generated variant matches do not hard block by default.
* CodeQL clean output is not required for this phase; remaining custom sanitizer findings should be reviewed against documented invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

## Commit pending

Date: 2026-06-17

Summary:

* Implement Phase 14 AI review provider integration
* Add explicit AI provider interface with OpenAI-compatible, Gemini, Claude, DeepSeek, Qwen, and local endpoint adapters
* Keep AI disabled by default and preserve deterministic rule-engine authority
* Add additive `ai_review` audit response metadata without removing existing response fields
* Default AI provider `block` output to `block_recommended` unless hard-block mode is explicitly enabled
* Add prompt template rendering with static config templates and a safe default review-first prompt
* Add deterministic hash-based in-memory AI cache with TTL
* Add bounded provider timeout, retry, backoff, and circuit breaker behavior
* Add token usage and configurable estimated cost calculation
* Add SQLite `ai_audit_logs` migration and query endpoint for compact AI attempt metadata
* Add fake-provider tests for AI cache, prompt rendering, failure handling, circuit breaker behavior, and deterministic audit authority
* Update API, README, security, config example, and CODEX documentation
* Apply the Phase 14 scanner policy: fix real issues, document provider/path/logging invariants, and do not damage architecture for CodeQL zero findings

Files:

* internal/ai/...
* internal/api/...
* internal/config/...
* internal/engine/...
* internal/storage/sqlite/...
* internal/storage/migrations/...
* cmd/server/...
* README.md
* SECURITY.md
* API.md
* config.example.yml
* CODEX.md

Notes:

* Append-only log entry for Phase 14.
* Existing Phase 1-13 APIs remain backward compatible.
* AI is an auxiliary review/explanation layer and does not change top-level deterministic rule-engine decisions.
* AI unavailable, timeout, error, unconfigured provider, and circuit-open states do not break normal audit responses.
* Provider credentials are read from configured environment variables only and are not required for tests.
* Prompt/raw response storage remains disabled by default.
* SQLite AI audit logs store compact metadata only by default.
* CodeQL clean output is not required for this phase; remaining provider/logging/cache findings should be reviewed against documented invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

## Commit pending

Date: 2026-06-17

Summary:

* Implement Phase 15 internal human review queue and admin moderation workflow
* Add review policy thresholds for AI and variant uncertainty
* Add temporary allow / temporary block / review-only / log-only policy behavior
* Add persistent internal review cases
* Add operator decisions and internal notes
* Add bulk review decisions
* Add review queue APIs and stats
* Add review policy APIs
* Add review audit trail and admin operation logging where practical
* Integrate review queue with AI and variant metadata while preserving deterministic rule-engine decisions
* Improve admin dashboard layout with visual review queue, risk badges, policy settings, and case details
* Preserve AI review-first behavior and keep AI disabled/hard-block disabled by default
* Preserve Phase 1-14 behavior and API compatibility
* Update API, security, deployment, README, and CODEX documentation
* Apply the Phase 15 scanner policy: fix real issues, document custom sanitizer invariants, and do not damage architecture for CodeQL zero findings

Files:

* internal/review/...
* internal/api/...
* internal/engine/...
* internal/ai/...
* internal/config/...
* internal/storage/...
* internal/storage/sqlite/...
* internal/storage/migrations/...
* web/admin/...
* README.md
* SECURITY.md
* DEPLOYMENT.md
* API.md
* CODEX.md

Notes:

* Append-only log entry for Phase 15.
* This is an internal platform moderation workflow, not a customer support ticket system.
* There is no user feedback, appeal, reply, or customer-service workflow.
* AI does not hard block by default.
* Rule engine remains primary.
* Uncertain AI/variant results are routed according to admin policy.
* All temporary actions and human decisions are auditable.
* CodeQL clean output is not required for this phase; remaining custom sanitizer findings should be reviewed against documented invariants.
* Gosec findings are fixed where practical and remaining findings are reported.

## Commit pending

Date: 2026-06-17

Summary:

* Implement Phase 12 performance benchmark documentation
* Run benchmark measurements against the current OpenAudit main code
* Document keyword matcher benchmark evidence
* Document regex matcher benchmark evidence
* Document domain matcher benchmark evidence
* Document 10k / 100k / 1M keyword coverage where measured or explain limitations
* Document 1KB / 10KB / 100KB text coverage where measured
* Document batch 100 / 1000 measurements where measured
* Document reload/build timing
* Document memory allocation results
* Document p50 / p95 / p99 latency where measured
* Add BENCHMARK.md with measured results and reproduction commands
* Update README.md with conservative evidence-backed high-performance wording
* Preserve runtime behavior and commit Markdown documentation only

Files:

* BENCHMARK.md
* README.md
* CODEX.md

Notes:

* Phase 12 is benchmark and documentation evidence only.
* Final committed changes are Markdown-only.
* Runtime matcher behavior is not changed.
* No benchmark helper code is committed.
* CodeQL clean output is not required for this phase; real issues are fixed and false positives are documented with invariants if applicable.
* Gosec findings are fixed where practical and remaining findings are reported.


## Commit pending

Date: 2026-06-22

Summary:
- Implement NetEase bundled rules Phase A foundation with default-disabled configuration.
- Add deterministic pack conversion, RE2 compatibility reporting, gzip validation, CLI, documentation, and tests.

Files:
- internal/bundled/...
- internal/config/...
- cmd/bundled-rules/main.go
- docs/bundled-rules-phase-a.md
- README.md
- CHANGELOG.md

Notes:
- Runtime loading and PCRE2 matching are deferred; no full upstream databases or generated packs are bundled.

## Commit pending

Date: 2026-06-22

Summary:
- Harden NetEase bundled rules Phase A with bounded file reads, strict JSON EOF and duplicate-key rejection, central pack validation, malformed-record reporting, report file generation, pack/report consistency checks, and single-member gzip validation.
- Improve reproducibility tests, environment override validation, CLI error handling, and Phase A documentation.

Files:
- internal/bundled/...
- internal/config/...
- cmd/bundled-rules/main.go
- docs/bundled-rules-phase-a.md
- CODEX.md

Notes:
- Runtime loading and PCRE2 matching remain deferred; no full upstream databases or generated packs are bundled.


## Commit pending

Date: 2026-06-22

Summary:
- Address PR #22 review findings by enforcing duplicate identity invariants, adding unknown-record accounting, strengthening pack/report validation, bounded CLI validate reads, rollback-capable pack/report replacement, and panic-safe JSON token handling.
- Add tests for parser malformed inputs, unknown groups, report mutations, mapping mutations, and rollback scenarios.

Files:
- internal/bundled/...
- cmd/bundled-rules/main.go
- docs/bundled-rules-phase-a.md
- CODEX.md

Notes:
- Runtime loading and PCRE2 matching remain deferred; no full upstream databases or generated packs are bundled.


## Commit pending

Date: 2026-06-22

Summary:
- Finalize PR #22 Phase A rollback and validation fixes with explicit rollback state tracking, secure same-directory temporary staging, directory sync handling, and canonical UTC timestamp validation.
- Add deterministic rollback state tests and UTC timestamp policy tests.

Files:
- internal/bundled/...
- docs/bundled-rules-phase-a.md
- CODEX.md

Notes:
- Runtime loading and PCRE2 matching remain deferred; no full upstream databases or generated packs are bundled.


## Commit pending

Date: 2026-06-22

Summary:
- Fix WritePairAtomic backup lifecycle so failed backup restoration preserves retained recovery backups and reports their paths.
- Add deterministic tests for retained pack/report backups, both-restore failure, and post-commit backup cleanup failure.

Files:
- internal/bundled/...
- docs/bundled-rules-phase-a.md
- CODEX.md

Notes:
- Runtime loading and PCRE2 matching remain deferred; no full upstream databases or generated packs are bundled.

## Commit pending

Date: 2026-06-23

Summary:
- Implement NetEase Integration Phase D optional PCRE2 runtime support behind explicit configuration and the `pcre2` build tag.
- Preserve default RE2 behavior and CGO-free builds, with clear unsupported errors when PCRE2 is requested in default builds.
- Add runtime statistics for selected regex backend, PCRE2 compatibility, backend-unavailable skips, and dataset/group-disabled skips.
- Add direct PCRE2 8-bit cgo binding with compile-time pattern construction and hardcoded match/depth limits.
- Update documentation, example config, Makefile optional PCRE2 targets, and tests.

Files:
- internal/matcher/...
- internal/bundled/...
- internal/engine/...
- internal/config/...
- README.md
- docs/bundled-rules-phase-b-runtime.md
- config.example.yml
- Makefile
- CHANGELOG.md
- CODEX.md

Notes:
- Default builds do not import PCRE2 or require CGO.
- Runtime downloads, automatic network updates, Docker/release packaging changes, root license changes, and NetEase data relicensing are not included.

## Commit pending

Date: 2026-06-23

Summary:
- Add a separate optional PCRE2 GitHub Actions workflow for tagged tests and builds with system PCRE2 dependencies.
- Fix PCRE2 backreference test patterns so tagged builds exercise native backreference support correctly.
- Add PCRE2-tagged bundled runtime coverage confirming additional compatible NetEase rules activate without changing default RE2 behavior.

Files:
- .github/workflows/pcre2.yml
- internal/matcher/pcre2_test.go
- internal/engine/bundled_runtime_test.go
- internal/engine/bundled_runtime_pcre2_test.go
- CODEX.md

Notes:
- Default CI and default CGO-free builds remain independent of PCRE2.
