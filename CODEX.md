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
