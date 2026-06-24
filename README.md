# OpenAudit

OpenAudit is an open-source content moderation and risk audit engine for policy-based content review, anti-spam, anti-fraud, compliance testing, and safety research. It supports deterministic rules, external rule imports, operator review workflows, AI-assisted review, SQLite persistence, and operational safety controls for running a local or self-hosted audit service.

## Features

- Text audit API with normalized matching, risk scoring, explanations, batching, and optional audit metadata.
- Keyword, regex, domain, Traditional/Simplified Chinese, pinyin, initials, homophone, and bounded variant detection.
- Rule management APIs with validation, hot reload, draft/staged/published release workflow, simulation, and pre-publish checks.
- Rule history, diffs, import batch metadata, API-managed rollback, and whole-ruleset release rollback.
- SQLite persistence for audit logs, rule changes, import batches, admin operations, AI audit metadata, and review cases.
- Internal review queue for uncertain AI and variant cases, with capped excerpts, operator decisions, notes, exports, and policy controls.
- AI review provider abstraction for optional auxiliary review across configured providers without making AI authoritative by default.
- Production access controls for management APIs and `/admin`, including production environment checks and Cloudflare Access/Tunnel guidance.
- Security scanning and release validation through CI, gosec, govulncheck, CodeQL, smoke tests, and deterministic E2E validation.

## Quick start

Run locally with the default configuration:

```bash
go run ./cmd/server
```

Or run with the development example config explicitly:

```bash
go run ./cmd/server --config ./config.example.yml
```

The default server address is `:8080`. Check health with:

```bash
curl http://localhost:8080/health
```

Use Docker Compose for local development only:

```bash
docker compose up --build
```

Run release-oriented local checks:

```bash
make smoke
make e2e
make release-check
```

`make smoke` starts the service and performs a basic API smoke test. `make e2e` runs deterministic end-to-end release validation with `scripts/e2e.sh`.
Build metadata is available with `go run ./cmd/server --version`.

## Configuration

- [`config.example.yml`](config.example.yml) is development-oriented and may include local sample values such as `dev-key`.
- [`config.production.example.yml`](config.production.example.yml) is the production example and uses conservative access-control and logging defaults.
- API keys, AI provider keys, and other provider secrets must come from environment variables or secret stores and must not be committed.
- Production examples are documented in [DEPLOYMENT.md](DEPLOYMENT.md), [`docker-compose.prod.example.yml`](docker-compose.prod.example.yml), and [`deploy/systemd/openaudit.service`](deploy/systemd/openaudit.service).

## Production warning

Do **not** expose `/admin` directly to the public internet. The recommended production model is:

```text
Cloudflare Access -> Cloudflare Tunnel -> 127.0.0.1:8080 on VPS -> OpenAudit
```

Use Cloudflare Access, Cloudflare Tunnel, and a localhost origin. Do not point a normal public admin DNS record directly at the VPS origin IP.

`docker-compose.yml` is local/development only because it exposes `8080:8080` for convenience. The production Compose example binds OpenAudit to localhost with `127.0.0.1:8080:8080`. Production logging defaults avoid raw request text, and AI prompt/raw provider response logging remains disabled unless an operator explicitly enables it after reviewing privacy and retention obligations.

## Documentation

- [API.md](API.md) — endpoint reference, request limits, examples, AI/variant response semantics, review queue APIs, and storage APIs.
- [IMPORTING.md](IMPORTING.md) — external ruleset strategy, Sensitive-lexicon-compatible imports, dry runs, reloads, and import safety.
- [DEPLOYMENT.md](DEPLOYMENT.md) — local, Docker, production examples, systemd, Cloudflare Access/Tunnel, storage, backup, and logging guidance.
- [SECURITY.md](SECURITY.md) — vulnerability reporting, scanner policy, production access controls, safepath constraints, SQL invariants, AI safety, and review queue safety.
- [BENCHMARK.md](BENCHMARK.md) — reproducible benchmark references and caveats.
- [docs/cloudflare-access.md](docs/cloudflare-access.md) — Cloudflare Access and Tunnel production model.
- [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) — phase-by-phase implementation history.
- [CHANGELOG.md](CHANGELOG.md) — release-note style summary of completed user-facing changes.
- [ROADMAP.md](ROADMAP.md) — future-facing roadmap.
- [docs/release.md](docs/release.md) — release tags, binary artifacts, SHA256SUMS, GHCR images, and PCRE2 distribution notes.

## Security and CI summary

CI runs formatting checks, `go vet ./...`, `go test ./...`, `go build ./...`, and smoke validation. Gosec is a blocking Phase 16 release-baseline security gate; real findings should be fixed where practical, and false positives should use narrow documented invariants rather than broad `#nosec` suppressions. Govulncheck is used for reachable vulnerability scanning, and CodeQL is used for Go security and quality analysis.

Deterministic E2E validation is available through `make e2e` and is treated as manual release validation unless it is wired into CI in the future.

## Development status

OpenAudit is an early self-hosted project. See [CHANGELOG.md](CHANGELOG.md) for release-relevant completed work, [ROADMAP.md](ROADMAP.md) for future work, and [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) for historical implementation notes.


## NetEase bundled rules (Phase A/B/C/D)

OpenAudit includes default-disabled, local-only NetEase bundled rule support. Phase A provides deterministic Pack generation and reports, Phase B loads local Packs at runtime, Phase C pins real G79/X19 artifacts with the GPL data boundary, and Phase D adds optional PCRE2 runtime support behind an explicit `bundled_rules.netease.regex_engine: pcre2` setting. RE2 remains the default backend and default builds remain CGO-free; PCRE2 builds require `CGO_ENABLED=1`, `-tags pcre2`, and the system `libpcre2-8` development package. No complete upstream database download occurs at runtime, no automatic network updates are performed, and Docker/release images remain default RE2 unless explicitly rebuilt. See `docs/bundled-rules-phase-a.md`, `docs/bundled-rules-phase-b-runtime.md`, and `docs/bundled-rules-phase-c-netease.md`.

## Production bundled NetEase operations

The production default remains RE2-only, `CGO_ENABLED=0`, and bundled NetEase disabled. Build it with:

```sh
make docker-build
CGO_ENABLED=0 go build ./...
```

Optional PCRE2 support is opt-in and requires a PCRE2-enabled binary/image built with CGO and `-tags pcre2`:

```sh
make docker-build-pcre2
CGO_ENABLED=1 go build -tags pcre2 ./...
```

Use `config.bundled-rules.examples.yml` for examples enabling no bundled rules, NetEase without datasets, G79 only, X19 only, both datasets, Shield/Intercept only, Replace/Nickname/Remind opt-in, `regex_engine: re2`, and `regex_engine: pcre2`. PCRE2 configs fail clearly when the current binary lacks PCRE2 support.

Operator checks:

```sh
go run ./cmd/server --config config.example.yml --validate-config
go run ./cmd/server --config config.example.yml --print-bundled-summary
make verify-bundled-netease
curl -H "X-API-Key: $OPENAUDIT_ADMIN_API_KEY" http://127.0.0.1:8080/rules/stats
```

Bundled runtime stats avoid raw regex patterns and offensive rule content while reporting provider/dataset enablement, selected regex engine, backend availability, compatibility counts, activated/skipped counts, safe pack hashes, and successful reload timestamps. See `docs/production-runtime-ops.md` for Docker, Compose, PCRE2, GPL/MIT data-boundary, and security guidance.

## Release distribution

Versioned releases are tag-triggered from `v*` tags. Default binary artifacts use RE2/Go regexp and are built for Linux, macOS, and Windows without requiring CGO. Optional PCRE2 distribution is Docker-first because native cross-compilation requires CGO, libpcre2, and platform toolchains. See [docs/release.md](docs/release.md) for release creation, SHA256 verification, GHCR pull/run commands, Docker tag strategy, and the bundled NetEase GPL/MIT data boundary.
