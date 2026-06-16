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

## API key policy

Development may use `dev-key` in examples. Production API keys must come from environment variables or secret stores and must never be committed. Future production variables include `OPENAUDIT_ENV=production`, `OPENAUDIT_API_KEYS`, and `OPENAUDIT_ADMIN_API_KEY`.

## Admin production warning

`/admin` must not be publicly exposed in production. Protect it with Cloudflare Access in front of Cloudflare Tunnel, and avoid direct public DNS records pointing to the origin VPS. Code-level Access verification is planned for a later phase.

## Scope

OpenAudit is a policy-based content review and risk audit engine for lawful moderation, anti-spam, anti-fraud, compliance testing, and safety research. Security support covers the OpenAudit codebase and documented deployment guidance, not third-party rule content.

## Safe configuration notes

Use least-privilege filesystem permissions, store logs in protected locations, avoid logging sensitive request text when not needed, rotate audit logs, and keep private or large rulesets outside git.
