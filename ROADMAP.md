# Roadmap

This roadmap lists future work only. Completed implementation history lives in [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md), and the product overview lives in [README.md](README.md).

## Release packaging and versioned artifacts

- Add repeatable versioned release artifacts with checksums and signed provenance where practical.
- Document a stable release process for tags, release notes, and upgrade checks.
- Clarify compatibility expectations for configuration, storage migrations, and rule formats between releases.

## Hosted/admin UI improvements

- Improve the admin dashboard for rule lifecycle operations, release comparison, review queue triage, and operational visibility.
- Add clearer UI affordances for production warnings, protected routes, and review-first AI/variant outcomes.
- Continue separating operator-only workflows from any external user communication or appeal concepts.

## Richer review workflows

- Add richer assignment, status, priority, and audit-trail views for internal moderator workflows.
- Expand retention and cleanup tooling for review cases and audit records.
- Improve export ergonomics while preserving row caps, excerpt limits, and secret-safe metadata handling.

## Policy and ruleset ecosystem

- Explore curated public rulesets, policy packs, and marketplace-style distribution without committing private or licensed third-party content.
- Add validation and metadata conventions for ruleset authors.
- Improve tooling for comparing, testing, and promoting external rulesets into staged releases.

## Observability and metrics

- Add structured operational metrics for audit latency, hit counts, review queue volume, provider status, cache behavior, and storage health.
- Document dashboard examples for common self-hosted observability stacks.
- Add alerting guidance for production failures, provider circuit-open states, and unusual queue growth.

## Broader deployment examples

- Expand deployment examples beyond the current local, Compose, systemd, VPS, and Cloudflare Access/Tunnel guidance.
- Add reverse proxy examples for private networks while preserving the requirement that `/admin` is not directly public.
- Document backup and restore drills for SQLite, rule files, release snapshots, and runtime storage.

## Performance and load testing

- Add repeatable load-test scenarios for text audit, batch audit, rule reload, SQLite-backed queries, review exports, and AI-provider-disabled paths.
- Track benchmark changes across releases with clear hardware and dataset caveats.
- Add stress tests for large rulesets and bounded variant expansion.

## Additional provider integrations

- Add more AI provider adapters behind the existing provider abstraction when they can preserve timeout, retry, cache, secret, and review-first semantics.
- Improve provider-specific cost and token accounting metadata.
- Add clearer local/offline provider examples for private deployments.

## Documentation refinements

- Continue tightening quick-start, operations, troubleshooting, and upgrade documentation.
- Add task-focused tutorials for importing rules, publishing rule releases, triaging review cases, and deploying behind Cloudflare Access.
- Keep development history, release notes, and future roadmap separate so the README remains a concise project entrypoint.
