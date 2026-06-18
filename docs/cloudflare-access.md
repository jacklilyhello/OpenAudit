# Cloudflare Access production model

This document describes the intended production access model for OpenAudit. It is documentation only; it does not configure Cloudflare.

```text
Cloudflare Access -> Cloudflare Tunnel -> 127.0.0.1:8080 on VPS -> OpenAudit
```

## Critical warnings

- Do **not** expose `/admin` directly to the public internet.
- Do **not** point a normal public A/AAAA admin DNS record directly at the VPS origin.
- Do **not** commit production API keys, admin API keys, or AI provider secrets.
- Keep origin firewall rules restrictive so the VPS service is reachable only through the local tunnel path or trusted administration channels.

## Cloudflare Access policy

Create a Cloudflare Access application for the OpenAudit hostname or admin path and set an Access policy for the operators who may use OpenAudit. Use your Cloudflare dashboard to choose the identity provider, allowed users/groups/domains, session duration, and any MFA requirements.

OpenAudit's conservative production example assumes Cloudflare Access is enforced before traffic reaches the VPS origin. Application secrets remain separate and must still be configured with OpenAudit environment variables.

## Cloudflare Tunnel public hostname

Configure a Cloudflare Tunnel public hostname for the OpenAudit hostname. The tunnel service target should be:

```text
http://127.0.0.1:8080
```

The production Docker Compose example binds OpenAudit to `127.0.0.1:8080:8080`, so the service listens on the VPS loopback interface rather than all public interfaces.

## OpenAudit API key environment variables

Set production API keys outside git, for example in your shell, a private Docker Compose env file, a systemd environment file, or a secret manager:

```bash
OPENAUDIT_API_KEYS=replace-with-long-random-key[,another-key]
OPENAUDIT_ADMIN_API_KEY=replace-with-different-long-random-admin-key
```

For systemd deployments, place these in `/etc/openaudit/openaudit.env` with restrictive permissions. For Docker Compose deployments, export them before running Compose or use an uncommitted env file.

## Production config files

Use `config.production.example.yml` as a conservative starting point. It sets `app.env: "production"`, keeps management APIs protected, does not allow admin access without an API key, keeps AI providers disabled by default, and disables full raw request text logging by default.

## Logging and privacy

Full raw request text may contain sensitive user content. The production example sets `audit_log.log_request_text: false` and leaves AI prompt/raw provider response logging disabled. Enable those fields only after explicitly reviewing privacy, retention, backup, and access-control obligations.
