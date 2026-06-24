# Production packaging and runtime operations

OpenAudit's production default is intentionally conservative: the default binary and Docker image use Go regexp/RE2-compatible matching, build with `CGO_ENABLED=0`, do not require `libpcre2`, and keep bundled NetEase datasets disabled until an operator opts in.

## Docker images

Build the default RE2 image:

```sh
make docker-build
# equivalent: docker build --target default -t openaudit:local .
```

Build the optional PCRE2 image:

```sh
make docker-build-pcre2
# equivalent: docker build --target pcre2 -t openaudit:pcre2-local .
```

The PCRE2 target installs `pcre2-dev` only in the build stage, compiles with `CGO_ENABLED=1 -tags pcre2`, and installs the runtime `pcre2` package in the final image. The default target does not install PCRE2 packages and remains CGO-free.

## Compose deployment

Use `docker-compose.prod.example.yml` for the default RE2 deployment. It binds `127.0.0.1:8080:8080` so Cloudflare Tunnel, Cloudflare Access, or a trusted reverse proxy can front the service. Do not publish `/admin` directly to the public internet.

For PCRE2, layer the opt-in override:

```sh
docker compose -f docker-compose.prod.example.yml -f docker-compose.pcre2.example.yml build
docker compose -f docker-compose.prod.example.yml -f docker-compose.pcre2.example.yml up -d
```

## Bundled NetEase enablement

Use `config.bundled-rules.examples.yml` for copy/paste snippets covering:

- all bundled rules disabled;
- bundled rules globally enabled while NetEase remains disabled;
- NetEase enabled with no datasets;
- G79 only;
- X19 only;
- G79 and X19;
- Shield/Intercept only;
- Replace/Nickname/Remind opt-in.

NetEase data is GPL-3.0-only third-party data under `data/bundled` and `third_party/netease-sensitive-words`; OpenAudit code remains MIT. Operators choose whether to enable these default-disabled datasets and must account for false positives and licensing obligations.

## Regex engines

`bundled_rules.netease.regex_engine: re2` is the default and works with default builds. `pcre2` requires a binary or image built with `CGO_ENABLED=1 -tags pcre2` and libpcre2 available at build time; dynamically linked containers also need the runtime `pcre2` package. PCRE2 can activate rules that RE2 rejects, but it uses native code and configured match/depth limits, so enable it only when you need PCRE features.

## Operational checks

Validate configuration without starting the listener:

```sh
go run ./cmd/server --config config.example.yml --validate-config
```

Print a safe bundled-rule summary without raw patterns or offensive content:

```sh
go run ./cmd/server --config config.example.yml --print-bundled-summary
```

Verify committed bundled artifacts are reproducible and present:

```sh
make verify-bundled-netease
```

Inspect runtime stats through the protected management API:

```sh
curl -H "X-API-Key: $OPENAUDIT_ADMIN_API_KEY" http://127.0.0.1:8080/rules/stats
```

The bundled stats include global/provider/dataset enablement, selected regex engine, backend availability, RE2 and PCRE2 compatibility counts, activated counts, config-disabled counts, backend-unavailable skips, safe pack metadata hashes, and successful reload timestamps. Public health endpoints intentionally do not expose these details.

## Limitations

- PCRE2 is opt-in and unavailable in default builds.
- Release packaging is Docker/Makefile based; fully automated release publishing remains manual.
- Bundled data is not downloaded or auto-updated at runtime.
- No automatic upstream NetEase updates occur in the service.
