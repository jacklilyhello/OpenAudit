# Release readiness and versioned distribution

OpenAudit releases are tag-driven and publish versioned binary artifacts plus Docker images. Pull-request validation uses a dry run only: it builds artifacts and images locally in CI, generates checksums, and never creates a GitHub Release, logs in to a registry, or pushes packages.

## Creating a release

1. Ensure `main` is green and the changelog is ready.
2. Create and push a signed or reviewed tag such as `v0.1.0-alpha.1`:
   ```sh
   git checkout main
   git pull --ff-only
   git tag v0.1.0-alpha.1
   git push origin v0.1.0-alpha.1
   ```
3. The tag-triggered release workflow creates the GitHub Release, uploads binaries and `SHA256SUMS`, and publishes GHCR images using only `GITHUB_TOKEN`.

Do not create release tags from pull requests. Normal branch pushes and pull requests do not publish.

## Version metadata

Binaries support:

```sh
openaudit --version
# or
go run ./cmd/server --version
```

The output includes the OpenAudit version, commit, build date, Go runtime version, and a regex backend summary. RE2 is always available. PCRE2 is reported as available only for binaries built with `CGO_ENABLED=1 -tags pcre2` and linked against libpcre2.

Local development builds default to `version=dev`, `commit=unknown`, and `date=unknown` unless overridden with ldflags or Makefile variables.

## Binary artifacts

Default release binaries are RE2/Go-regexp builds and are intended to be CGO-free. `make build-all` builds:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

`make snapshot` writes compressed local artifacts under `dist/snapshot/`; `dist/` is ignored and must not be committed. `SHA256SUMS` files are generated from sorted artifact paths for deterministic verification.

Verify downloaded artifacts with:

```sh
sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS` if GNU `sha256sum` is unavailable.

## PCRE2 distribution

PCRE2 remains optional and is not the default. Native PCRE2 cross-compilation requires CGO, libpcre2 development headers, and platform-specific toolchains, so versioned native PCRE2 binary artifacts may be Linux-only or deferred. The supported release distribution for PCRE2 is the Docker image built from the `pcre2` Dockerfile target.

## Docker and GHCR tags

For tag `v0.1.0-alpha.1`, the release workflow publishes:

Default RE2 image:

- `ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1`
- `ghcr.io/jacklilyhello/openaudit:latest`

Optional PCRE2 image:

- `ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1-pcre2`
- `ghcr.io/jacklilyhello/openaudit:pcre2`

Pull and run the default image:

```sh
docker pull ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1
docker run --rm -p 8080:8080 ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1 --config /app/config.yml
```

Pull and run the PCRE2 image:

```sh
docker pull ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1-pcre2
docker run --rm -p 8080:8080 ghcr.io/jacklilyhello/openaudit:v0.1.0-alpha.1-pcre2 --config /app/config.yml
```

## NetEase data and license boundary

OpenAudit code is MIT licensed. Bundled NetEase source snapshots and generated packs/reports are third-party GPL-3.0-only data. The root MIT license does not relicense that data. Notices and exact hashes are maintained in `THIRD_PARTY_NOTICES.md` and `data/bundled/NETEASE-NOTICE.md`.

Bundled NetEase data is default-disabled. OpenAudit does not download complete upstream data at runtime, does not automatically synchronize NetEase data on startup, and does not print raw NetEase regex patterns in release logs. Operators choose whether to enable the local bundled data and must evaluate licensing and moderation impact for their deployment.
