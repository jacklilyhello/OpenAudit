SHELL := /bin/sh

APP_NAME := openaudit
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP_NAME)
DIST_DIR := dist
IMAGE := openaudit:local
IMAGE_PCRE2 := openaudit:pcre2-local
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: help fmt fmt-check vet test test-pcre2 build build-pcre2 build-all release-check snapshot run clean ci govulncheck gosec docker-build docker-build-pcre2 docker-run docker-smoke docker-smoke-pcre2 smoke e2e verify-bundled-netease regenerate-bundled-netease

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "OpenAudit development targets:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format all Go files
	gofmt -w $(GO_FILES)

fmt-check: ## Check Go formatting without modifying files
	@test -z "$$(gofmt -l $(GO_FILES))" || (gofmt -l $(GO_FILES); exit 1)

vet: ## Run go vet
	go vet ./...

test: ## Run tests
	go test ./...

build: ## Build OpenAudit binary into ./bin/openaudit
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/server

build-all: ## Build default RE2/CGO-free release binaries for common platforms
	rm -rf $(DIST_DIR)/build
	mkdir -p $(DIST_DIR)/build
	@set -eu; for platform in $(PLATFORMS); do \
		goos=$${platform%/*}; goarch=$${platform#*/}; ext=""; \
		if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST_DIR)/build/$(APP_NAME)-$(VERSION)-$$goos-$$goarch$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" ./cmd/server; \
	done
	cd $(DIST_DIR)/build && find . -type f -name '$(APP_NAME)-*' -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS

release-check: fmt-check vet test build build-all verify-bundled-netease ## Run local release validation without publishing
	$(BIN) --version
	cd $(DIST_DIR)/build && sha256sum -c SHA256SUMS

snapshot: build-all ## Create local compressed release snapshot artifacts and SHA256SUMS
	rm -rf $(DIST_DIR)/snapshot
	mkdir -p $(DIST_DIR)/snapshot
	@set -eu; for f in $(DIST_DIR)/build/$(APP_NAME)-$(VERSION)-*; do \
		base=$$(basename "$$f"); \
		case "$$base" in SHA256SUMS) continue ;; esac; \
		cp "$$f" "$(DIST_DIR)/snapshot/$$base"; \
		(cd $(DIST_DIR)/snapshot && tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -czf "$$base.tar.gz" "$$base" && rm "$$base"); \
	done
	cd $(DIST_DIR)/snapshot && find . -type f -name '*.tar.gz' -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS

test-pcre2: ## Run optional PCRE2-tagged tests (requires CGO and libpcre2-8 development files)
	CGO_ENABLED=1 go test -tags pcre2 ./...

build-pcre2: ## Build optional PCRE2 binary (requires CGO and libpcre2-8 development files)
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -tags pcre2 -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)-pcre2 ./cmd/server

run: ## Run OpenAudit locally
	go run ./cmd/server

clean: ## Remove local build artifacts
	rm -rf $(BIN_DIR) dist coverage.out

ci: fmt-check vet test build ## Run local CI checks

govulncheck: ## Install if needed and run govulncheck
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

gosec: ## Install if needed and run blocking gosec security scan
	@command -v gosec >/dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec ./...

docker-build: ## Build default RE2/CGO-free local Docker image
	docker build --target default -t $(IMAGE) .

docker-build-pcre2: ## Build optional PCRE2 Docker image with CGO/libpcre2
	docker build --target pcre2 -t $(IMAGE_PCRE2) .

docker-smoke: docker-build ## Validate default Docker image config without starting listener
	docker run --rm $(IMAGE) --config /app/config.yml --validate-config

docker-smoke-pcre2: docker-build-pcre2 ## Validate optional PCRE2 Docker image config without starting listener
	docker run --rm $(IMAGE_PCRE2) --config /app/config.yml --validate-config

docker-run: ## Run local Docker container
	docker run --rm -p 8080:8080 -v "$$(pwd)/data:/app/data" -v "$$(pwd)/storage:/app/storage" -v "$$(pwd)/config.example.yml:/app/config.yml:ro" $(IMAGE) --config /app/config.yml

smoke: ## Run local smoke test script
	./scripts/smoke.sh

e2e: ## Run deterministic end-to-end verification
	./scripts/e2e.sh

verify-bundled-netease: ## Verify committed NetEase Phase C artifacts without network or writes
	go run ./cmd/sync-netease-rules -mode=verify

regenerate-bundled-netease: ## Regenerate committed NetEase Phase C artifacts from committed snapshots
	go run ./cmd/sync-netease-rules -mode=regenerate
