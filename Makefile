SHELL := /bin/sh

APP_NAME := openaudit
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP_NAME)
IMAGE := openaudit:local
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: help fmt fmt-check vet test build run clean ci govulncheck gosec docker-build docker-run smoke

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
	go build -o $(BIN) ./cmd/server

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

docker-build: ## Build local Docker image
	docker build -t $(IMAGE) .

docker-run: ## Run local Docker container
	docker run --rm -p 8080:8080 -v "$$(pwd)/data:/app/data" -v "$$(pwd)/storage:/app/storage" -v "$$(pwd)/config.example.yml:/app/config.yml:ro" $(IMAGE) --config /app/config.yml

smoke: ## Run local smoke test script
	./scripts/smoke.sh
