## Aegis Security Platform - developer tasks
SHELL := /bin/bash
GO    ?= go
NODE  ?= npm

# Release version: git tags are the single source of truth (semantic-release
# cuts them from conventional commits). Override explicitly for local tests.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# Version stamping must cover EVERY var a component reports at runtime:
#   main.version            - cmd/server, cmd/worker, cmd/feed-worker, cmd/connector (cli flag)
#   main.scannerVersion     - cmd/scanner (scanners row version)
#   connectorapp.Version    - aegis-connector runtime (registrations + heartbeats)
#   endpoint.AgentVersion   - cert-based endpoint agent
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) \
  -X main.scannerVersion=$(VERSION) \
  -X github.com/FlameInTheDark/aegis/internal/connectorapp.Version=$(VERSION) \
  -X github.com/FlameInTheDark/aegis/internal/endpoint.AgentVersion=$(VERSION)

-include .env
export

COMPOSE := docker compose -f deploy/compose/docker-compose.yml

.PHONY: help dev dev-hybrid down logs ps build docker test lint fmt generate proto migrate-up migrate-down migrate-version seed e2e clean run-server run-worker run-scanner run-feed-worker run-connector

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

dev: ## Start the FULL stack in docker compose (build images + run everything)
	AEGIS_VERSION=$(VERSION) $(COMPOSE) up -d --build
	@echo ""
	@echo "Full stack is starting (first image build takes a few minutes):"
	@echo "  UI     http://localhost:3000   (admin@aegis.local / aegis-demo-admin-2026)"
	@echo "  API    http://localhost:8080"
	@echo "  Logs   make logs"
	@echo "  Stop   make down"
	@echo ""

dev-hybrid: ## Hybrid dev: docker data layer + native go binaries (./scripts/dev.sh)
	./scripts/dev.sh

down: ## Stop the compose stack (data volumes are kept)
	$(COMPOSE) down

logs: ## Follow compose logs
	$(COMPOSE) logs -f --tail=100

ps: ## Show compose service status
	$(COMPOSE) ps

build: ## Build all Go binaries into ./bin
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/aegis-server      ./cmd/server
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/aegis-worker      ./cmd/worker
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/aegis-scanner     ./cmd/scanner
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/aegis-feed-worker ./cmd/feed-worker
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/aegis-connector  ./cmd/connector

docker: ## Build all service images
	AEGIS_VERSION=$(VERSION) $(COMPOSE) build

test: ## Run Go tests
	$(GO) test ./... -race -count=1

test-frontend: ## Build the SPA and run the Playwright browser suites
	cd web && $(NODE) run build
	cd web && $(NODE) run test:e2e

lint: ## Lint Go (gofmt + vet) and frontend
	@go build ./...
	@test -z "$$(gofmt -l cmd internal api)" || { gofmt -l cmd internal api; echo "run: make fmt"; exit 1; }
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed (skipped)"

fmt: ## Format Go code
	$(GO) fmt ./...
	gofumpt -w -l .

generate: proto ## Regenerate generated code (protobuf/gRPC via buf)

proto: ## Generate protobuf/gRPC code for the agent protocol
	cd api/proto && buf generate

migrate-up: ## Apply PostgreSQL migrations
	$(GO) run ./scripts/migrate up

migrate-down: ## Roll back the last PostgreSQL migration
	$(GO) run ./scripts/migrate down

migrate-version: ## Show current schema version
	$(GO) run ./scripts/migrate version

seed: ## Print instructions + apply demo seed data
	$(GO) run ./scripts/seed

e2e: ## Run the end-to-end verification suites (boot their own sandbox: postgres + nats + stubs; see scripts/)
	bash scripts/e2e-features.sh
	bash scripts/e2e-connectors.sh
	bash scripts/e2e-repro-bugs.sh
	bash scripts/repro-auth.sh

clean: ## Remove build artifacts
	rm -rf bin dist

# --- run targets (hybrid dev, after ./scripts/dev.sh or make dev-hybrid) -------
# Env mirrors scripts/dev.sh: data layer from docker compose (host-published
# ports), binaries on the host. ClickHouse user/password match the compose
# clickhouse service (the image locks its default user to container-internal
# 127.0.0.1 when no credentials are configured).

AEGIS_DEV_ENV := \
	AEGIS_ENV=development \
	AEGIS_LOG_LEVEL=info \
	AEGIS_DATABASE_URL=postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable \
	AEGIS_REDIS_URL=redis://localhost:6379/0 \
	AEGIS_NATS_URL=nats://localhost:4222 \
	AEGIS_CLICKHOUSE_URL=clickhouse://aegis:aegis-ch-dev@localhost:9000?database=aegis \
	AEGIS_S3_ENDPOINT=http://localhost:9001 \
	AEGIS_S3_BUCKET=aegis \
	AEGIS_S3_ACCESS_KEY=aegis \
	AEGIS_S3_SECRET_KEY=aegis-secret-change-me \
	AEGIS_JWT_SECRET=change-me-32-bytes-min-secret-key \
	AEGIS_BOOTSTRAP_ADMIN_EMAIL=admin@aegis.local \
	AEGIS_BOOTSTRAP_ADMIN_PASSWORD=aegis-demo-admin-2026 \
	AEGIS_DEMO_MODE=true

run-server: ## Run aegis-server against the docker data layer
	$(AEGIS_DEV_ENV) ./bin/aegis-server

run-worker: ## Run aegis-worker against the docker data layer
	$(AEGIS_DEV_ENV) ./bin/aegis-worker

run-scanner: ## Run aegis-scanner against the docker data layer
	$(AEGIS_DEV_ENV) ./bin/aegis-scanner

run-feed-worker: ## Run aegis-feed-worker against the docker data layer
	$(AEGIS_DEV_ENV) ./bin/aegis-feed-worker

run-connector: ## Run aegis-connector (enroll: make run-connector ARGS="--connect host:9090/<token>")
	./bin/aegis-connector $(ARGS)
