#!/usr/bin/env bash
# Hybrid dev convenience (spec §111): docker data layer up + one server boot
# to apply migrations, then run the Go binaries natively.
#
#   Prefer the fully containerized stack?  `make dev` builds and runs
#   EVERYTHING (server, worker, scanner, feed-worker, frontend) via docker
#   compose — no manual steps. This script is only for hacking on the Go
#   services with native binaries + debugger.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[aegis-dev] starting data layer (postgres redis nats clickhouse rustfs)…"
docker compose -f deploy/compose/docker-compose.yml up -d postgres redis nats clickhouse rustfs

echo "[aegis-dev] waiting for postgres…"
for i in $(seq 1 30); do
  docker compose -f deploy/compose/docker-compose.yml exec -T postgres pg_isready -U aegis && break
  sleep 1
done

echo "[aegis-dev] building binaries…"
make build

echo "[aegis-dev] starting server once to apply migrations + bootstrap…"
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
AEGIS_DEMO_MODE=true \
timeout 15 ./bin/aegis-server || true

cat <<'NEXT'

[aegis-dev] data layer is ready.
  server:   make run-server   (envs above required)
  worker:   make run-worker
  scanner:  make run-scanner
  feed:     make run-feed-worker
  frontend: cd web && npm run dev   (http://localhost:3000)
  login:    admin@aegis.local / aegis-demo-admin-2026
NEXT
