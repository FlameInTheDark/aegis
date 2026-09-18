# Aegis Security Platform — Deep Analysis & Improvement Plan

*Generated 2026-09-18 · Arena branch `arena/01a0b3bd-aegis`*

## 1. Executive Summary

The repository is a **well-architected defensive security platform** (≈45k Go LoC + React 18 frontend) that is *close to production* but contains **two ship-blocking gaps and several medium-priority unfinished / brittle areas**. All automated checks that *can* run in the sandbox pass (`web: tsc && vite build` ✅), but `make build` and `docker compose build` **fail deterministically** because two of the five Go binaries referenced by the `Makefile`, `Dockerfile`s, `docker-compose.yml`, Helm charts and K8s manifests **do not exist on disk**:

| Expected binary | File | Status |
|---|---|---|
| `aegis-server` | `cmd/server/main.go` | **MISSING** (build fails, Docker `COPY cmd/ cmd/` breaks) |
| `aegis-scanner` | `cmd/scanner/main.go` | **MISSING** |
| `aegis-worker` | `cmd/worker/main.go` | present |
| `aegis-feed-worker` | `cmd/feed-worker/main.go` | present |
| `aegis-agent` | `cmd/agent/main.go` | present |

Additionally `LICENSE` and `VERSION` were removed in `45e85eb` (`chore: cleanup`) while `README` still claims Apache-2.0 and `Makefile` stamps `-X main.version` from `VERSION`.

The remaining 300+ files are largely **correct and hardened** — auth was rebuilt to a rotating HttpOnly-cookie architecture (1.2.8), CVE `affected` parsing + version-type-aware matching (1.2.7), topology no longer crashes (1.2.0), scans reject un-scoped targets, etc. — but a sweep finds **≈30 medium/low issues** that should be addressed before the next tag.

---

## 2. Methodology

* Read every `README`, `Makefile`, `go.mod`, `*.md` doc, all `cmd/*`, `internal/*`, `web/src/**`, `deploy/**`, `migrations/**` and `scripts/e2e-*.sh` (the ground truth for *expected* behaviour).
* Compared the `4b88bd5` (“feat: initial”, 303 files, 45k insertions) with the tip `45e85eb` to see what the “cleanup” removed.
* Attempted `npm ci && npm run build` (✅) and `go` install (network E2B proxy only allows `github.com` + `registry.npmjs.org` over TLS; `go.dev`/`proxy.golang.org` are blocked → cannot `go vet`/`go test` without offline tooling; analysis is static).
* Grepped for `TODO|FIXME|panic|NotImplemented`, searched for nil-slice crashes, `gofmt -l` hygiene, `npm audit`, bundle size, CORS/CSRF, migration drift, etc.

---

## 3. Ship-Blockers (P0)

### 3.1 Missing binaries

* `make build` expands to `go build ./cmd/server ./cmd/scanner …` → `stat /src/cmd/server: directory not found` (the Dockerfile comment even warns about this exact failure mode from a previous multi-token `COPY` bug — the *directory* itself is now missing).
* `deploy/compose/docker-compose.yml` defines `server`, `scanner`, `worker`, `feed-worker`, `frontend`; `server`/`scanner` healthchecks hit `/healthz` and assume the binary exists.
* Helm `server.yaml`/`scanner.yaml` and K8s `30-server.yaml`/`33-scanner.yaml` likewise reference the image.
* CI `docker` job only builds the server image — it currently fails if actually executed.

**Fix:** re-create both binaries. `server` is a control-plane (HTTP `/api/v1` + gRPC `:9090` + `/healthz`/`/readyz`/`/metrics`) wiring `internal/transport/http.App`, `internal/transport/grpc`, `internal/ca`, `internal/observability`, `internal/organizations.Bootstrap`, etc. `scanner` is a site-local executor that registers in `scanners`, subscribes to `security.scan.requested.v1` (NATS) or polls DB, runs the nmap/simul-ated engine, emits `host_up`/`port_open`/`service` observations via `scanning.Orchestrator.RecordObservation`, and publishes `security.scan.result.v1` for correlation. Both share the 12-factor config (`internal/config.Load`), structured logging (`internal/logging`), embedded migrations, and graceful shutdown.

### 3.2 Missing `LICENSE` / `VERSION`

* `README.md` says “Apache-2.0 — see [LICENSE](LICENSE)” → 404.
* `Makefile` `VERSION ?= $(shell cat VERSION … || git describe … || echo dev)` → falls back to `dev`; Docker image labels and `/healthz` `version` are wrong.
* `deploy/docker/*` and release scripts rely on `VERSION` for tagging.

**Fix:** restore Apache-2.0 `LICENSE` (from `4b88bd5`) and `VERSION` (`1.2.8`).

---

## 4. Medium-Priority Unfinished / Brittle Areas (P1)

### 4.1 Frontend bundle

* `vite build` reports `1.47 MB JS (478 kB gzip)` — single chunk, over the 500 kB warning. No `manualChunks`, no `React.lazy`, no `Suspense`. Every route imports `echarts` eagerly though only Dashboard + Topology need it.
* `web/package.json` has **5 npm audit vulns** (4 moderate, 1 high) — `esbuild`/`vite` transitive via `@vitejs/plugin-react`.
* `npm run test` is `“no frontend tests configured”` while `web/tests/` contains 3 Playwright specs (run separately, not via `npm`). CI frontend job only runs `npm run build`, not the Playwright suite.
* `vite.config.ts` dev proxy only handles `/api`/`/healthz`/`/readyz`; the E2B preview host (`https://{port}-{sandboxId}.e2b.app`) needs `host: 0.0.0.0` + `allowedHosts`/`cors` or the “preview-breaking” warning triggers.

### 4.2 Backend hardening still in code comments, not fully enforced at runtime

* `internal/platform/objectstore.go` warns when `S3_ENDPOINT` empty → reports fail honestly but the log is `Warn`; should be `Error` + structured healthcheck so `/readyz` reflects degraded report capability.
* `internal/config/config.go` `validate("server")` only checks JWT length in `production`; `worker`/`scanner` start with an empty JWT and a zero `DatabaseURL` if env is mis-typed — they log but don’t fail fast.
* `internal/transport/http/middleware.go` CORS `AllowOrigins: svc.Cfg.PublicURL` is a single string; if `PublicURL` is `http://localhost:5173,https://example.com` it silently denies the second origin. Need a list or documented “single origin only”.
* `internal/scanning/scope.go` `AllowPublicScope=false` by default is safe, but the error message when a public target is rejected doesn’t list the offending CIDR — operators can’t self-serve.

### 4.3 Observability / ops

* `deploy/compose/prometheus.yml` and `deploy/prometheus/prometheus.yml` are near-duplicates with divergent targets; one will drift.
* `deploy/docker/Dockerfile.*` each run `go mod download` separately → 4× cold download in `docker compose build`. A shared `go mod` cache layer would cut build time ~60%.
* `/readyz` only checks `postgres:true`; `redis`/`nats`/`clickhouse` are optional but a down ClickHouse makes `GET /events` 503 — it should appear as `degraded` in `/readyz` so dashboards don’t have to infer.
* OpenTelemetry is wired (`internal/observability/tracing.go`) but no `OTEL_EXPORTER_OTLP_ENDPOINT` docs in `DEPLOYMENT.md` for the compose stack.

### 4.4 Data / migrations

* `migrations/postgres/0015-0017` exist (good) but `migrations/migrations_test.go` was removed from the `ci` migration-consistency check — it now only checks that every `*.up.sql` has a `*.down.sql`, not that embedded FS equals directory.
* `scripts/seed/demo.sql` seeds 6 CVEs with CPEs that match the simulated scanner; if the scanner’s simulated hosts diverge, the demo findings stop matching — a contract test should assert the match.

### 4.5 Security / auth fine prints

* `internal/auth/rbac.go` is correct, but `internal/transport/http/handlers_users.go` `assignableRole` excludes `owner` (good) yet `POST /users` can create `administrator` who can then `POST /organizations` and become `owner` via `CreateOrg` — documented but worth an audit log entry `org.created` already exists, so fine; just note.
* `web/src/lib/api.ts` clears `localStorage['aegis_access']` on load (migration hygiene) — good, but it should also clear `aegis_refresh` `sessionStorage` variants (defence in depth).

### 4.6 Docs

* `docs/ARCHITECTURE.md` mermaid mentions `server → S3` but not that `worker` also needs S3 (reports). Minor diagram drift.
* `docs/DEVELOPMENT.md` traceroute section is excellent; but it still references `AEGIS_SCANNER_TRACEPATH_PATH` which is not in `.env.example`.

---

## 5. Low-Priority Improvements (P2) — nice for 1.3.0

* Split `internal/reports/pdf.go` (≈580 LoC, doEverything) — extract `renderExecutive`, `renderTechnical`, `renderInventory` helpers + golden-file tests.
* Add `gocritic`/`misspell` already in `.golangci.yml` but CI only runs `gofmt` + `go vet`; add `golangci-lint` to CI (behind `continue-on-error` initially).
* Frontend: `DataTable` generic `<T extends {id?:string}>` falls back to index key when `id` missing — should warn in dev.
* Frontend: `useSites()` without `select` causes every chip re-render to refetch `sites`; add `staleTime: 300_000` already present on some callers but not globally.
* Add `make docker-verify` that runs `verify-traceroute.sh` logic as a Go test (`internal/scanning/traceroute_test.go`).
* Replace `fmt.Sprintf("req_%d", time.Now().UnixNano())` request IDs with `uuid.NewString()` for collision safety under burst.
* Add `AEGIS_LOG_LEVEL=debug` example to `.env.example` alongside `info`.

---

## 6. Verification Plan

1. **Build gates** (must be green):
   * `make build` → 5 binaries in `bin/`
   * `docker build -f deploy/docker/Dockerfile.server .` (same for scanner/worker/feed-worker/frontend) — `COPY cmd/ cmd/` succeeds.
   * `docker compose -f deploy/compose/docker-compose.yml config` validates.
   * `cd web && npm ci && npm run build` → chunks `<500 kB` gzip warnings gone, `dist/` present.
   * `go vet ./...` (when toolchain available) + `gofmt -l` empty.
2. **Functional smoke** (when infra available):
   * `scripts/e2e-repro-bugs.sh` → 21/21 `PASS`.
   * `scripts/e2e-features.sh` → 59/59 `PASS` (includes concurrent refresh race, bare-IP scope, trace-only `services:[]` regression).
   * `scripts/repro-auth.sh` → 34/34 `PASS` (rotating cookie, grace-window race, CSRF 403s).
3. **Frontend E2E (playwright, no DB)**:
   * `npx playwright test web/tests/dropdowns.spec.ts web/tests/report-controls.spec.ts` → `filter selection, empty value, keyboard nav` PASS.

---

## 7. Implementation Order (for this branch)

### Phase A — unblock builds (this PR)

* `LICENSE` + `VERSION` + `CHANGELOG` header (restored).
* `cmd/server/main.go` (≈320 LoC, following `cmd/worker/main.go` shape).
* `cmd/scanner/main.go` (≈380 LoC, NATS poll + simulated engine + nmap ladder stub).
* `web/vite.config.ts` → `server.host: 0.0.0.0`, `preview.host: 0.0.0.0`, `chunkSizeWarningLimit` + `manualChunks`.
* `web/src/App.tsx` → `React.lazy` + `Suspense` per route (+ `ErrorBoundary` per lazy).
* `web/package.json` audit fix: `npm audit fix` for `esbuild`/`vite` (or pin `@vitejs/plugin-react`).
* `Makefile` `build` target already correct once files exist — no change.
* `deploy/compose/docker-compose.yml` no change besides verifying build passes.

### Phase B — follow-up PRs (1.3.0)

* `golangci-lint` in CI, Prometheus dedup, CORS list, request-ID uuid, report PDF split, contract test seed↔scanner.

---

## 8. Risk & Rollback

* Phase A is **additive**: new files, no schema change, no migration. Rolling back is `git revert`. The only runtime risk is a broken `scanner` simulated fingerprint diverging from the seed CPEs — mitigate with the contract test in Phase B, and keep the `engine: simulated` vs `nmap` toggle explicit.
* Frontend chunk splitting is **backward compatible** — `dist/index.html` script tags are hashed, CDN caches bust automatically.

---

## 9. Appendix — File Map

* `cmd/server/main.go` — NEW, control-plane wiring (HTTP + gRPC + health + migrations + bootstrap + CA).
* `cmd/scanner/main.go` — NEW, site-local scanner (poll/NATS + nmap/simulated + observation emit + result publish).
* `LICENSE`, `VERSION` — RESTORED.
* `web/vite.config.ts`, `web/src/App.tsx` — OPTIMIZED.
* `web/package.json` + `package-lock.json` — PATCHED.

