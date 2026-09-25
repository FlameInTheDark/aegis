# Aegis Security Platform — Repository Analysis, UI/UX Review & Feature Proposals

**Document type:** engineering review (bugs, defects, gaps, UX findings, feature proposals)
**Repository:** `FlameInTheDark/aegis` @ `70c4c59` (`main`), analysis branch `arena/01a0d658-aegis`
**Date:** 2026-09-25
**Scope reviewed:** Go control plane (`cmd/`, `internal/`, `api/`, `migrations/`), React SPA (`web/`), CI (`.github/workflows`), deployment assets (`deploy/`), documentation (`docs/`, `README.md`), Makefile/tooling.

**How to read this document**

| Marker | Meaning |
|---|---|
| **P0** | Security or data-integrity defect that must be fixed before any multi-tenant or internet-exposed deployment |
| **P1** | Functional defect: documented feature does not work, or works incorrectly for real users |
| **P2** | Robustness, performance, or maintainability problem with user-visible impact in realistic conditions |
| **P3** | Polish, consistency, documentation drift, dead code |
| `evidence` | `path:line` where the behaviour was observed by reading the code (static review — see §1 for the constraints) |

---

## 0. Executive summary

Aegis is a genuinely well-built codebase: the domain model is coherent, RBAC is centralised, the refresh-token rotation with reuse detection is better than most commercial products, the alert-trigger engine is idempotent by construction, the scan pipeline is careful about argv-injection and scope safety, and the documentation is unusually thorough. Nothing in this report suggests a rewrite; almost every finding is a bounded, well-defined fix.

That said, the review found **concrete, reproducible defects in four clusters**:

1. **Tenant-isolation gaps (P0).** Organization scoping is enforced *by convention* in handler code (there is no RLS anywhere in `migrations/postgres/`). Four read endpoints and one write endpoint bypass that convention, and the suppression feature — the mechanism designed to make findings durable — is never consumed by the correlation pipeline.
2. **Trust-boundary / deployment defects (P0–P1).** The HTTP server trusts a client-supplied `X-Forwarded-For` globally (rate-limit bypass, audit-log spoofing, memory growth), `/readyz` always returns `200` so Kubernetes readiness gates are inert, the Helm chart cannot render (missing helper + missing values), the Kubernetes Secret keys are wrong for the consumers, and the dev `scripts/` tree referenced by the Makefile and docs is not in the repository at all.
3. **Frontend correctness (P1–P2).** Client-side filtering applied *after* server-side pagination silently shortens pages and mis-states totals (Findings "Active", Scans, Detections, Events, assets/findings facets); the "updated 45 s ago" freshness chip on the dashboard is hard-coded; a hook that sends search to the server on every keystroke exists next to a debounce helper with zero callers; and several hooks/endpooints the UI advertises (notes thread, detection-rule authoring, global search in the command palette) are not wired.
4. **A UI with two design generations and thin state handling.** Two component kits, two charting libraries, duplicated badges/empty states, no skeleton loaders, no error states on any page, inconsistent permission gating, and a 2 400 px-wide desktop layout that never adapts to small screens.

### Top 12 fixes by value

| # | Finding | Severity | Where |
|---|---|---|---|
| 1 | `PATCH /assets/{id}` writes cross-tenant — `AssetRepo.Update` has no `organization_id` predicate | **P0** | §2.1 |
| 2 | `/assets/{id}/{services,software,findings,interfaces}` + `/topology/evidence/{edge}` read without resolving the asset in the caller's org | **P0** | §2.2 |
| 3 | Global trust of `X-Forwarded-For` → rate-limit bypass, spoofable audit IPs, unbounded in-process limiter map | **P0** | §2.3 |
| 4 | Suppressions are write-only: `SuppressionRepo.Active` has zero callers, and the suppress handler ignores the finding id | **P0** | §2.5 |
| 5 | `/readyz` returns `200` even when PostgreSQL is unreachable; K8s readiness probe is therefore a no-op | **P1** | §2.4 |
| 6 | Helm chart fails to render (undefined `aegis.selectorLabels`, missing `.Values.scanner`/`.secrets`), K8s Secret keys do not map to environment variables, worker probe points at a port that is never opened | **P1** | §2.8 |
| 7 | `scripts/` (dev bootstrap, migrate CLI, seed, e2e suites) is not tracked, but `make dev-hybrid/migrate-up/seed/e2e` and two docs depend on it | **P1** | §2.9 |
| 8 | Webhook configuration is a dead feature: detections `Notifier` is never wired, `WebhookRepo.Enabled/MarkFired` are never called | **P1** | §2.6 |
| 9 | `POST /assets/{id}/notes` has no permission check, ignores tenant ownership, expects `content` while the client sends `note`, and has no read path | **P1** | §2.7 |
| 10 | The whole gRPC plane runs `insecure.NewCredentials()` (connector connect tokens and secrets in clear text) while README/THREAT-MODEL advertise mTLS | **P1** | §2.10 |
| 11 | Findings/Scans/Detections/Events paginate on the server and then filter in the browser, silently truncating and mis-counting | **P1** | §4.1 |
| 12 | Access JWTs cannot be revoked: `sid` is issued but never checked, so logout/password change/disable leaves tokens valid up to `AEGIS_ACCESS_TOKEN_TTL` (default **1 h**) | **P1** | §2.11 |

Quick wins (each ≤ 1 day, high signal): return `503` from `/readyz`; add `organization_id` to the three unscoped repo updates; delete the eight `var _ = …` artefacts; drop `tailwind.config.ts`; remove the hard-coded `45_000`; gate `/vulnerability-search-actions/capabilities`; wire `useDebounced` into the three server-search inputs; add `ErrorState` branches to the query pages; make the CI `frontend` job run `npm test`.

---

## 1. Method, coverage and limitations

**What was reviewed**

- Backend: all HTTP handlers (`internal/transport/http/*.go`), middleware/auth/refresh rotation, RBAC matrix, repositories (`internal/repository/postgres`, `internal/repository/redis`), scanning (`internal/scanning`, `internal/scanner`, `internal/scanexec`), hub/connector/agent data planes, alerting and detections engines, feeds, reports/PDF writer, config, `cmd/*` entrypoints, all 73 migrations.
- Frontend: `main.tsx`, `App.tsx`, router, auth client/provider, api client, `lib/queries*.ts`, `lib/ws.ts`, `lib/scanstream.ts`, shell/sidebar/topbar/command palette, all 13 pages, shared components, both UI kits, charts, Tailwind v4 theme, Playwright + Vitest configs and existing specs.
- Infra/docs: both workflows, compose stack, Kubernetes manifests, Helm chart, nginx config, Dockerfiles, Makefile, README, all 19 documents in `docs/`.

**Constraints (important for interpreting this report)**

- The sandbox has **no Go toolchain** (and `go.dev`/`proxy.golang.org` are unreachable), so *nothing in the Go code was compiled, vetted, or executed*; all backend findings are static-reading findings. `go vet`/`go test` should be re-run in a normal environment as a confirmation step (§8).
- **Docker is unavailable**, so the compose stack, e2e scripts and image builds could not be exercised.
- `web/node_modules` is absent; npm registry is reachable, so `npm ci && npm test && npx playwright test` is feasible in a prepared environment but was not run here.
- **Only one commit exists in history**, so no regression archaeology (no `git blame`) was possible.

**Severity calibration used here:** a finding is P0 when it crosses a tenant or trust boundary, P1 when a shipped/documented capability demonstrably cannot work, P2 when it degrades under realistic load or after configuration drift, P3 for polish and drift.

---

## 2. Critical defects (P0/P1)

### 2.1 P0 — Cross-tenant asset write via `PATCH /assets/{id}`

**Evidence.** `internal/transport/http/handlers_assets.go:474` validates the fields, then calls `a.svc.Assets.Update(Context(c), c.Params("id"), fields)` at `handlers_assets.go:573`. The repository method (`internal/repository/postgres/repo_assets.go:113`) builds `UPDATE assets SET … WHERE id = $1` — **the organization is never part of the predicate**:

```
Update(ctx, id, fields) → Update("assets").Set(k,v)… .Where(squirrel.Eq{"id": id})
```

Compare `AssetRepo.Delete` (`repo_assets.go:130`), which *does* scope by `organization_id`. The handler also never verifies, before writing, that the asset belongs to the caller's organization: the only org-scoped read happens *after* the write (`handlers_assets.go:574`), and its error is discarded, so a cross-tenant write succeeds and returns `null` to the attacker.

**Impact.** Any authenticated user holding `asset:write` (analyst and above) can modify any asset in another organization — `tags`, `owner`, `notes`, `criticality`, `exposure`, `name_override`, `device_type_override`, `parent_override` — if they know or guess the UUID. Because overrides feed the topology derivation and risk context, this is both data-tampering and a foothold for larger inference attacks. UUIDv4 unguessability is the only remaining mitigation, and asset ids leak widely inside a tenant (topology payloads, change history, exports, alert payloads, support tickets).

**Fix (recommended).**
1. Change the signature to `Update(ctx, orgID, id string, fields map[string]any)` and add `organization_id = $n` to the predicate; return `pg.ErrNotFound` when `RowsAffected() == 0`.
2. In the handler, load `Assets.ByID(ctx, orgID, id)` first (as `handleGetAsset` does) and 404 on miss — this also makes the post-write re-read redundant.
3. Audit-log the update with before/after diff (`AuditService.Entry` already exists) so tampering is traceable.
4. Defence in depth: add PostgreSQL **row-level security** to tenant tables with a session GUC set per request (`SET LOCAL app.current_org = …`). See §6.21 — this is the durable fix for the whole class of §2.1/§2.2 defects.

### 2.2 P0 — Unscoped asset sub-resource reads (and topology evidence)

**Evidence.** These handlers never call `claimsFrom`, never call `requirePerm`, and never resolve the asset against the caller's org — they pass the raw path parameter straight to a repository that filters by asset id only:

| Route | Handler | Repository |
|---|---|---|
| `GET /assets/{id}/services` | `handlers_assets.go:580` | `ServiceRepo.ListForAsset` (`repo_assets.go:516`) — `WHERE asset_id = $1 AND state='open'` |
| `GET /assets/{id}/software` | `handlers_assets.go:589` | `SoftwareRepo.ListForAsset` (`repo_assets.go:663`) |
| `GET /assets/{id}/findings` | `handlers_assets.go:597` | `FindingRepo.ListForAsset` (`repo_findings.go:271`) |
| `GET /assets/{id}/interfaces` | `handlers_assets.go:673` | `InterfaceRepo.ListForAsset` (`repo_assets.go:418`) |
| `GET /topology/evidence/{edgeID}` | `handlers_assets.go:787` | `Topology.EvidenceForEdge` — no asset/org join |

Contrast with the sibling handler `GET /assets/{id}/traces`, which correctly resolves via `Assets.ByID(ctx, orgID, id)` before touching trace data; and `GET /assets/{id}` (`handlers_assets.go:177`) which is fully scoped. The inconsistency is the tell that this is an oversight, not a design decision.

**Impact.** Cross-tenant read of a host's open services, installed software (with versions — an inventory of exploitable packages), open findings including CVEs, and network interfaces (MACs, addresses). The `/topology/evidence/{edge}` variant discloses raw traceroute/probe output. Again gated only by UUID knowledge, but this is exactly the pattern pentests report as "broken object-level authorization".

**Fix.** Same shape as §2.1: resolve the object in the caller's org first (`Assets.ByID`), then delegate. For defence in depth, teach the repository layer to take `orgID` and `JOIN assets` (or use RLS), so a future handler cannot forget. Add a regression test that requests another org's asset id and expects `404`.

### 2.3 P0 — Client-controlled `X-Forwarded-For` trusted globally

**Evidence.** `internal/transport/http/server.go:133` sets `fiber.Config{ProxyHeader: "X-Forwarded-For"}` with no `EnableTrustedProxyCheck`/`TrustedProxies` configuration anywhere in the codebase. Consequences are immediate at three sites:

1. **Rate limiting.** `RateLimitBucket` (`context.go:60`) keys buckets as `bucket + ":" + c.IP()`, and `c.IP()` returns the (spoofed) XFF value when `ProxyHeader` is set. A client can rotate the header per request and never hit the auth/refresh/event limits — trivially defeating the 20/min login throttle that protects credential stuffing.
2. **Audit integrity.** Every audit entry stores `c.IP()` (`AuditService.Entry(ctx, orgID, actor, action, target, c.IP(), …)` throughout). All recorded source IPs are therefore attacker-controlled and useless for investigations.
3. **Memory growth (in-process limiter).** `rateLimiter` (`server.go:408`) keeps `local := map[string][]time.Time{}` keyed by the same value, prunes *timestamps* inside a key but **never removes keys for idle IPs**, and never runs a sweep. With random XFF values — or simply many real clients when Redis is down — the map grows without bound for the process lifetime. Additionally, the Redis branch fails open (`if err == nil && !allowed`), so a Redis outage silently disables throttling.

**Impact.** Credential-stuffing/brute-force protection is bypassable; audit logs are poisonable; a cheap remote memory-exhaustion vector exists in the fallback limiter.

**Fix.**
1. Configure trusted proxies explicitly (`EnableTrustedProxyCheck: true`, `TrustedProxies: []string{...}` from config, e.g. `AEGIS_TRUSTED_PROXIES`), and derive the client IP from `c.IPs()[0]` only when the immediate peer is trusted; otherwise use `c.Context().RemoteAddr()`.
2. Add periodic eviction to the fallback limiter (sweep keys older than `window` every N seconds, or cap the map size and evict oldest) — a small janitor goroutine owned by the app, not by the closure.
3. Make the Redis path distinguish "denied" from "error": on error, prefer the local limiter rather than allowing unconditionally; emit a metric/log so operators see degradation.
4. Document the required reverse-proxy header behaviour (nginx already sets `X-Forwarded-For` correctly in `deploy/nginx/nginx.conf`).

### 2.4 P1 — `/readyz` always returns `200`

**Evidence.** `handlers`/`server.go:445`:

```
ready, deps := a.svc.Health.Check(ctx, critical)   // critical = {postgres: true}
status := "ready"; if !ready { status = "not_ready" }
return c.Status(fiber.StatusOK).JSON(...)          // always 200
```

`deploy/kubernetes/30-server.yaml:20` and `deploy/helm/aegis/templates/server.yaml:20` use `readinessProbe: { httpGet: { path: /readyz, port: 8080 } }`.

**Impact.** A server that cannot reach PostgreSQL still passes its readiness probe, so Kubernetes keeps routing API traffic to it; the failure surfaces to users as 500s from a "Ready" pod, and the orchestrator never restarts the pod. The body does say `not_ready`, so operators *can* see it — but no automated consumer does.

**Fix.** Return `503` when `!ready` (keep the JSON body; keep `/healthz` as the liveness signal, which correctly stays `200`). Optionally support `?verbose=1` for dependency detail and add a metric (`aegis_readyz_status{status=…}`). Mirror the fix in the worker's `serveWorkerHealth` — it already returns `503` correctly (`cmd/worker/main.go:461`), which is why the asymmetry stands out.

### 2.5 P0 — Suppressions are recorded but never applied

**Evidence.** `SuppressionRepo` exposes `Insert` (`repo_findings.go:372`) and `Active` (`repo_findings.go:387`). A repository-wide search for `.Active(` in `internal/` returns **zero call sites** — the only writer is the HTTP handler (`handlers_vulns.go:262`). Nothing in `internal/vulnerabilities/correlate.go`, the findings list path, the risk engine or the report generator consults suppressions.

The handler itself is also wrong in three ways (`handlers_vulns.go:240`):
- it **ignores the `:id` path parameter** and builds the scope from query parameters `?cve=…&asset_id=…` — so `POST /findings/{unknown}/suppress` succeeds;
- it does not require **any** scope field, and `strPtr` maps an empty string to `nil` (`handlers_vulns.go:269`), so a request without scope parameters inserts a row whose `vulnerability` **and** `asset_id` are both NULL — a "suppress everything" record. This is not hypothetical: the SPA's Suppress button posts only `{reason}` with no query string (`FindingsPage.tsx:437-460` → `useSuppressFinding`, `queries.ts:948-952`), so **every suppression created from the UI is scope-less**;
- `asset_id` is inserted verbatim with no `Assets.ByID(ctx, orgID, …)` validation, so a suppression can reference another tenant's asset.

**Impact (end to end).** Clicking "Suppress permanently" shows a success toast, but nothing in the product changes: the finding keeps its status, remains in the active list, and no later pipeline consults the suppression. The operator's reasonable conclusion is that suppression is broken — and because `FindingRepo.Upsert` explicitly re-opens `resolved` findings when they are re-observed (`repo_findings.go:98-125`), there is not even an indirect path by which a scope-based suppression could stick. Meanwhile the rows accumulate with no read, expiry or revoke surface, so the compliance story ("we suppressed this deliberately, for this reason, until this date") is stored but unverifiable, and the audit entry references a finding id that was never used to build the scope (and may not exist).

**Fix (design).**
1. `handleSuppressFinding` should load the finding org-scoped via `Findings.ByID(ctx, claims.OrganizationID, c.Params("id"))`, derive `{cve, asset_id}` from it, and require at least one scope field (reject empty scope with `400`).
2. Introduce `GET /findings/suppressions` and `DELETE /findings/suppressions/{id}` (permission `finding:write`), so operators can audit and revoke.
3. **Enforce** in the pipeline: in `vulnerabilities.Correlator` (and in `FindingRepo.Upsert` / matcher post-processing), load active suppressions for the org once per run, and when a match hits a suppressed `{cve}`/`{asset}` key, either skip creating/refreshing the finding or mark it `suppressed` with reason and `suppressed_until` (preferred — it preserves the evidence trail). Make the SPA's suppress action send the finding's own scope, and have the list filter treat `suppressed` as a distinct state rather than mixing it into active results. Respect `expires_at`; emit an alert event (`finding.suppressed`) so the alert engine can notify.
4. Backfill semantics in `docs/ALERTS.md` / `docs/API.md` and add a test that a suppressed CVE does not re-open on re-correlation.

### 2.6 P1 — Webhook configuration is a dead feature (two alerting systems, one wired)

**Evidence.** The API exposes full CRUD for legacy webhooks (`/webhooks`, `handleListWebhooks`/`handleCreateWebhook` in `handlers_agents.go`, backed by `WebhookRepo` in `repo_detections.go:236+`). Sentinel checks show:
- `DetectionsEngine.Notifier` is **never assigned** anywhere in `cmd/` or `internal/` (the engine holds the field and the worker constructs `detections.Engine{…}` without it);
- `WebhookRepo.Enabled` and `WebhookRepo.MarkFired` have **no callers**;
- the live delivery path is the newer `internal/alerting` stack (`DeliveryWorker`, `alert_deliveries`, `SafeWebhookURL` SSRF guard, HMAC signing, retry/DLQ).

**Impact.** A user can create a webhook through the API, see it listed in the UI, and never receive a single delivery — with no error anywhere. The duplicate system also doubles the attack surface (the legacy path has no `SafeWebhookURL` equivalent on the write side) and confuses the data model (`webhook_configs` vs `alert_destinations`).

**Fix.** Pick one system and make it obvious:
- **Recommended:** deprecate the legacy path. Return `410 Gone` (or `409` with a pointer to `/alerts/destinations`) from `POST /webhooks`, keep `GET` read-only for one release, remove the UI surface, and delete the unused repo methods. Add a migration note; the legacy table has no consumers to migrate.
- **Alternative:** implement the legacy contract by translating `webhook_configs` rows into alert destinations at write time, so one delivery engine remains.
- Either way, delete the dangling `Notifier` field or wire it to the alerting `Store` so the detections engine emits `detection.match.created` trigger events (see §6.9).

### 2.7 P1 — The notes endpoint: ungated, mis-contracted, unreadable

**Evidence.**

| Layer | Reality |
|---|---|
| Route | `POST /assets/:id/notes` (`server.go:245`) — no permission check in `handleAddNote` (`handlers_core.go:246`) |
| Body contract | Handler requires `{"entity":…, "content":…}` and rejects empty `content` (`handlers_core.go:252`) |
| Client | `useAddNote` posts `{ note }` (`web/src/lib/queries.ts:1410`) — always `400` |
| Client usage | `useAddNote` is imported and instantiated in `AssetDetailPage.tsx:98` but **never called** (dead code) |
| Reads | `NoteRepo.List` (`repo_findings.go:430`) exists but has **no HTTP route** — notes can never be read back |
| Validation | `entity` is a free-form string from the request body, stored verbatim; `entity_id` from the URL is not validated against the caller's org |

**Impact.** Any authenticated user — including a read-only `viewer` — can write notes against any entity id, including other tenants' assets; the UI path for notes is broken and has no read surface, so the feature exists only as an unaudited write primitive.

**Fix.** Decide the feature's fate:
- **Keep it:** add an explicit permission (`finding:write` or a new `note:write`), validate `entity ∈ {asset, finding, detection, scan}` and resolve `entity_id` org-scoped, expose `GET /assets/:id/notes`, and fix the client contract to `{ entity, content }`.
- **Remove it:** delete the route, handler, hook and dead import (the asset-level `notes` *column*, edited via `PATCH /assets/{id}`, is the feature users actually use — see §5.4).
Either way the enum validation and tenant resolution are mandatory; do not leave a generic write primitive with no read path.

### 2.8 P1 — Deployment manifests: Helm chart cannot render, K8s secrets do not reach the process

**Helm.** `deploy/helm/aegis/templates/` contains 8 templates, and they reference things the chart does not define:

| Template reference | Status |
|---|---|
| `include "aegis.selectorLabels"` (`templates/scanner.yaml:18,23`, `templates/feed-worker.yaml:14,19`) | **not defined** in `templates/_helpers.tpl` (it defines name/fullname/labels/image/env only) → template execution error |
| `.Values.scanner.replicas / name / siteId / capabilities / nodeSelector / tolerations / resources / hostNetwork` (`templates/scanner.yaml`) | **no `scanner:` key in `values.yaml`** → nil-map error |
| `.Values.secrets.existingSecret` (`templates/scanner.yaml:63`) | **no `secrets:` key in `values.yaml`** |
| `configMapRef: { name: aegis-config }` / `secretRef` in scanner & feed-worker | no ConfigMap/Secret templates exist in the chart |
| `.Values.feedWorker.*` (feed-worker templates) | not present in `values.yaml` |

`helm lint deploy/helm/aegis` fails as soon as it renders scanner/feed-worker; `helm install` will fail. `templates/NOTES.txt` also advertises a Swagger UI at `/swagger/index.html` that the product does not serve (§3.13).

**Kubernetes.** `deploy/kubernetes/12-secret.yaml` stores keys named `database-url`, `jwt-secret`, `s3-access-key`, `bootstrap-admin-email/password`, and the Deployments consume it with `envFrom: secretRef`. `envFrom` maps **key names directly to environment variable names**, so the container receives `database-url=…` — but `internal/config/config.go` reads `AEGIS_DATABASE_URL` (or the bare `DATABASE_URL`), never `database-url`. Every credential in that Secret is therefore invisible to the process; the stack boots with defaults (Connect refused, or worse, demo fallbacks). The ConfigMap has the same shape problem for any key not spelled as the env var.

**Worker probe.** `deploy/helm/aegis/templates/worker.yaml:20` probes `httpGet /healthz port 8080`, but the worker's health listener binds `AEGIS_METRICS_ADDR` — default `:9100` (`cmd/worker/main.go:452`) and unset in the chart, while `values.yaml`/`_helpers.tpl` only export DB/Redis/NATS/JWT vars. The readiness probe can never succeed.

**Fix.**
1. Rewrite the chart: define `aegis.selectorLabels`, add `scanner`, `feedWorker`, `worker`, `secrets`, `s3`, `metrics` sections to `values.yaml`, and add `configmap.yaml`/`secret.yaml` templates (or document `secrets.existingSecret` as required and guard with `required "…" .Values.secrets.existingSecret`).
2. Probe the metrics port (`9091` in the compose convention; make it explicit as `AEGIS_METRICS_ADDR: ":9091"` in the chart env and point `readinessProbe` at it).
3. For Kubernetes, use either correctly-named Secret keys (`AEGIS_DATABASE_URL`, `AEGIS_JWT_SECRET`, …) with `envFrom`, or explicit `valueFrom.secretKeyRef` mappings; add a `kubectl apply --dry-run=client` + `helm template` CI step (§3.11/§7) so this class of bug cannot ship again.
4. Keep the compose file's demo credentials clearly labelled — see §3.12 for the production-safety hardening.

### 2.9 P1 — `scripts/` is missing from the repository, but the Makefile and two docs depend on it

**Evidence.** `git ls-files scripts` returns **0 files**; the directory does not exist in the checkout. Yet:

- `Makefile:41` — `dev-hybrid` runs `./scripts/dev.sh`;
- `Makefile:85-91` — `migrate-up|migrate-down|migrate-version` run `go run ./scripts/migrate <cmd>`;
- `Makefile:94` — `seed` runs `go run ./scripts/seed`;
- `Makefile:96-101` — `e2e` runs four `scripts/*.sh` suites;
- `docs/DEVELOPMENT.md` documents the hybrid flow around `scripts/dev.sh` (and `scripts/feeds`);
- `.gitignore` contains half a dozen `scripts/…` entries, implying the tree once existed.

**Impact.** Four documented developer workflows (`make dev-hybrid`, `make seed`, `make migrate-*`, `make e2e`) fail immediately for anyone cloning the repository. CI never notices because it does not call them.

**Fix.** Commit the scripts (preferred — they encode real environment knowledge, e.g. the ClickHouse credentials in the `AEGIS_DEV_ENV` block), or delete the targets and rewrite `docs/DEVELOPMENT.md` to the `make dev` (compose) path plus the raw binary invocations. Add a CI guard: a job that `grep`s the Makefile for referenced paths and checks they exist (cheap, catches this exact drift).

### 2.10 P1 — The gRPC plane is plaintext everywhere; mTLS exists only in prose

**Evidence.** `cmd/server/main.go:303`:

```
grpcSrv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
// TLS terminated at LB in production; mTLS documented
```

No `tls.Config`, no `ClientCAs`, no `RequireAndVerifyClientCert` and no certificate verification hook exist anywhere in `internal/transport/grpc/` or `internal/ca/` (`internal/ca/ca.go` *issues* device certificates but nothing verifies them on the wire; `ParseCSR` exists at `agent_server.go:424`). Meanwhile `README.md:13,49`, `docs/ARCHITECTURE.md:14`, `docs/SECURITY-MODEL.md:7` and `docs/THREAT-MODEL.md:10` state or diagram "mTLS", and `docs/SPEC-COMPLIANCE.md:30` asserts a "mTLS device-cert verification hook is present (`CertAgentID`)" — that identifier does not exist in the codebase.

**Impact.** Two consequences. (a) Deployment guidance tells operators to point connectors at a **public** address (`AEGIS_CONNECTOR_PUBLIC_ADDR=aegis.example.com:9090` in the compose comments); without TLS termination at a load balancer that the operator must separately configure and that the product never documents in code, the connect token and connector secret travel in clear text — enough to enrol a rogue scanner/connector. (b) Documentation promises a security property the code does not implement, which is worse than silence for auditors.

**Fix.**
1. Add real TLS support: `AEGIS_GRPC_TLS_CERT/KEY` (+ optional `AEGIS_GRPC_CLIENT_CA` for mTLS), wired through `grpc.Creds(credentials.NewTLS(...))`; the CA and CSR machinery already exists, so verifying `ClientAuth: RequiresAndVerifyClientCert` against the device CA is a small step.
2. Until then, fail loudly: log a startup warning when gRPC is plaintext and `AEGIS_ENV=production`, and refuse to start unless `AEGIS_GRPC_ALLOW_INSECURE=true`.
3. Correct the documentation and remove the `CertAgentID` claim; state exactly what is and is not protected today (and reconcile with `docs/SPEC-COMPLIANCE.md:30`, which currently reads as an accepted assumption rather than a gap).

### 2.11 P1 — Access tokens are not revocable within their TTL

**Evidence.** `auth.Claims` carries `SessionID` (`internal/auth/password.go:69`, JSON `sid`) and the login handler stores it on the session row. The authentication middleware (`internal/transport/http/middleware.go:18-35`) validates the signature and audience and then trusts the claims for the rest of the request — it never checks the session row for revocation, disablement or role change. Logout/refresh-reuse revoke the *session*, not outstanding access JWTs.

**Impact.** After logout, password change, admin disable, or refresh-token reuse detection, the previously issued access JWT remains valid for up to `AEGIS_ACCESS_TOKEN_TTL` — default **1 hour** (`internal/config/config.go:152`). For an operator console with destructive capabilities (scans, deletes, credential entry), a 1-hour revocation window is long. `docs/SECURITY-MODEL.md` should also state this tradeoff explicitly rather than implying immediate effect.

**Fix (any of, in increasing cost).**
1. Shorten the default access TTL to 5–15 minutes (the refresh flow is already robust and the SPA already handles 401 → refresh single-flight), documenting the change in `docs/AUTH.md`.
2. Validate `sid` on each request against a small cache: Redis `SET session:<sid> <epoch>` refreshed on rotation, plus the existing `sessions` row as source of truth; reject requests whose `sid` is absent/revoked. The Redis client and `DedupCheck`-style helpers already exist.
3. For high-risk mutations (scan creation, asset delete, suppression, connector revoke), require a *fresh* token (`auth_time` claim older than N minutes → `401` with a step-up hint) — see §6.2.

### 2.12 P1 — Frontend data-correctness defects (details in §4)

Summarised here because they are functional, not cosmetic:

- **Filter-after-pagination.** `FindingsPage` opens on the "active" tab, sends `status: undefined` (the code comment admits "the backend has no negation filter, so fetch the page unfiltered and keep the resolved out client-side", `FindingsPage.tsx:51-58`) and then removes resolved/accepted/false-positive/suppressed rows *after* the server paginated — so a 50-row page can render 31 rows. Worse, the "active" count is read from a separate **unfiltered** `useFindings({site, limit: 1})` query and displayed as `activeTotal` (`FindingsPage.tsx:62-68`), i.e. the active counter shows the total number of findings of *every* status, and the severity chips are counted from another capped 200-row fetch (`FindingsPage.tsx:70-72`). The same anti-pattern appears in `ScansPage` (fetch `limit: 200` then filter/paginate client-side), `DetectionsPage` (server fetch without `status`, client filter), `EventsPage` (client filter over 200), `AssetsPage`/`VulnerabilitiesPage` facet counts.
- **Fake freshness.** `OverviewPage.tsx:116` renders `timeAgo(Date.now() - 45_000)` — a literal 45 000 ms offset, i.e. "45s ago" on every render forever.
- **Dead advertisement.** The command palette placeholder promises "Search assets, groups, pages, actions…" (`AppShell.tsx:215`) but only lists static actions, asset groups and pages; `useSearch` (`queries.ts:1460`), the hook behind the existing `GET /search` endpoint, has **zero callers**.
- **Per-keystroke server queries.** `VulnerabilitiesPage` binds the search box straight into `useVulnerabilities({search: q})`, and `useDebounced` (`components/ui/index.tsx:400`) has **zero callers** — every keystroke issues a request against the CVE index.
- **Contract mismatch.** `useAddNote` sends `{note}` where the server wants `{content}` (§2.7).
- **Unwired hooks.** `useDetectionRules`, `useCreateRule`, `useUpdateRule` (`queries.ts:988-1019`) exist with no consumer: there is no UI to author, test or toggle detection rules, even though the engine and CRUD endpoints ship.

---

## 3. Backend correctness, robustness and operational findings (P2/P3)

### 3.1 Scope validation is self-contradictory

`internal/scanning/scope.go` carries a `denylist` parameter through `ValidateScope` **that is never read**, and the private/public classification is written twice with identical bodies:

```
if allPrivate(...) { v.Private = allPrivate(...) } else { v.Private = allPrivate(...) }
```

The real denial filtering happens in a separate pass (`FilterDenied`, called from `Orchestrator.Create`), which is why the dead parameter and the duplicated branch were never noticed. The practical consequences:

- Validation **counts and warnings** (`v.Count`, "non-private targets" warnings, per-profile `maxTargets` checks) are computed *before* denylist filtering, so a scan whose targets are all denied still reports "N targets validated" and then fails later with "no targets remain after denylist filtering".
- Because the deny logic lives in two places, a future change to one path silently diverges.
- `FilterDenied` semantics are asymmetric: a CIDR is denied only when a deny network fully covers the target (`Contains`), whereas a bare IP is denied by exact/contained match — worth an explicit unit-test table so the intent is documented (e.g. `10.0.0.0/24` vs deny `10.0.0.0/25` = *not* denied).

**Fix.** Collapse into one function: `ValidateScope(ctx, orgID, targets, denylist, opts) (FilteredScope, error)` that (1) normalises, (2) applies the denylist first, (3) then classifies and counts, (4) returns both the accepted set and a structured rejection report (`{input, reason}`) that the API can echo to the user. Delete `FilterDenied` or make it the single implementation used by both callers. Add table-driven tests for the deny matrix, the 262 144-address ceiling, and the profile `max_targets` interaction.

### 3.2 SSH scans bypass scope validation entirely

`Orchestrator.Create` validates targets only for the `nmap` engine; an `ssh_inventory` profile accepts `ssh_hosts` from the request without consulting site networks, the org denylist or `AllowPublicScope`. This appears intentional (the operator supplies explicit credentials, so the host is deemed authorised), but it means a scope-policy control (denylist) can be violated by choosing the SSH engine, and the resulting scan is recorded with `targets` derived from `sshHosts`. **Recommendation:** still run `ssh_hosts` through the denylist (cheap, no false negatives), record the reason a host was accepted, and surface a warning in the create-scan response; document the deliberate difference in `docs/SCANNER.md`.

### 3.3 Silent simulated-engine fallback

`cmd/scanner/main.go` `pickEngine` falls back to the **simulated** engine when nmap is absent (warn log only, scanner continues). A scan then "succeeds" with fabricated observations: ports, services and findings that a user may act on. **Fix.** make it opt-in (`AEGIS_SCANNER_ALLOW_SIMULATED=true`) and *fail closed* otherwise; when simulation is allowed, record the engine on the scan/task rows and render a persistent "SIMULATED" badge in the UI and in reports (see §5.15). This is the single most dangerous "looks like it worked" failure mode in the product.

### 3.4 Scan pipeline details worth tightening

- `internal/scanexec/scan.go` calls `ScanPorts` with an always-empty port list (a config backfill masks it). It works today, but the call site is misleading and one refactor away from being a bug — either remove the parameter or pass the resolved profile ports.
- `portSpecArgs` precedence (explicit `-p` > `FullTCPPorts` `-p-` > `TopTCPPorts` > top-100) is correct but undocumented in `docs/SCANNER.md`; the UI never shows which port set a profile produced, so an operator cannot tell a 100-port scan from a full-range one without reading the profile editor.
- The `-sS` → `-sT` privilege fallback happens after a **non-zero exit**, and the retry is silent. Surface it as a scan warning/event (`scan.warning`) so the operator knows the scan degraded from SYN to connect scans (different timing/firewall behaviour).
- Port budget formula (`count / rate * 4 + 60 s`, clamped 2–25 min) should be logged with the resolved numbers; the kill-switch polling loop is 3 s, which is documented.
- `ScanRepo.UpdateState/SetError/SetKillSwitch` are correctly internal-only; keep them that way.

### 3.5 N+1 queries in hot read paths

`handleGetVuln` (`handlers_vulns.go:88-115`) lists findings for a CVE and then calls `Assets.ByID` **once per finding** to fetch the hostname — an N+1 that grows with the deployment's exposure (a widely-present CVE can be installed on thousands of assets). Replace with one join: `FindingRepo.ListForCVE` should return the asset hostname (it already joins assets in `findingJoins` for the list path). Apply the same review to `handleGetAsset`'s relation sections (seven sequential repository calls — parallelise with `errgroup` and a per-section timeout; the sections are already best-effort tolerated in the code).

### 3.6 Handler-level issues

| Where | Issue | Impact | Fix |
|---|---|---|---|
| `handlers_assets.go:573-576` | `Update` error is mapped to `404 "asset not found or update failed"`, hiding real database failures; the subsequent `ByID` error is discarded so the API can return `null` for a successful write | Operators see 404s during DB incidents; clients crash on `null` | Distinguish `pg.ErrNotFound` from other errors; re-read with `err != nil → 500` |
| `handlers_alerts.go:796` (`handleAlertsHealth`) | `Outbox.CountUnpublished(ctx)` is called **without** an organization argument, while `DeadCount` is org-scoped | The health endpoint leaks global outbox backlog/oldest-age (cross-tenant operational metadata) into every tenant's UI | Scope the count by org (add `organization_id` to the outbox query) or return it under an admin-only endpoint |
| `handlers_vulnsearch.go:23` | `handleVulnSearchCapabilities` has no permission check and probes `SELECT count(*)` against `osv_records`/`oval_records` | Minor information disclosure (whether another tenant's sync populated shared tables); inconsistent with the neighbouring handlers | Gate with `vuln:read`, and cache the availability flags per process instead of probing per request |
| `handlers_vulns.go:240` | Suppress handler: see §2.5 | — | — |
| `handlers_core.go:246` | Notes: see §2.7 | — | — |
| `handlers_core.go:269` (`handleMetricsSummary`) | Severity counters (`critical/high/medium/low`) are tallied over a **capped 200-row** findings list, while the `vulnerabilities` number uses the true total; asset count is also capped at 200 | With >200 open findings the dashboard under-reports severity, contradicting the same page's own total | Use the existing aggregation query (`FindingRepo.OpenSeverityByOrg` already does a `GROUP BY`) for the counters, and `COUNT(*)`/`COUNT(DISTINCT)` for assets |
| `middleware.go:360-383` (`handleMe`) | The response mixes fresh and stale data: `organizations[].role` is read from the database per membership, but the top-level `permissions` list is `auth.PermissionsFor(claims.Role)` — the **JWT role claim** — directly underneath a comment that says permissions are "derived server-side from the CURRENT role (never from the stale JWT permission claim)" | After a role change, `permissions` (and therefore any permission-aware UI built on it, §5.15) is stale until the access token refreshes — up to 1 h by default (§2.11) — while `organizations[].role` already reflects the new role, leaving the payload internally inconsistent | Derive `permissions` from the freshly read role for `claims.OrganizationID` (one extra `RoleFor` call, or reuse the value already in the loop) and keep the comment honest |
| `handlers_scans.go` (schedules) | Schedule creation validates the profile against `domain.Profiles` (built-ins) only, while `CreateScan` resolves custom presets via `Profiles.Resolve` | A user who schedules a *custom* profile gets rejected at schedule-create time but accepted at scan-create time — confusing and asymmetric | Use the same resolver in both paths |
| `internal/platform/objectstore.go:114`, `internal/repository/postgres/repo_assets.go:713`, `repo_tenancy.go:602`, `handlers_agents.go:200`, `handlers_core.go:432`, `handlers_events.go:241`, `middleware.go:396`, `server.go:457` | Eight `var _ = <pkg>.<Name>` statements that exist only to keep imports alive | Dead code that signals unfinished refactors and defeats `unused` linters | Delete the import and the statement or use the symbol |
| `middleware.go:24`, `handlers_ws.go:52` | `auth.NewTokenIssuer(...)` is allocated on **every authenticated request** (HTTP and WS) | Small but needless allocation churn on the hottest path; also duplicates TTL config reading | Build one issuer at app construction and store it on `App`/`Services` |
| `handlers_core.go` (`handleLogin`) | Picks `orgs[0]` as the session organization and substitutes the **nil UUID** for users with no membership; role/perms are derived from that single membership | Multi-org users cannot choose an org at login (and cannot switch without re-login); org-less users get a session bound to a nil UUID that bypasses "must have an org" assumptions downstream | Add an explicit org selector on login (or a `POST /auth/switch-org` that re-issues the session), and reject org-less sessions with a clear 403 unless they are system administrators |
| `handlers_core.go:48` (`handleListOrgs`) | A user whose **current** role is `owner` receives **every organization in the database** (`Orgs.List`), not just memberships | Organization names/slugs (metadata) of unrelated tenants leak to any user who is owner of *any* org; in a multi-tenant deployment with per-org ownership this is wrong | Return memberships only; expose a separate, explicitly platform-scoped "all organizations" view for a genuine super-admin role (see §6.16) |

### 3.7 Error handling, silent degradation, observability

- `listOrEmpty` (`handlers_assets.go:466`) converts *any* repository error into an empty list. For `GET /assets/{id}` this means a database hiccup renders as "this asset has no services / no findings" — the most misleading possible failure mode for a security tool. Best-effort sections are a good idea, but the response must carry a per-section status (e.g. `sections: {services: "ok"|"error"}`) or at minimum log at `warn` with the asset id. Same pattern in `handleGetAsset`'s five sections and in `handleAssetTraces`.
- `handleReadyz` (§2.4) and the worker's `/readyz` disagree on status-code semantics.
- `handleListEvents` defaults `from` to `now-24h` server-side and the UI's "Pause live"/"Resume live" only triggers a single refetch (`EventsPage.tsx:27-33`), and `useEvents` (`queries.ts:1026-1038`) sets no `refetchInterval`, so "Resume live" does not actually resume updates — the list stays frozen until navigation or a manual reload. Either wire the WS notification channel for events or set a refetch interval while `live === true`.
- Audit entries are written with `c.IP()`, which §2.3 shows is attacker-controlled; several failure paths also record no actor (by design for failed logins).
- Metrics/OTel hooks exist (`internal/observability`) but there is no SLO/error dashboard definition in `deploy/` (Prometheus is an optional compose profile with a single default scrape config).

### 3.8 Data model and database findings

- **No row-level security anywhere.** A grep for `POLICY` across `migrations/postgres/` returns nothing. Every isolation guarantee in the product is therefore a property of hand-written SQL. Given §2.1/§2.2, RLS with a per-request `app.current_org` GUC plus a non-superuser application role is the highest-leverage structural fix available (see §6.21).
- **Suppression rows can be all-NULL** (§2.5) — add a CHECK constraint (`vulnerability IS NOT NULL OR asset_id IS NOT NULL`) so the database itself refuses a scope-less suppression.
- **Notes have no read endpoint** and no uniqueness/limits beyond the model; if kept, add `GET /assets/:id/notes` and an index on `(entity, entity_id, created_at)`.
- Session retired-hash ledger is capped at 200 entries / 1 h (`docs/AUTH.md`), which is sensible; document what happens under a token-replay storm (oldest entries drop out of the grace ledger, which correctly turns into a hard failure rather than a silent success).
- `migrations/` are paired (CI enforces `.up`/`.down`), but nothing enforces **reversibility content** (a `.down.sql` that only drops a column while the `.up.sql` created three). Consider a migration-drill job (§7) that applies up → down → up against a throwaway database.
- `nilUUID` sessions (§3.6) create rows whose `organization_id` matches no organization — any join on organizations silently yields empty sets instead of failing loudly. Add a FK or a constraint if the model allows it.

### 3.9 Reports and the PDF writer

`internal/reports/generator.go` uses `html/template` (auto-escaped — correct, and the XSS sweep found no `template.HTML` anywhere). `internal/reports/pdf.go` is a self-contained PDF 1.4 writer with WinAnsi fallback: no external binary, which is a deliberate and good choice for air-gapped deployments, but it caps typography (no Unicode beyond WinAnsi — CJK/Cyrillic text degrades to `?`; no images/logos/embedded fonts; tables drawn manually). Two consequences worth planning for: (a) brand/logo support is a common procurement requirement — see §6.11; (b) long report jobs should stream pages rather than build one in-memory buffer (verify peak memory with a large estate; a 20 000-finding technical report is plausible).

### 3.10 Alerts engine observations

The alerting stack is the strongest part of the backend (transactional outbox, idempotent occurrence keys, `FOR UPDATE SKIP LOCKED` claiming, bounded delivery with backoff and DLQ, SSRF-guarded webhook URLs with HMAC). Two gaps: the detections engine never emits into it (§2.6), and `CountUnpublished` is not org-scoped (§3.6). Additionally, `handleAlertsHealth` reports `"evaluator": "worker"` as a hard-coded string — it should be real liveness (last evaluation timestamp per org), otherwise the UI's health strip is decorative.

### 3.11 CI/CD pipeline gaps

| Area | Current state (`.github/workflows/ci.yml`) | Gap |
|---|---|---|
| Go tests | `go test ./... -short` | No `-race`, no integration tests, no coverage floor; the `-short` suite cannot cover repositories, migrations or the scan pipeline |
| Frontend tests | `npm ci && npm run build` only | **Neither Vitest (11 spec files) nor Playwright (`web/tests/redesign.spec.ts`, a full mocked-API UI suite) is executed** — the most valuable frontend asset is dead weight in CI |
| Docker | builds the server image | worker/scanner/frontend/connector images are never built in CI, so a broken Dockerfile ships until release |
| Swagger | `swagger-staleness` job marked `continue-on-error` (placeholder) | No annotations exist in the code (`grep -rn "swagger" internal/ cmd/` → nothing) and there is **no `make swagger` target**, yet `docs/API.md`, the Helm NOTES and `docs/SPEC-COMPLIANCE.md` advertise `/swagger/index.html` |
| Manifest validation | none | Broken Helm/K8s manifests pass CI silently (§2.8). Add `helm template`/`helm lint` + `kubeconform`/`--dry-run=client` |
| Supply chain | none | No SBOM, no image scanning (trivy/grype), no signing (cosign), no dependency review on PRs |
| Lint | `gofmt -l` + `go vet` | `golangci-lint` is optional/local only (`.golangci.yml` exists); frontend ESLint/`tsc` runs only as part of `npm run build` (`tsc -b`) |
| Migration pairing | up/down presence check (good) | No apply/rollback drill against a real Postgres service container |

### 3.12 Deployment defaults that are safe in a demo and unsafe in production

`deploy/compose/docker-compose.yml` is an excellent zero-config demo: `AEGIS_DEMO_MODE=true`, `AEGIS_JWT_SECRET=change-me-32-bytes-min-secret-key`, `admin@aegis.local / aegis-demo-admin-2026`, `AEGIS_COOKIE_SECURE=false`, S3 creds `aegis-secret-change-me`, ports published on the host. That is fine *because* the stack also prints the credentials on `make dev`. The risk is drift: nothing in the runtime refuses to start with these values in a production profile, and the Helm/K8s path (which does not set `DEMO_MODE`) still ships `jwtSecret: change-me` in `values.yaml`. Recommended guardrails:

1. On boot, if `AEGIS_ENV=production` and (`DEMO_MODE=true` or the JWT secret matches a known demo value or the bootstrap admin password is the demo one), **refuse to start** with an explicit error listing the offending variables.
2. Add `AEGIS_COOKIE_SECURE=true` and `AEGIS_PUBLIC_URL` guidance to the K8s ConfigMap (a `Secure`-flagged `__Host-` cookie is already implemented in code but only activates when the deployment says so).
3. Remove the `jwtSecret`/`bootstrapAdminPassword` placeholders from `values.yaml` and use `required` in the template so Helm fails with a readable message rather than deploying `change-me`.
4. Publish the compose file's host ports on `127.0.0.1` by default (the data layer already does this; the API on `8080` does not) and document how to expose it behind the bundled nginx.
5. Scanner capabilities are handled well (NET_RAW only, `no-new-privileges`, explicit "never privileged" comments) — extend the same rigour to the frontend container (add `readOnlyRootFilesystem`, `runAsNonRoot`, dropped caps) and to a `securityContext` for every workload.

### 3.13 Documentation drift (docs assert things the code does not do)

| Document claim | Reality | Action |
|---|---|---|
| `docs/SPEC-COMPLIANCE.md:19-22` — UI lives in `web/src/features/{assets,findings,scans,dashboard}` | There is no `web/src/features/` directory; pages live in `web/src/pages/` | Update the map |
| `docs/SPEC-COMPLIANCE.md:30`, README, ARCHITECTURE, SECURITY-MODEL, THREAT-MODEL — "mTLS", "`CertAgentID` verification hook" | Plaintext gRPC (`insecure.NewCredentials()`); `CertAgentID` does not exist in the codebase | Fix code (§2.10) then docs |
| `docs/SPEC-COMPLIANCE.md:24`, `docs/API.md:66`, Helm `NOTES.txt` — Swagger annotations on every handler, `make swagger`, `/swagger/index.html` | No annotations, no Makefile target, no route serving Swagger UI | Either implement (recommended, §6.21) or delete the claims |
| `README.md:17`, `docs/DEVELOPMENT.md:58` — keyboard chords `g a`, `g s`, `g v`, `g e` | The shell implements ⌘K and `[` (sidebar) only; no `g`-chord handling exists | Implement (§5.14) or remove the claim |
| `docs/DEVELOPMENT.md` — `./scripts/dev.sh`, `make e2e`, `make seed`, `make migrate-*` | `scripts/` is not tracked in git (§2.9) | Commit or rewrite |
| `deploy/compose/README.md:73` — "see `configs/suricata`, `configs/zeek`" | `configs/` contains only `agent.example.yaml`, `feed-worker.yaml`, `scanner.yaml`, `server.yaml`, `worker.yaml` | Add the files or fix the reference |
| `docs/SPEC-COMPLIANCE.md` — "Windows/macOS agent collectors: stdlib basics" | Accurate per the code; keep, but surface per-OS capability in the UI (§6.10) |
| `deploy/helm/aegis` presented as a usable deployment path (README "Kubernetes/Helm deployments") | Chart does not render (§2.8) | Fix or mark experimental in README |
| `docs/API.md` — CI "generated docs served when `swag` output is committed by CI" | The CI job is a `continue-on-error` placeholder | Same as Swagger row |

A practical guard: add a docs-lint CI job that extracts backticked paths from `docs/*.md`/`README.md` and fails when a referenced file does not exist (this review found 4 such references automatically in minutes). Command-shaped claims (`make <target>`) can be checked the same way against the Makefile.

### 3.14 Permission-model inconsistencies (authenticated ≠ authorised)

Every `/api/v1` route below the auth middleware requires a valid access token, but only a subset then checks a *permission*. Two of the gaps are functional defects rather than hardening opportunities:

- **Telemetry ingestion is gated by a read permission.** `POST /events` (`handlers_events.go:197`) and `POST /sensors/{sensorID}/events` (`handlers_events.go:218`) both call `requirePerm(c, domain.PermEventRead)`. Any role that can *read* events can therefore *push* them — injecting synthetic sensor telemetry that flows into detections, alert triggers and the audit record. Ingestion must require a write permission (`event:write`, granted to analyst/operator) or sensor-scoped credentials issued per sensor; `POST /sensors/{id}/events` in particular should authenticate the sensor, not a human session.
- **`handleAddNote` has no check at all** (§2.7).

The remaining ungated routes (Appendix A) are defensible as "org-scoped reads", but the pattern is fragile: authorisation is a per-handler convention with no structural guarantee. Recommended enforcement: declare required permissions in the route table itself (a struct per route with `Perm domain.Permission` or `OrgScopedOnly bool`) and add a test that walks the route table and fails when an entry declares neither. That converts "remember to call `requirePerm`" into "the test tells you what you forgot" — and it makes the security posture reviewable in one screen.

---

## 4. Frontend correctness findings

### 4.1 Filter-after-pagination (data correctness)

| Page | Behaviour | Correct behaviour |
|---|---|---|
| **Findings** (`FindingsPage.tsx:51-72`) | "Active" tab sends no `status` filter (the comment in the code says the backend cannot express it); the client strips resolved/accepted/false-positive/suppressed rows after server pagination, the "active" total is actually the **unfiltered** total from a separate `limit: 1` query, and severity chips count a capped 200-row fetch | Add server-side multi-status/negation filtering (`status_in=…`, `status_not_in=…` or `active=true`), take `total` from the same response, and compute facets with a `GROUP BY` endpoint (or a single query returning counts) |
| **Scans** (`ScansPage.tsx`) | Fetches `limit: 200` and filters state/engine/search + paginates client-side | Server filters + server pagination (the endpoint already supports `state`, `site`, page/limit) |
| **Detections** (`DetectionsPage.tsx`) | Fetches matches without `status`, filters severity/status/search client-side over the first 200 | Pass `status`/`severity`/`q` to the API; add `q` to `handleListMatches` if missing |
| **Events** (`EventsPage.tsx`) | 200-row cursor page, client search over message/srcIp/meta | Server-side search parameter (ClickHouse filter already supports several fields), and a real "live" mode |
| **Assets / Vulnerabilities** | Facet/KPI tiles fire extra `limit: 200`/`limit: 1` queries to synthesise counts (e.g. `useVulnerabilities({kev: true, limit: 1})`, `useAssets({limit: 200})`) | Extend `/metrics/summary` (or add `/vulnerabilities/facets`) to return all counts in one cheap aggregate query |
| **Overview** | Three sources of aggregation: assets `limit: 200`, findings `limit: 200`, detections `limit: 50` | Prefer server aggregates; keep the capped fetch only for the "recent activity" strip |

Why this matters beyond correctness: the silent truncation means a security team can look at "Active findings: 38" when the estate has 400, and a page that shows 31 rows looks like a rendering bug. These are the kinds of defects that cause operators to distrust the tool.

### 4.2 Counts and freshness that lie

- `OverviewPage.tsx:116` — the "updated 45s ago" chip is `timeAgo(Date.now() - 45_000)`, i.e. **always** 45 seconds. Replace with the newest `dataUpdatedAt` across the queries backing the cards (`useQueryClient`/`query.state.dataUpdatedAt`) and render a real relative time + "Refresh" affordance.
- `AppShell.tsx:64-78` (`useNavCounts`) — sidebar badges derive `scans` from `items.length` of a `state=running&limit=50` page and `connections` from a client-side filter over the full connector list; both are page-scoped approximations presented as totals.
- `useMetricsSummary` is polled from the shell on every page; the KPI numbers shift while the user reads them, with no visual indication that a refresh occurred (no skeleton, no "updating" state). Prefer `keepPreviousData` + a subtle updating indicator.

### 4.3 Unwired hooks and dead client code

| Symbol | Status | Recommended action |
|---|---|---|
| `useDebounced` (`components/ui/index.tsx:400`) | 0 callers | Apply to the three server-search inputs (Vulnerabilities, Assets, Findings) — see §4.1; it exists precisely for this |
| `useSearch` (`queries.ts:1460`) | 0 callers; `GET /search` endpoint unused by the UI | Wire into the command palette (see §6.20) or delete both |
| `useDetectionRules`/`useCreateRule`/`useUpdateRule` (`queries.ts:988-1019`) | 0 callers; no rule-authoring UI | Build the rules UI (§6.9) or delete the hooks until then |
| `useAddNote` (`queries.ts:1407`) + `const addNote = useAddNote()` (`AssetDetailPage.tsx:98`) | Unused; payload contract is wrong anyway | Fix or delete (§2.7) |
| `web/src/components/table/DataTable.tsx` + the legacy kit (`components/ui/index.tsx`) | Only 5 files import the legacy kit (`DataTable`, `charts/Chart`, `alerts/{DestinationManager,TriggerList}`, `vulns/SearchActions`); `DataTable` itself is used only by those | Migrate the five consumers to the modern kit, then delete the legacy module and its tokens |
| `web/tailwind.config.ts` | v3-syntax config (content globs, hex palette) while the project is Tailwind v4 with the theme in `src/index.css` `@theme`; no `@config` directive references it | Delete it — it is dead configuration that will confuse the next contributor |
| `severityMeta`/`severityOrder`/badge components | Duplicated between `components/shared.tsx` and the legacy kit | Keep one source of truth (§5.13) |

### 4.4 Two design systems and two charting libraries

- **Component kits:** `components/ui/*` (shadcn-style, Radix-based, Tailwind v4 tokens — the modern generation) and `components/ui/index.tsx` (custom token names `bg-bg-panel`, `border-line`, `text-fg-dim`, `rounded-sm2`/`md2`, its own `Button/Badge/Pill/StatusPill/Meter/MiniBars/KPICard/Pagination/Dialog/Tabs`…). Both are live; the legacy kit also carries a hand-rolled `Dialog` with no focus trap, whereas the modern kit uses Radix Dialog (focus management, scroll lock, aria wiring). Visual drift is already visible (radii, spacing, colour sources) and duplicated semantics (two `SeverityBadge`s, two `StatusPill`/`Badge`s, two `EmptyState`s).
- **Charts:** `recharts` is used **only** by `OverviewPage`, while `echarts` (with a shared dark theme in `components/charts`) powers every other chart. Both libraries ship in the initial bundle (measure the exact cost with `vite-bundle-visualizer`; the overlap is several hundred kB of source), two tooltip/legend styles coexist, and theming changes must be made twice.
- **Recommendation:** finish the migration (one kit, one chart library — echarts, since it already owns the shared theme, sparklines and the topology overlays), delete the legacy module and the recharts dependency, and add a lint rule/CI grep that fails when the legacy kit is imported again.

### 4.5 Loading, empty and error states

- **No page renders `ErrorState`** (0 occurrences across `src/pages/*`). Combined with §3.7's `listOrEmpty` behaviour and TanStack Query defaults (`retry: 1`), a failed request typically renders as an **empty state** — e.g. "No findings match. Adjust the filters…" when the API is down. This is the single most damaging UX defect in the app: it converts an outage into a false negative.
- **No skeletons anywhere** (`Skeleton` count = 0 across pages), and page-level loading flags are sparse: Findings 0, Assets 0, Events 0, Vulnerabilities 0, Overview 0, Detections 0, Reports 0, Scans 0; only Settings (11), AssetDetail (6), Connections (3), Alerts/Topology (2 each) reference `isLoading/isPending/isFetching`. Tables therefore appear empty for a moment on every navigation — indistinguishable from "no data".
- **Mutation feedback** is generally good: toasts are used 33× in Settings, 10× in Connections, 7× in AssetDetail, 4-5× elsewhere; two pages (Detections, Alerts) have almost none and rely on optimistic row updates.
- Duplicate-empty-state inconsistency: some pages render `EmptyState` inside a `TableCell` with `colSpan`, others as a standalone panel.

**Fix (pattern).** Introduce a small `<QueryBoundary query={q} skeleton={<TableSkeleton rows={8}/>} empty={…}>{children}</QueryBoundary>` and adopt it on every list/detail view; extend `ErrorState` with `onRetry` (invalidate the query) and a correlation id from `request_id`. Then write a Vitest/MSW test asserting that a 500 renders the error state, not the empty state.

### 4.6 Accessibility

| Issue | Evidence | Fix |
|---|---|---|
| Clickable table rows are not operable by keyboard and expose no role/name | 5 pages: `FindingsPage.tsx:165`, `AssetsPage.tsx:422`, `VulnerabilitiesPage.tsx:220`, `ScansPage.tsx:249` (plus detections list) use `<TableRow onClick>` with no `tabIndex`, `role`, or `onKeyDown` | Render a focusable inner element (the primary cell as a link/button) or add `role="button" tabIndex={0}` + Enter/Space handling; prefer real `<a href="#/assets/id">` so middle-click/copy-link work |
| Toast dismiss button has no accessible name | `components/ui/toaster.tsx:84` — `<button onClick={dismiss}><X/></button>` | `aria-label="Dismiss notification"` |
| Custom `Dialog` has no focus trap/Escape/`aria-labelledby` | `components/ui/index.tsx:247-259` — only a click-outside handler and `aria-label` | Use Radix Dialog (already a dependency) or add focus management |
| Live regions are rare | 5 `aria-live`, 18 `role=`, 6 pages with any `aria-label`; scan progress/log panels update without announcements | Add `aria-live="polite"` to scan progress/state badges and alert counters; ensure the log panel does not announce every line (use a summary region) |
| Keyboard shortcuts are undocumented and inconsistent | `/` focuses search only on Topology; `[` toggles the sidebar globally; ⌘K opens the palette; `?`/shortcut help does not exist; docs promise `g`-chords | Add a `?` shortcut sheet, implement the documented chords (or delete them from docs), and make `/` work on every list page |
| Colour-only severity encoding | Severity is colour + text in most places (good), but chart series and topology edges rely on colour alone | Add pattern/shape or labels to chart series; provide a legend with text |
| Focus visibility | Global `outline-none` patterns exist in the theme; focus rings are inconsistent across the two kits | Standardise a visible `:focus-visible` ring token |

Add an automated accessibility gate (axe-core via Playwright, or `@axe-core/react` in Vitest) on the main pages; today nothing measures this.

### 4.7 Responsiveness and layout

- The shell always reserves the sidebar (`RAIL=56`/`FULL=244`, `Sidebar.tsx:22-23`, `AppShell.tsx:301`); there is **no mobile drawer** and no breakpoint that hides it. On a 768 px tablet the content column is effectively ~530 px; on a phone (375 px) it is ~130 px. Collapsing is manual (`[`) or via a toggle — an operator on a tablet cannot reach the table columns comfortably.
- Responsive-prefix usage is very low for the size of the app: 97 occurrences across ~8 600 lines, distributed as Settings 11, Overview 9, Detections 6, Alerts/Vulnerabilities 4, Assets/Events/Scans 3, Findings 2, Connections/Reports/Topology **1 each**.
- Tables do scroll horizontally (the `Table` primitive wraps in `overflow-x-auto`) — good — but per-row actions, dialogs (`sm:max-w-2xl`) and multi-column filter bars assume a wide viewport; the detail Sheets/panels are full-height overlays that work poorly under ~900 px.
- The footer status strip hides its right-hand text below `sm` (good) but keeps three live indicators; on narrow screens they wrap awkwardly.

**Recommendation:** treat 1280 px as the design target but make 768 px usable (off-canvas sidebar + a "filter drawer"), and validate the six highest-traffic pages (Overview, Assets, Asset detail, Findings, Scans, Alerts) at 375/768/1280 in the Playwright suite with screenshots.

### 4.8 Realtime/WebSocket

- The WS handshake carries the access JWT in the **query string** (`?access_token=…`, documented in `handlers_ws.go` and `ws.ts`). Query strings are recorded by reverse proxies, CDNs, browser history and server access logs; with a 1-hour default TTL this is a real credential-disclosure path. Prefer a short-lived, single-use ticket (`POST /api/v1/ws/ticket` → 30 s opaque token) or the `Sec-WebSocket-Protocol` subprotocol header, which browsers can set and servers can validate.
- The client is well-built (single socket, ≤32 channels, exponential backoff 0.5→15 s with jitter, re-subscription, 25 s ping, 90 s server read deadline, polling fallbacks). Two gaps: on reconnect there is no "catch-up" for `state` events missed while disconnected (the scans page relies on a refetch, which is fine but undocumented), and the notify channel drives toasts — those should respect a per-user quiet mode (§6.19).

### 4.9 Frontend performance

- **No route-level code splitting.** No `React.lazy`/dynamic import anywhere; every page, both chart libraries and every component load in the initial bundle. `vite build` should be measured (§8) and the routes split (`lazy(() => import('@/pages/TopologyPage'))`), which also removes recharts/echarts from the critical path for non-chart pages.
- **Shell-wide polling fan-out.** `useNavCounts` alone mounts `useMetricsSummary`, `useScans(state=running, limit=50)`, `useDetectionMatches(limit=1)`, `useAlertOccurrences(limit=1)`, `useConnections()` (full list) and `useAssetGroups()`; on top of that the shell polls feeds and the active page runs its own queries with 10–30 s refetch intervals (9 intervals in `queries.ts`). Every tab in every page keeps 6+ background requests alive. Consolidate: one `/api/v1/nav-counts` endpoint (single query, single interval), or `staleTime`-aware intervals with visibility pauses (`refetchIntervalInBackground: false` is the default, but background tabs still poll when visible).
- **Oversized components.** `AssetDetailPage.tsx` is 1 915 lines, `SettingsPage.tsx` 1 549, `TopologyPage.tsx` 961. AssetDetailPage alone holds tab state, metrics preferences, topology panel, findings/details, notes and forms. Split into tab-level components with their own queries; this unlocks lazy loading, testing and parallel work.
- **Client-side pagination re-fetch.** `usePagination` (`components/shared.tsx:508`) slices an already-fetched array while the underlying `useAssets({limit: 200})`/`useScans({limit: 200})` refetch whole pages on invalidation; combined with §4.1 this is both a correctness and bandwidth issue.

### 4.10 Small consistency defects

- Two `Severity`/`Exposure`/`Criticality` colour maps (`data/types.ts` + `components/shared.tsx`) with different hex values (e.g. severity colours diverge from the chart theme), so the same "critical" is two different reds.
- Date/number formatting is centralised in `lib/format.ts`/`lib/utils.ts` — good — but several pages still hand-roll `new Date(...).toLocaleString()` and `tabular` alignment is applied inconsistently to numeric columns.
- `Mono`/`KeyValue`/`Kbd` helpers exist but card headers, detail rows and table footers each have a slightly different implementation (`TableFooterBar` vs `Pagination` vs `TableFooter`).
- Empty-string vs missing values: `asset.notes ?? "—"` renders an em-dash in some places and nothing in others.
- `Toaster` caps at 4 items and 3.8 s; destructive-action confirmations rely on `ConfirmDialog` in some flows and on inline confirm state in others (e.g. suppress) — unify on one confirmation primitive.

---

## 5. UI/UX review by area

Overall the console has a coherent identity — dark-first, dense, KPI-led, with a strong information hierarchy on the pages that have been finished. The problems are concentrated in *state handling*, *navigation depth*, *permission awareness*, *mobile*, and the residue of the partially-completed redesign.

### 5.1 Global shell, navigation and information architecture

**Works:** persistent scope selector (site), live nav counts, collapsible rail with smooth width transition (real layout space, no overlap), status footer (scanner / feed sync / contextual slot), ⌘K palette, breadcrumbs, avatar menu, `BroadcastChannel` session sync across tabs.

**Problems**
- **14 destinations in 4 groups with no search inside the nav.** Topology, Detections and Events are peers of Assets/Findings but are used far less; the sidebar badge counts are approximations (§4.2), which erodes trust in the only at-a-glance signal.
- **No mobile/tablet navigation** (§4.7).
- **Empty command palette promise:** placeholder text advertises asset search that does not exist (§4.3), and the palette cannot reach entities (only pages/groups).
- **Footer claims are static:** "scanner-local" is hard-coded (`AppShell.tsx:310`), not the actual healthiest scanner; "feeds synced <relative>" is real, but the third slot is per-page.
- **No org switcher** even though the API supports multiple memberships (§3.6); multi-org users must log out.
- **No keyboard-shortcut discoverability** (no `?` sheet), and the two implemented shortcuts are undiscoverable.

**Improve to**
1. Reduce top-level nav to 6–7 items with grouped fly-outs (Inventory: Assets/Topology/Groups; Assess: Scans/Findings/Vulnerabilities; Detect: Detections/Events/Alerts/Sensors; Operate: Connections/Reports/Settings) and let power users pin items.
2. Replace static footer strings with live status popovers (scanner fleet health, feed freshness, worker/evaluator heartbeat).
3. Add an org switcher in the sidebar header (calls a new `POST /auth/switch-org`), showing the active org in the browser tab title.
4. Add a `?` shortcut sheet listing all shortcuts, and make the palette search entities (assets, findings, CVEs, connectors) — see §6.20.

### 5.2 Overview / dashboard

**Works:** KPI tiles read well, the risk-trend and severity donut communicate posture quickly, the "act on this" tile wording (`onClick` into the filtered list) is a good pattern.

**Problems**
- **Fake freshness chip** (§4.2) — the most visible trust defect on the first screen.
- **Aggregations from capped lists** (§4.1): every number is computed from at most 200 assets/findings, so a 5 000-asset estate sees an understated posture with no indication of truncation.
- **No time-range control, no drill-down from charts** (clicking the donut does nothing), no "compare to last week", no saved layout.
- **Charts are a third-party grab bag:** the overview uses recharts while the rest of the app uses echarts, so tooltips, legends, fonts and colour usage differ within one click of each other (§4.4).
- **No "what changed" panel** (new assets, new criticals, resolved findings, feed sync) even though the API exposes events, change history and metrics timeseries.

**Improve to**
1. Server-side aggregate endpoint for all tiles + charts (one request, one cache entry), with a visible "as of HH:MM:SS" from `dataUpdatedAt` and a manual refresh.
2. Add a "Since you were last here" strip driven by `/metrics/timeseries` and `asset changes` (new assets, new criticals, resolved, feed syncs) with per-item links.
3. Make every chart element clickable into the corresponding filtered list; add a time-range selector (24 h / 7 d / 30 d) that also persists per user.
4. Converge on the echarts theme and delete recharts.

### 5.3 Assets list

**Works:** column chooser with persistence and order healing (`aegis.assets.columns.v2`), sortable columns, multi-select for bulk actions, group filter, CSV-ish density, type icons, risk meters.

**Problems**
- **No loading or error state** (§4.5); on a slow network the table looks empty.
- **No filters persisted in the URL** beyond group/target, so a shared link does not reproduce the analyst's view; the docs claim URL-persisted filters.
- **No bulk edit** for the fields that matter most operationally (owner, criticality, tags, group membership) — only per-row editing via the detail page.
- Selecting rows and scrolling loses the selection affordance (the action bar is not sticky).
- The empty state says "Adjust the filters" but offers no one-click reset.

**Improve to:** URL-serialize every filter/sort/page (single `useTableState` hook), sticky bulk-action bar with count + "clear selection", bulk edit drawer (owner/tags/criticality/groups), server pagination + accurate total, skeleton rows, error state with retry, one-click "reset filters".

### 5.4 Asset detail

**Works:** excellent depth (identity, identifiers with weights, interfaces, services, software, findings, traces, timeline, endpoint metrics, topology panel, overrides, tags/notes) and the provenance-first presentation (source badges, confidence, first/last seen) is exactly right for a security tool.

**Problems**
- **1 915 lines / one route** — the page loads every tab's data eagerly (metrics, traces, findings, groups, agents) which makes the first paint slow and the code hard to change (§4.9).
- **Tabs are not URL-addressable** in all cases, so "the SSH software tab of asset X" cannot be shared/deep-linked reliably; conversely `?focus=` is used for topology only.
- **Editing affordances are inconsistent:** tags/notes live in a dialog, overrides in another, criticality/exposure inline — three interaction models for one concept ("analyst corrections").
- **Endpoint metrics require a bound connector**; when none is bound the section renders an empty chart rather than an explanatory "bind an agent to collect performance metrics" call-to-action with a link to Connections.
- **Destructive actions** (rediscover, delete) are separated from the rest of the header and lack a consequences summary ("this deletes N findings, N services, N software records").

**Improve to:** split into tab components with per-tab queries + `React.lazy`; URL-sync the active tab and sub-selections (`?tab=software&q=openssl`); unify corrections in a single "Edit" drawer grouped by scanned vs analyst override with a visible "revert to scanned" affordance; add a delete confirmation that enumerates cascade counts fetched from the server; replace empty chart states with guidance CTAs.

### 5.5 Findings

**Works:** severity chips, a detail sheet with status/history handling, suppress/acknowledge flows with reasons, bulk selection (the backend enforces confirmation for dangerous bulk ops), asset/CVE cross-links.

**Problems**
- **The "Active" tab is a lie** (§4.1): the count and the rows disagree with the server.
- **Facet counts are fetched with a separate 200-row query** and can disagree with the list length.
- **Triage loop is incomplete:** no owner assignment from the list, no due dates/SLA, no "next / previous finding" navigation inside the detail sheet, no keyboard-driven triage (j/k, x to select, s to suppress) even though the product markets keyboard-driven operation.
- **Notes thread is unavailable** (§2.7) — analysts cannot leave context on a finding.
- **No saved views** ("my criticals", "unassigned >7 days") and no export.

**Improve to:** server-side status/owner/severity filters + accurate totals; a triage mode with keyboard shortcuts and an inline detail pane (list-detail instead of sheet); owner + due date + SLA fields on the finding model with an "overdue" view; a comments/activity thread (reuse the notes model properly); saved views with URL persistence; CSV/JSON export of the current view (§6.5); risk-acceptance with expiry and approvals (§6.4).

### 5.6 Vulnerabilities (CVE index)

**Works:** KEV/EPSS framing ("prioritise by KEV and EPSS, not CVSS alone"), server-side sort/window, CVE detail with affected assets, search actions workbench (shadow/augment/fallback modes), diagnostics surface.

**Problems**
- **Per-keystroke search** (§4.3) hammers the index; no debounce, no "searching…" indicator.
- **KPI tiles fire three separate queries** (index size via `limit: 1`, KEV via `limit: 1`, open findings via metrics) — three round-trips for three numbers.
- The **detail view is a sheet**, which truncates long CVE descriptions and reference lists; there is no "open as page" for linkability.
- **Search actions are an expert-only surface:** modes, fields and operators are exposed raw with no templates, no dry-run diff visualisation beyond preview, and no indication of what "augment" changes in existing findings.
- No watchlist/subscription ("tell me when this product gets a new CVE") and no vendor/advisory enrichment beyond NVD/KEV/EPSS/OSV.

**Improve to:** debounce + server-driven facets in one query; deep-linkable CVE pages (`#/vulnerabilities/{cve}`) with the sheet as a quick-peek only; guided "search action" builder with templates (vendor/product/ecosystem), a preview diff (findings added/changed) and a rollback; watchlists with digests (§6.7).

### 5.7 Scans

**Works:** status strip, live job log with history paging and WS tail, per-scan stats, cancel/kill-switch, schedules inline in the create dialog, engine/state filters, copyable CLI preview of the equivalent nmap command (a genuinely nice touch for operator trust).

**Problems**
- **Client-side filtering over a 200-row fetch** (§4.1) with `usePagination` — the count in the strip and the table contents can disagree.
- **The log panel is a raw firehose** with no level filter shortcuts, no search, no "jump to latest" affordance after scrolling up, and no download.
- **Schedules cannot be managed** — `useSchedules`/`useCreateSchedule`/`useDeleteSchedule` exist but no page lists schedules; they can be created (checkbox in the dialog) and never edited or deleted from the UI.
- **No scan comparison UI** even though `/scans/{id}/changes` exists — the "what changed since the last scan" question is the main reason operators run recurring scans.
- **No policy preview**: the dialog shows a profile name but not the resolved port set, rate, timeout or whether it will be elevated (the confirmation checkbox covers elevation only).

**Improve to:** server-side filters/pagination; schedule management panel (list, edit, pause, next-run preview, timezone); scan-diff view (added/removed services & findings, resolved vulns) as a first-class mode; log panel with level filter, substring search, download and auto-follow toggle; a "policy summary" block in the create dialog (resolved ports/rate/duration estimate + simulated-engine warning if applicable).

### 5.8 Topology

**Works:** two views (graph/table), arrange modes, group filtering and grouping, host detail side panel, path tracing integration, manual offsets, evidence drill-down.

**Problems**
- The heaviest page in the app (961 lines) with **all assets loaded to build the graph client-side**; on a large estate the graph is rendered from a capped fetch and silently incomplete.
- **No minimap, no zoom controls beyond scroll, no node search highlight persistence**; `?focus=` supports deep links but filters/search reset on reload.
- **Graph interaction is mouse-first** — no keyboard traversal, no accessible alternative beyond the table view (which is good, but the graph is where the value is).
- **No path-to-critical visualisation** ("shortest path from the internet-facing segment to this crown-jewel asset") and no way to annotate/override a link's meaning beyond parent overrides.
- Layout options are undocumented ("hierarchy" vs others) and there is no "save this arrangement" action.

**Improve to:** server-side graph aggregation with level-of-detail (return gateways/subnets first, expand on demand), minimap + zoom buttons + fit-to-screen, keyboard traversal and a node list with search, path-finding overlay, saved arrangements per site, and an explicit "graph is showing N of M nodes" cue with a "load more" affordance.

### 5.9 Detections

**Works:** match list with severity/status, detail pane, status transitions (new/triaged/ignored), rule-type labels, sensor-source provenance.

**Problems**
- **No rule management UI at all** despite `useDetectionRules`/`useCreateRule`/`useUpdateRule` hooks and full CRUD endpoints (§4.3) — operators cannot see, author, tune or disable the rules generating detections. This is the biggest functional hole in the "Detect" area.
- Client-side filtering over 200 matches; no timeline/histogram; no correlation to assets beyond a text field; no bulk triage.
- No indication of **rule health** (last match, evaluation errors, dedup window behaviour).

**Improve to:** a Rules tab with list/editor (threshold, temporal, entity-aggregation, Sigma import/export), enable/disable, a test bench ("run against the last 7 days" preview with match counts before saving), per-rule health (last match, error, evaluation lag) and a detections timeline with bulk triage. See §6.9.

### 5.10 Events

**Works:** level/category filters, free-text search including metadata, day grouping, expandable rows, "Pause live".

**Problems**
- **"Resume live" is inert** — toggling it issues one refetch and there is no polling interval or event subscription behind it (§3.7), so the control actively misleads.
- Client-side filtering over a 200-row page; no time-range picker (server defaults to last 24 h); no export; no "create detection rule from this event" affordance; no sensor/source health summary.
- Timestamps use relative formatting in the list and absolute in the detail (inconsistent within one interaction).

**Improve to:** real live mode (WS channel or 5 s polling with a visible "live" indicator + new-event counter chip), server-side filters, time-range and saved queries, "create rule from event" and "add to watchlist" actions, export, and a per-sensor health strip (last event received, drop rate).

### 5.11 Alerts

**Works:** the four-view structure (Active / History / Trigger rules / Destinations) matches the mental model; occurrence detail shows evidence snapshots and lifecycle transitions; the trigger editor exposes the condition DSL and metric thresholds; destination manager handles webhook config with test sends; the alerting engine behind it (outbox, dedup, recovery, cooldown, HMAC-signed deliveries) is the most robust backend subsystem.

**Problems**
- **Acknowledge/silence is missing from the Active list** — the model supports `acknowledged`/`suppressed` occurrences, but the UI does not expose acknowledge-from-list, bulk acknowledge, or "silence for 1 h/1 d".
- **No on-call/assignment notion** (owner, escalation) and no per-user notification preferences: deliveries are org-scoped destinations only, so an analyst cannot subscribe personally to critical alerts (§6.19).
- The **trigger builder is dense** — appropriate for experts, but there is no template gallery ("new device", "critical finding", "feed stale", "CPU > 90 % for 10 min"), no validation summary visible while editing (the server validates; the client has `alert-validation.ts` but the flow hides the results until save), and no "would have fired N times in the last week" dry run.
- **Health strip is hard-coded** (`"evaluator": "worker"`, §3.10).

**Improve to:** acknowledge/snooze/bulk actions in the Active view with keyboard triage; trigger templates + live validation + dry-run preview against recent events; per-user subscriptions and quiet hours; real evaluator health; and an explicit "which destinations received this and what did they answer" trail (delivery list per occurrence with retry/status).

### 5.12 Reports

**Works:** job list with progress and polling while generating, multiple report types (executive/technical/inventory/scan-comparison), format choice, download via API, failure surfaced with error text.

**Problems**
- **No report scheduling or delivery** — reports are one-shot jobs; the obvious recurring workflow ("email the weekly executive report") is missing (§6.11).
- **No template/branding control** (logo, colours, cover page, custom sections) and the hand-rolled PDF writer cannot embed images today (§3.9).
- **No preview** before generating; long jobs give only a percentage.
- Report definitions are created implicitly per job; there is no library of saved definitions.

**Improve to:** saved report definitions + schedules (cron) + delivery to alert destinations (email/S3/webhook), branding configuration, a preview pane (HTML) before generating the PDF, and a comparison view for scan-comparison reports surfaced in the UI (not only in the artifact).

### 5.13 Connections

**Works:** guided create flow (issue token → copy command), kind/type filters, per-connector status and liveness, revoke and delete with confirmation, per-connector config editor, and honest documentation of the capability matrix.

**Problems**
- **No fleet view**: no version distribution, no "outdated agents" filter, no bulk action, no task dispatch ("run inventory now") from the list — the agent task system exists but is not exposed here.
- **No logs/health per connector** (last heartbeat, last error, reconnect count) beyond a status dot.
- Status vocabulary mixes presence (`online`), lifecycle (`pending`) and health, and the pending count drives a sidebar badge that can exceed what the list shows (client-side filter, §4.2).

**Improve to:** fleet table with version/OS/capabilities/last-seen columns, filters and bulk actions (upgrade instructions, rotate token, revoke, dispatch task), per-connector detail drawer with heartbeat history and recent errors, and a "connect a new endpoint" wizard that adapts the command to OS/architecture (§6.10).

### 5.14 Settings

**Works:** the most complete area (sites, account, presets, users, scanners, feeds, metrics, audit), with 33 toast calls — feedback is reliable here.

**Problems**
- **1 549 lines of sections in one file**, no sub-navigation or deep links (`#/settings?sites` is not shareable), and no search inside settings.
- **Permission-blind UI:** every section renders regardless of role; a `viewer` sees destructive controls that will 403 (see §5.15).
- **Feeds section** shows status but not per-feed sync history/provenance (the feeds API tracks `feed_sync_runs`); operators cannot answer "why did the index stop growing".
- **Audit section** is read-only with limited filters (no actor/action/date-range combination visible, no export), which weakens its investigative value.
- Scan-preset editor does not preview resolved behaviour (ports/rate/duration) and does not share the validation of the send path (§3.6).

**Improve to:** settings as a routed sub-tree (`#/settings/users`), role-aware visibility (hide vs disable-with-tooltip based on `me.permissions`), feed sync history with per-run records and "sync now", audit filters + CSV export + retention notice, and a preset editor with live resolved-policy preview.

### 5.15 Cross-cutting UX themes

1. **Permission-aware UI is absent.** `permissions` is present in the auth payload (`api-types.ts:17`), but no page consults it: viewer-role users see every button and learn about restrictions via 403 toasts. Adopt `<Can perm="finding:write">…</Can>` (hide for read-only roles; disable with an explanatory tooltip where discoverability matters).
2. **Simulated/degraded mode is invisible.** The scanner falls back to a simulated engine silently (§3.3); the UI must badge the engine and any degraded transports (plaintext gRPC, Redis-less rate limiting) in the status footer.
3. **Every list needs the same four states** — loading (skeleton), empty (with the primary action), error (with retry + request id), and stale ("showing data from HH:MM, reconnecting…"). Today most lists implement one or two.
4. **Terminology drift:** "assets" vs "devices" vs "hosts"; "findings" vs "vulnerabilities" vs "CVEs"; "detections" vs "matches"; "connectors" vs "agents" vs "scanners" vs "sensors". Add a glossary page (the docs already have the vocabulary) and align column headers/labels/empty states.
5. **Confirmation consistency:** destructive actions use `ConfirmDialog` (delete asset), inline expanders (bulk status), native checkboxes (elevated scan) and typed confirmations (none). Standardise: risk-proportionate confirmation component with a consequences list.
6. **Motion and density:** transitions are tasteful but there is no density control (comfortable/compact) for the tables that dominate the app; a per-user density token is cheap and valuable for 1 080 p operators.
7. **Feedback latency:** mutations that hit the worker (rediscover, report generation, search actions) return 202 and rely on toasts; add an inline "job started → view progress" affordance linking to the job/log rather than a disappearing toast.
8. **Onboarding:** the first-run experience is a login form; there is no wizard ("create site → add network → run first scan → connect an endpoint") even though the demo data pipeline exists and `docs/OPERATIONS.md` describes the sequence. A 4-step guided first-run would materially increase time-to-value.
9. **No global "offline/degraded" banner** when the API or WebSocket is unreachable; the WS status is only surfaced indirectly (polling fallbacks still render data, so the app *looks* healthy while stale).
10. **No in-app help.** `HelpCircle` icons exist in the create-scan dialog only; the excellent `docs/` content is not reachable from the UI. Add contextual docs links and a "?" panel.

---

## 6. Feature proposals

Each proposal states the **purpose** (problem it solves and for whom), the **user experience**, the **technical design** (data model, API, worker/algorithm changes with file-level anchors), **effort** (S ≤ 1 week, M ≈ 2–4 weeks, L ≈ 1–2 months for one experienced engineer) and **risks/dependencies**. They are ordered roughly by strategic value, not by size.

### 6.1 SSO (OIDC + SAML) and SCIM provisioning — *M*

**Purpose.** Today the only way into the platform is an email/password account created by an administrator (`handleLogin`, `users` table). Enterprise buyers require SSO: no shared passwords, central offboarding, and group→role mapping. Without it, Aegis cannot pass a procurement review in a regulated organisation.

**UX.** Settings → Authentication: add "Single sign-on" with provider cards (Okta, Entra ID, Google Workspace, generic OIDC, generic SAML), a guided metadata exchange (issuer/authorize/token/jwks URLs or IdP metadata XML), a **test-login** button, and a mapping table (IdP group → Aegis role + organization). Login page renders "Continue with <IdP>" buttons next to the password form; a domain-hint box (`user@corp.com`) auto-routes by email domain. Administrators can enforce SSO-only per organization (password login disabled except for a break-glass account).

**Design.**
- **Data model:** `identity_providers` (id, organization_id, kind `oidc|saml`, name, issuer, client_id, client_secret_enc, metadata_json, group_claim, enabled, created_at); `idp_group_mappings` (idp_id, idp_group, role, organization_id); `users` gains `idp_id`, `subject` (unique per IdP) and `password_hash` becomes nullable (SSO-only users); `auth_events` for audit.
- **Flow (OIDC):** `GET /api/v1/auth/oidc/:id/start` → state + PKCE verifier stored in a short-lived Redis key, redirect to the IdP; `GET /api/v1/auth/oidc/:id/callback` validates `state`, exchanges the code (no client secret in the browser), verifies `id_token` signature via JWKS (cache keys, respect rotation), maps claims (`sub`, `email`, `groups`) → user + membership + role, then issues **the existing session**: reuse `auth.NewTokenIssuer` + the refresh-cookie/session-row machinery so SSO and password logins converge on identical session semantics (rotation, reuse detection, `sid`).
- **SAML:** an XML signature verification path (an off-the-shelf library), assertion replay protection via an `assertion_id` cache, and metadata import/export endpoints.
- **SCIM 2.0:** `/api/v1/scim/v2/Users` and `/Groups` with a bearer provisioning token (`connectors`-style secret hashing), mapping to users/memberships; deprovisioning disables the user and revokes all sessions (`sessions` table already supports family revocation).
- **Security:** never trust unverified email — require `email_verified` (OIDC) or a signed assertion; store secrets with envelope encryption (new `internal/crypto` helper keyed by `AEGIS_SECRET_KEY`); audit every login and mapping change.
- **Migration:** additive; password auth remains the default until an IdP is enabled.

**Risks.** SAML implementations are heavy — prefer OIDC-first with SAML later; IdP group claims vary wildly, so make the mapping UI testable against real claims.

### 6.2 MFA (TOTP + WebAuthn) and step-up authentication — *M*

**Purpose.** A console that can scan networks and hold scan credentials must not be protected by a single password. Add second factors plus *step-up* (re-authentication) for high-risk actions.

**UX.** Account → Security: enrol TOTP (QR + recovery codes, shown once), add passkeys/security keys (WebAuthn), list and revoke factors, view active sessions and revoke individual ones. Login: password → 6-digit prompt (or passkey prompt with conditional UI). For elevated operations (create scan with `confirm_elevated`, delete asset, revoke connector, change roles), a modal asks for a fresh factor assertion if the last one is older than N minutes.

**Design.**
- **Data model:** `user_factors` (user_id, kind `totp|webauthn`, secret_enc or credential_id/public_key, sign_count, name, created_at, last_used_at); `recovery_codes` (user_id, code_hash, used_at); `sessions` gains `auth_level` and `auth_at`.
- **TOTP:** RFC 6238 with a 30 s step and ±1 window, secrets encrypted at rest; comparison in constant time alongside the existing argon2id helpers.
- **WebAuthn:** register/assert flows via a Go WebAuthn library; store the credential public key and counter; require user verification for step-up assertions.
- **Access tokens:** add `amr` and `auth_at` claims; the middleware rejects step-up-required routes when `now - auth_at > AEGIS_STEP_UP_TTL` (default 15 min) with a `401 step_up_required` code the SPA understands (the api client already distinguishes error codes) and a modal that re-authenticates without dropping the session.
- **Enforcement policy:** per-organization settings (`require_mfa: all|admins|off`), plus a login-time "MFA required for your role" flow.
- **Recovery:** recovery codes are single-use and hashed; a `mfa.reset` admin action requires the `user:manage` permission and is audited.

**Dependencies.** Interacts with §2.11 (revocation); implement `auth_at` there so step-up and revocation share plumbing.

### 6.3 API tokens and service accounts — *M*

**Purpose.** Every automation story today requires a human login: there are no machine credentials. CI pipelines, SIEM exports, ticketing sync and Terraform-style provisioning all need scoped, rotatable, auditable tokens that do not expire with a user's password.

**UX.** Settings → API tokens: create a token with a name, optional expiry, an organization, and a **scope set** (permission subset, e.g. `asset:read`, `finding:read`, `scan:write`); show the secret exactly once with a copy button and a curl example; list tokens with last-used time, creator and "rotate"/"revoke" actions. Service accounts appear as non-human actors in the audit log and in `assignee` pickers (labelled as machines).

**Design.**
- **Data model:** `api_tokens` (id, organization_id, service_account_id, name, prefix, secret_hash, scopes text[], expires_at, last_used_at, revoked_at, created_by); `service_accounts` (id, organization_id, name, role, disabled) — a service account is a user-like principal with a role but no password.
- **Presentation:** `Authorization: Bearer aeg_<prefix>_<secret>`; the existing `authenticate` middleware first tries JWT parsing, then the token path: split prefix → look up by prefix → verify `secret_hash` (SHA-256, cheap since the secret is high-entropy) → build the same `auth.Claims` shape (`org`, `role`, `perms` intersected with `scopes`, `sid = token:<id>`) so **every existing permission check keeps working unchanged**.
- **Least privilege:** the effective permission set is `role_permissions ∩ token_scopes`; add a CI/API test that a token without `asset:write` receives `403` on `PATCH /assets/{id}` — this also guards §2.1.
- **Operations:** tokens inherit the per-request rate limits (with a separate bucket), are never usable for `/auth/*`, cannot be created with scopes exceeding the creator's own permissions, and are revoked automatically when the service account is disabled. Store `last_used_at` asynchronously (Redis counter → periodic flush) to avoid a write per request.
- **Docs:** an OpenAPI-generated SDK story (§6.18) pairs with this feature.

**Effort note.** This is the highest-value "unblocks other work" feature in the list; the middleware change is small and well-isolated.

### 6.4 Finding workflow: ownership, SLA and risk acceptance — *M*

**Purpose.** Aegis finds vulnerabilities but does not manage their remediation lifecycle. Analysts cannot say who owns a finding, when it is due, or why it was accepted — so the product stops at "detect" while buyers expect "manage".

**UX.** Findings list gains Owner, Due date and SLA columns with inline assignment; the detail pane becomes a proper work surface: activity/comment thread, status transitions with reasons, attachments/links, and an "Accept risk" flow (justification, expiry, optional approver). Saves an "Overdue" and "Unassigned" default view. Asset detail shows the same for its findings.

**Design.**
- **Data model:** `findings` gains `owner_id` (user), `due_at`, `sla_policy_id`, `accepted_until`, `accepted_by`, `acceptance_reason`; a `finding_activity` table (id, finding_id, actor, kind `comment|status|assignment|acceptance`, body, created_at) that generalises the existing notes concept; `sla_policies` (organization_id, severity → duration, business-hours calendar flag).
- **Computation:** a worker loop (mirroring the existing 30 s maintenance ticker) recalculates `due_at` when severity/owner changes and emits `finding.overdue` trigger events so the alert engine notifies automatically (no new delivery code — reuse `alerting.EmitFindingStatusChanged` patterns).
- **Acceptance semantics:** `accepted_until` is a first-class suppression scope (distinct from §2.5 suppressions): the correlation pipeline marks matching findings `accepted` (visible, not hidden) until expiry, then re-opens them and emits an event. This makes risk acceptance auditable and self-expiring.
- **API:** `PATCH /findings/{id} {owner_id, due_at}`, `POST /findings/{id}/comments`, `POST /findings/{id}/accept`, `GET /findings/{id}/activity`, plus `GET /findings?sla=overdue|due_soon`.
- **UI:** reuses the existing list/detail patterns; the activity thread is a simple timeline (no rich text) to stay within the current component vocabulary.

**Dependencies.** Requires §2.7's decision on notes (this proposal supersedes the notes endpoint with a proper entity-scoped activity model).

### 6.5 Saved views, URL state and exports — *S–M*

**Purpose.** Analysts repeatedly reconstruct the same filtered views, and cannot share them or take data out. The backend supports most filters already; the frontend does not persist them (`docs/DEVELOPMENT.md` even claims URL-persisted filters that only exist on a few pages).

**UX.** Every list page gets: a filter bar whose state is fully encoded in the URL (`#/findings?severity=critical&status=open&owner=me&sort=risk&page=2`), a "Save view" action with a name (private or shared to the organization), a view switcher dropdown, and an "Export" menu (CSV/JSON of the current filter). Saved views appear in the sidebar as shortcuts and in the command palette.

**Design.**
- **Frontend:** one `useUrlTableState(schema)` hook that maps typed filter descriptors to `URLSearchParams` (the router already exposes `query`/`navigate`), replacing the ad-hoc `useState` filters in Findings/Assets/Scans/Detections/Events/Vulnerabilities.
- **Backend (saved views):** `saved_views` (id, organization_id, owner_id, scope `private|org`, entity `findings|assets|scans|…`, name, filter_json, created_at) with `GET/POST/PATCH/DELETE /api/v1/saved-views`. Validate `filter_json` against a per-entity whitelist (never pass it to SQL directly — map to the existing typed filter structs).
- **Exports:** `GET /api/v1/findings/export?format=csv&…` streaming with `encoding/csv` over a paged `Query` (constant memory, `Content-Disposition`), reusing the exact same filter struct as the list handler so the export always matches the view. Cap rows (e.g. 100 k) with a clear error, and audit the export (data exfiltration is a security-relevant event). Reuse the existing report-job pipeline for anything larger.
- **Permissions:** exports honour the caller's permissions and are audited; saved org-wide views require `settings:manage`-level trust or are limited to the creator's role.

### 6.6 Ticketing and chat integrations — *M*

**Purpose.** Remediation happens in Jira/ServiceNow/GitHub/Slack/Teams, not in the vulnerability console. Delivery infrastructure already exists (alert destinations with HMAC, retry, DLQ) — this feature extends it to bidirectional issue sync.

**UX.** Settings → Integrations: connect Jira/ServiceNow/GitHub with credentials, map Aegis severity → ticket priority, and choose project/board/queue. On a finding: "Create ticket" (auto or manual), the finding shows the ticket key and sync status, and status transitions flow back (ticket Done → finding `resolved`/`verified`). Slack/Teams get rich cards ("critical finding on 10.0.0.5" with Open/Assign/Acknowledge action buttons) instead of raw JSON.

**Design.**
- **Data model:** `integrations` (id, organization_id, kind, config_json_enc, enabled); `external_links` (finding_id/asset_id, integration_id, external_id, url, state, last_synced_at).
- **Outbound:** reuse the `alerting` outbox + delivery worker pattern (durable, retried) but add a **provider adapter interface** (`CreateIssue`, `UpdateIssue`, `ParseWebhook`) with Jira/ServiceNow/GitHub implementations; HMAC and SSRF guards already exist for generic webhooks.
- **Inbound:** `POST /api/v1/integrations/{id}/webhook` verifies provider signatures, maps external states to finding statuses via a configurable transition table, and writes through the same service used by the UI (so history and audit are consistent).
- **Idempotency:** `external_links` unique on `(integration_id, external_id)`; ticket creation is idempotent per finding (skip if a link exists).
- **Slack/Teams:** implement as a destination kind (`chat`) rather than a new subsystem — the message formatter lives next to the existing webhook payload builder in `internal/alerting/store.go`.

### 6.7 Watchlists and subscriptions — *S–M*

**Purpose.** Users care about specific products, vendors, CVEs and assets — not the whole index. A watchlist turns the passive CVE table into an alerting surface ("tell me when a new critical affects our OpenSSH fleet" or "when KEV adds something we run").

**UX.** "Watch" buttons on CVE detail, product/vendor rows, asset detail and search-action results, with a per-watch notification choice (in-app/digest/webhook). A "Watched" view lists matches with an unread indicator. Daily/weekly digest email option (requires §6.19).

**Design.**
- **Data model:** `watchlists` (id, organization_id, owner_id, subject `cve|product|vendor|cpe|asset|query`, value, created_at); matching happens in the **correlation worker**: after a feed sync or correlation pass, evaluate new/updated CVEs against watch rows (using the existing matcher/index queries) and emit `watchlist.match` trigger events into the alert outbox — no new delivery path needed.
- **Dedup:** a `watchlist_hits` table with a unique `(watchlist_id, cve_id, asset_id)` key so notifications never repeat.
- **Performance:** evaluate watches as a single SQL join against the CVE index and installed software for `product|vendor` subjects, and reuse the matcher for `cve` subjects; run after each feed sync (the feed-worker already sequences syncs) and after each correlation job.
- **API:** `GET/POST/DELETE /api/v1/watchlists`, `GET /api/v1/watchlists/hits`.

### 6.8 Attack-path and exposure analytics — *L*

**Purpose.** The product has a topology graph and a risk score, but it cannot answer the operator's most important question: *"if an attacker is on this host, what can they reach, and which path leads to our critical data?"* This is what turns a scanner into a decision tool — and it is also a strong differentiator against pure scanners.

**UX.** Topology gains a mode: pick a source (internet-facing asset, compromised hypothesis) and a target (critical asset or criticality group) → the graph highlights the shortest/cheapest path with hop-by-hop reasoning (open service, exploited CVE with KEV/EPSS, credentials reachable, shared subnet). A "choke points" panel lists hosts whose removal disconnects the most critical pairs. Findings and asset pages link to "paths through this host".

**Design.**
- **Graph model:** derive an `attack_graph` view from existing data at aggregation time — nodes = assets; edges = (a) observed topology links (existing topology evidence), (b) same-subnet reachability derived from interfaces/networks, (c) service-mediated adjacency (e.g. exposed SSH/RDP/HTTP), weighting edges by exploitability of the service's known CVEs (`KEV && EPSS`-weighted, reuse the risk engine's blending logic so scores are explainable).
- **Algorithm:** Dijkstra/A* for weighted shortest paths (cost = inverted exploitability × hops), and for choke points a betweenness-style measure computed on the induced subgraph of critical assets (networkx-style logic implemented in Go, or precomputed in the worker and cached per site). Graphs for realistic estates (10⁴ assets, 10⁵ edges) are tractable if computations run in the worker and results are cached in Redis/Postgres with a TTL keyed by data version.
- **API:** `GET /topology/attack-paths?from=&to=&site=`, `GET /topology/choke-points?site=`, `GET /topology/attack-paths/explanations` — all returning plain JSON with per-hop evidence ids so the UI can link to raw observations.
- **Delivery:** asynchronous job (`correlation_jobs` already exists for long-running compute) that refreshes the cache when assets/services/findings change materially.
- **Honesty requirement:** label every path "hypothesis based on observed services and known vulnerabilities" — never present it as a validated exploit chain (the product's ethical stance, README, depends on this).

### 6.9 Detection rule authoring (with Sigma import/export and a test bench) — *M*

**Purpose.** The detection engine and its CRUD API exist, but no user can see or tune a rule (no UI consumes `useDetectionRules`). Behavioural rules that nobody can edit are, in practice, unusable in a real SOC.

**UX.** Detections gains a "Rules" tab: filterable list (kind, enabled, last match, source), an editor for threshold/temporal/entity-aggregation rules with typed fields, a Sigma **import** (paste or upload YAML → mapped rule preview → save) and **export**, a clone/template gallery ("port scan burst", "new external destination", "auth failures spike"), and a test bench: "evaluate against the last 7/30 days" showing would-be matches, per-entity breakdown and evaluation cost before saving.

**Design.**
- **Frontend:** the hooks already exist; build the editor against `GET /detections/rules` + `POST/PATCH`, with a schema-driven form (a small `RuleDraft` type + validators like the existing `alert-draft.ts`/`alert-validation.ts` pattern).
- **Backend:** add `POST /detections/rules/preview` that runs the rule definition against historical events in ClickHouse for a bounded window with a hard row/time budget (return counts + a capped sample, never unbounded). Sigma mapping: a `internal/detections/sigma` package that converts Sigma `detection` blocks into the engine's rule types, reporting unmappable constructs explicitly (never silently dropping conditions).
- **Safety:** previews are read-only and rate-limited; rule changes are revisioned (`revision`/`updated_by`) and audited, exactly like alert triggers.
- **Quality:** a rule "health" panel computed from matches/errors over the last 24 h so dead or noisy rules are visible.

### 6.10 Fleet management for agents, scanners and connectors — *M*

**Purpose.** Once more than a handful of endpoints are enrolled, operators need to know what version each runs, what its capabilities are, when it last reported, and how to act on it (dispatch a task, update, rotate credentials). Today `ConnectionsPage` is a create/delete list.

**UX.** Connections becomes a fleet table: columns for kind, version, OS/arch, capabilities, health, last heartbeat, bound assets; bulk selection with actions ("Run inventory now", "Rotate token", "Revoke"); a detail drawer with heartbeat history, recent errors and a task queue view; an "outdated" filter that highlights agents behind the current release and shows per-platform upgrade commands (mirroring the create-connector command UX, which is genuinely good).

**Design.**
- **Data:** the `agents`/`connectors`/`scanners` tables already store version and heartbeat fields; add `capabilities` normalisation if needed and a `agent_tasks` history view (the table exists with task types and results).
- **Tasks:** expose the existing typed-task dispatch over HTTP (`POST /connectors/{id}/tasks` and a task-status endpoint) — the worker-side execution path exists (`agentTasks`, `PendingTasks`, `CompleteTask`), so this is mostly an API/UI surface, plus permissions (`connector:manage`).
- **Updates:** do **not** implement remote self-update in v1 (security posture: the product deliberately avoids remote code execution on endpoints). Instead: publish per-platform upgrade commands, expose the target version vs installed version, and (optionally) a "download agent package" link served from the control plane with checksums. If auto-update is ever added, require signed manifests verified against the existing CA/keys — document the decision explicitly.
- **Troubleshooting:** a per-connector "diagnostics" action that reuses the diagnostic task type and streams the result into the existing job-log panel.

### 6.11 Scheduled, templated and branded reporting — *M*

**Purpose.** Reporting is one-shot today: no schedules, no delivery, no branding, no preview. Recurring stakeholder reporting is usually the *reason* a platform like this gets renewed.

**UX.** Reports gains a "Definitions" list (type, scope, sections, format, branding profile) and a "Schedules" list (cron, recipients/destinations, next run, last result). A definition editor toggles sections (executive summary, KEV highlights, top assets by risk, SLA/overdue table, scan comparison, detection summary), picks a branding profile (logo, colours, cover text, footer/legal note) and offers "Preview (HTML)" before saving. Delivery to alert destinations (email/S3/webhook) reuses the destination manager.

**Design.**
- **Data model:** `report_definitions` (id, organization_id, name, type, params_json, sections_json, branding_id, format, created_by, updated_at) and `report_schedules` (definition_id, cron, timezone, destinations text[], enabled, last_run_at, next_run_at); `report_jobs` gains `definition_id` (it may already reference one).
- **Scheduling:** the worker already owns a 30 s maintenance ticker and a durable `correlation_jobs` queue; add a `RunDueReportSchedules` step that enqueues report jobs (idempotent by `(definition_id, scheduled_slot)`), reusing the existing job claiming semantics.
- **Rendering:** extend `internal/reports/generator.go` with a section registry so sections are composable; branding is a template-variable bag injected into the HTML template and passed to the PDF writer.
- **PDF writer:** the hand-rolled writer must gain images (logo) — or the pipeline switches to headless-Chrome rendering for rich output with the hand-rolled writer retained as the air-gapped fallback (§3.9). Decide explicitly and document the tradeoff.
- **Delivery:** email requires an SMTP/API configuration (`AEGIS_SMTP_*`) and a new destination kind; otherwise deliver to existing webhook/S3 destinations.

### 6.12 Scan governance: maintenance windows, rate budgets and approvals — *L*

**Purpose.** Enterprise scanning is constrained: change freezes, business hours, per-site bandwidth budgets, and approval for intrusive profiles. Today scope safety is not a scan-policy engine — a scan can start at any time, on any validated target, at the profile's fixed rate.

**UX.** Settings → Scan policy: per-site maintenance windows (allowed days/hours, timezone, blackout dates), a per-site packet-rate budget, and an approval requirement for elevated profiles. When an operator creates a scan outside a window, the dialog explains why it is blocked and offers "schedule for the next window" or "request approval" (with justification). An approvals inbox shows requests with approve/deny and audit.

**Design.**
- **Data model:** `scan_policies` (site_id, allowed_windows jsonb, max_packet_rate, require_approval_for text[]/profiles, updated_by); `scan_approvals` (scan_request_json, requested_by, status, decided_by, decided_at, justification).
- **Enforcement points:** (1) `Orchestrator.Create` — after scope validation, evaluate policy; block or mark `pending_approval`; (2) the scheduler — `RunDueSchedules` skips/pushes runs outside windows with a recorded reason; (3) the scanner — clamp `max_packet_rate` to the policy budget when accepting a job (defence in depth, since the orchestrator is not the only path into the scanner).
- **Rate ceilings:** the scanner caps already exist (`MaxPacketRate` 500 pps default); make them per-assignment rather than global.
- **Approvals:** reuse the notifications/alerts plumbing for "approval requested"; the approve action creates the scan with the same payload, audited end to end.
- **Policy simulator:** a read-only endpoint that answers "if I ran this profile with these targets now, what would happen?" (resolved port set, estimated duration, rate, policy verdict) — this also fixes the transparency gap in §5.7.

### 6.13 Asset lifecycle, dynamic groups and software intelligence — *M*

**Purpose.** Assets are the platform's spine, but lifecycle management is manual: groups are static memberships, ownership is a free-text field, end-of-support is invisible, and there is no software/licence roll-up. Buyers use these to run the platform as a system of record, not just a scanner.

**UX.**
- **Dynamic groups:** a group filter builder ("device_type = printer AND site = HQ AND exposure = internal"), previewed live with a count; membership recomputed automatically.
- **Ownership:** assign an owner (user or team) at group, site or asset level; assets inherit from the most specific scope; a "My assets" view.
- **End-of-support tracking:** a curated EOL dataset matched against OS/product versions (Windows 10, Ubuntu 22.04, EOS switches…), surfacing "12 assets on unsupported software" as a KPI with drill-down, and feeding the risk engine as a factor.
- **Software intelligence:** an org-wide software inventory (name/version/ecosystem, installed count, affected-asset count, known CVEs, latest version) with "outdated" comparison where a vendor feed allows it; licence-mode reporting (best-effort, explicitly not a SAM product).

**Design.**
- **Dynamic groups:** add `filter_jsonb` to `asset_groups` (keeping the existing manual membership rows for static groups), and evaluate filters in SQL (`assetFilterWhere` already exists) with a materialised `asset_group_members` refresh in the worker (debounced: recompute on asset insert/update via the existing change pipeline, or a 60 s sweep). Preview endpoint: `POST /asset-groups/preview {filter}` returns a count + first N assets.
- **Ownership:** `owner_id` on `assets` (already present as text — migrate to a FK when the users/teams model allows), `site_owners`/`group_owners` tables with most-specific-wins resolution in a SQL view or in `AssetFilter`.
- **EOL:** a small curated table (`eol_products`: vendor, product, version_pattern, eol_date, source_url) shipped in migrations and refreshed by the feed-worker from a JSON manifest in the repo (so it works air-gapped); matching reuses the version-comparison helpers from the vulnerability matcher.
- **Software roll-up:** one aggregate query over `software` (`GROUP BY name, version` with `count(DISTINCT asset_id)`) plus the existing findings join for CVE counts — expose as `GET /software/summary`.

**Note.** This feature also gives the risk engine better inputs (criticality inheritance, EOL, exposure) and improves the Overview KPIs, so it pays for itself twice.

### 6.14 Compliance mapping and evidence export — *L*

**Purpose.** Organisations must demonstrate control coverage and evidence ("which hosts are missing patches for critical CVEs?", "is our network inventory complete?"). Mapping findings/assets/detections to frameworks turns operational data into audit output — and is a common purchase criterion.

**UX.** A Compliance section: pick a framework (CIS Controls v8, NIST 800-53 rev5 subset, ISO 27001 Annex A subset), see control families with coverage status derived from live data (e.g. "CIS 1.1 Asset inventory: 1 240 assets discovered, last scan 2 h ago → **covered**"; "CIS 7.4 Patch management: 37 critical findings older than 30 days → **gap**"), drill into the evidence (the filtered asset/finding lists), and export an attestation package (HTML/PDF + CSV evidence bundle) for a time range.

**Design.**
- **Data model:** `frameworks` (id, key, name, version), `controls` (framework_id, code, title, description, parent), `control_checks` (control_id, kind `query|metric`, definition_json, threshold_json, weight) — a declarative rule set that maps to existing queries (asset/finding/scan/detection metrics) rather than new collection. Ship a curated starter catalog in migrations and version it.
- **Evaluation:** a worker job (reusing the correlation job queue) evaluates checks on a schedule (daily) and stores `control_status` snapshots (`framework_id, control_id, status, evidence_json, evaluated_at`) so trends are visible; ad-hoc evaluation via `POST /compliance/evaluate`.
- **Evidence:** each check's evidence is a set of query parameters echoing the API filters, so the export bundle simply re-runs the same filtered queries with `?format=csv` (§6.5) and bundles them with the HTML summary — no duplicated query logic.
- **Honesty:** the UI must phrase these as "mapped indicators", not certifications. Provide a `docs/COMPLIANCE.md` explaining what each mapping does and does not prove.

### 6.15 Data governance: retention, legal hold, redaction and portability — *M*

**Purpose.** The platform stores sensitive inventory (MACs, hostnames, installed software, endpoints' metrics). Operators need retention control, auditable deletion, and the ability to answer subject-access requests — increasingly a legal requirement, and a trust differentiator for a self-hosted security product.

**UX.** Settings → Data: retention policies per data class (events/telemetry in ClickHouse, findings resolved older than X, asset history, audit log, report artifacts) with a dry-run ("would delete 1.2 M events"), an immutable-audit toggle, legal-hold flags per site/org, and "Export all data for this asset/subject" plus "Erase" actions with confirmation and audit.

**Design.**
- **Retention engine:** a worker loop executing policy statements (ClickHouse `ALTER … DELETE`/TTL already partly configured; Postgres batched `DELETE … WHERE … LIMIT`) with per-run manifests stored in `retention_runs` (counts, durations, errors) — never silent.
- **Legal hold:** `legal_holds` (scope asset/site/org, reason, created_by, released_at); the retention queries exclude held scopes (join or id blacklist) and the UI shows held items.
- **Redaction:** a per-organization setting that hashes/truncates MAC addresses and hostnames in read paths for users without a new `asset:identity` permission — implemented as a response-shaping layer in the handlers (one helper, applied where identifiers are serialised) rather than schema changes.
- **Portability:** `GET /api/v1/assets/{id}/export` returns a JSON bundle (asset, identifiers, services, software, findings, interfaces, activity) and `POST /api/v1/assets/{id}/erase` performs the cascade delete with an audit record (the cascade already exists for `DELETE /assets/{id}`; erase adds retention of the audit trail).
- **Audit integrity:** optionally append a hash chain (`prev_hash` column on `audit_log`) so tampering is detectable — cheap to implement, meaningful in audits.

### 6.16 Multi-tenant / MSSP mode — *L*

**Purpose.** The data model is already organization-scoped, but the UX and privileges assume a single org. MSPs and large enterprises need org switching, cross-org rollups and a platform-administrator role that is genuinely separate from per-org ownership (see §3.6, where an org `owner` currently lists every organization).

**UX.** An org switcher in the sidebar; a "Portfolio" view for platform admins (per-org KPIs: assets, critical findings, overdue SLAs, license/seat usage); per-org settings and branding; role assignment per org. Users with several memberships see "My organizations" and can hold different roles in each.

**Design.**
- **Model:** introduce a distinct `platform_admin` role flag outside the org role matrix (e.g. `users.is_platform_admin`) with its own permission set; keep `memberships.role` as the per-org role. `handleLogin` must stop defaulting to `orgs[0]` (§3.6) and instead accept a chosen org or issue a session with the "last used org" preference.
- **Cross-org queries:** portfolio endpoints iterate orgs with per-org aggregates (`GET /platform/organizations/summary`), never returning raw tenant rows to the wrong org. Consider a materialised `org_metrics` table refreshed by the worker to keep the portfolio view cheap.
- **Session semantics:** switching org re-issues the access token with a new `org` claim while keeping the same session row (and a `switch` audit entry); the SPA's `BroadcastChannel` already keeps tabs consistent.
- **Isolation:** with RLS (§6.21) the platform admin path is the only one allowed to bypass the org GUC — make that explicit in code and tests.

### 6.17 Air-gapped and offline operation — *M*

**Purpose.** The product targets defence, OT and regulated environments; those are often air-gapped. Today the feed-worker downloads from the internet on first run (`cvelistv5` ships a ~350 MB archive) and reports/agent packages may assume connectivity.

**UX.** Settings → Feeds: an "Offline mode" switch with an import/export panel: export a signed feed bundle from a connected instance, download it, upload it to the isolated instance; show bundle contents (feed, version, date, signature) before applying. A visible "last successful feed sync" banner when stale, and no outbound connections attempted in offline mode.

**Design.**
- **Bundles:** a `feed_bundle` container format (tar.gz + manifest with SHA-256 per file + an ed25519 signature over the manifest) produced by `POST /feeds/bundles` (streaming from object storage or the DB) and consumed by `POST /feeds/bundles/import` (verify signature, then run the normal ingestion pipeline path so provenance/`feed_sync_runs` stay accurate).
- **Config:** `AEGIS_OFFLINE_MODE=true` disables all egress paths (feeds, alert webhooks to non-allowlisted hosts, OTel exporters) and logs refusals; make the SSRF allowlist configurable (`AEGIS_EGRESS_ALLOWLIST`) so on-prem integrations still work.
- **Licensing:** if a licence key is ever introduced, support offline verification (signed licence file with an expiry and org binding) — avoid phone-home.
- **Docs:** a first-class `docs/AIRGAP.md` describing the two-instance workflow, since the current docs assume connectivity.

### 6.18 Extensibility: event subscriptions (webhooks v2), OpenAPI, SDK — *M*

**Purpose.** Existing webhooks are dead (§2.6) and the only extension points are alert destinations. Integrations teams need documented, versioned, retryable event subscriptions and a typed API client.

**UX.** Settings → Event subscriptions: create a subscription with event types (the `TriggerEvent` catalogue already enumerates them), destination URL/secret, filters (site/severity) and a delivery log (status, retries, payload preview, replay). A "Run test" button. Documentation links to the OpenAPI explorer.

**Design.**
- **Reuse, don't reinvent:** the `alerting` outbox + `alert_deliveries` + `SafeWebhookURL` + HMAC + DLQ already implement exactly the semantics needed; generalising `alert_destinations` into a `destinations` concept with a `kind ∈ {webhook, chat, email, s3, subscription}` is a smaller change than building a parallel system. The trigger-matching layer already includes event types, scope filters and conditions — expose a "subscription" trigger type that always fires for its event list (no condition evaluation) to keep the code path identical.
- **Payload contract:** publish a versioned envelope (`{version, event_id, type, occurred_at, org, data}`), document it, and add a schema registry file in `api/` so tests can validate payloads.
- **Replay:** the existing `ReplayDead` operation already exists for alert deliveries; surface it per subscription.
- **OpenAPI + SDK:** add `swaggo`-style annotations (or hand-maintained `api/openapi.yaml` validated by CI) generated from handler structs, serve it at `/openapi.json` with a small docs route, and generate a TypeScript client for the SPA (replacing the hand-written `lib/api-types.ts` drift risk). The frontend already duplicates types; generated clients would remove an entire class of mismatch bugs.
- **Rate/abuse controls:** per-subscription rate limits and circuit breaking (disable after N consecutive failures, notify the owner) so a broken consumer cannot stall the queue.

### 6.19 Notification preferences, digests and escalation — *S–M*

**Purpose.** Alerts currently go to org-scoped destinations only. Individuals cannot subscribe to what they care about, silence noise during maintenance, or receive a daily digest — and nothing escalates when an alert is unacknowledged.

**UX.** Account → Notifications: per-channel preferences (in-app, email, chat, webhook), severity floor, quiet hours, digest frequency; per-trigger overrides ("also notify me personally"). Alert occurrences gain "acknowledge", "snooze 1 h", "assign" with an escalation if unacknowledged for N minutes (configurable per trigger severity).

**Design.**
- **Data model:** `user_notification_prefs` (user_id, channel, min_severity, quiet_hours jsonb, digest `off|daily|weekly`), `alert_acknowledgements` (occurrence_id, user_id, at, note) and `notification_escalations` (trigger_id, after_minutes, destination_ids). The occurrence lifecycle already models `acknowledged`, so escalation is "if still firing/acknowledged==false after N minutes → emit a delivery to the escalation destination list" — implemented as a periodic worker statement over open occurrences (indexed by `state, fired_at`).
- **Digests:** a worker job assembles per-user digests from `alert_occurrences` + new findings + overdue SLAs and delivers through the destination abstraction; templates live next to the report templates.
- **Chat delivery:** a `chat` destination kind with Slack/Teams payload adapters (§6.6).
- **Dedup/suppression:** honour quiet hours and snoozes when creating deliveries (a single filter in `insertDeliveries`), so behaviour is consistent across channels.

### 6.20 Global search and command palette v2 — *S–M*

**Purpose.** Search exists on the backend (`GET /search`, `useSearch` unused) and the palette is static. A real operator console must answer "where is srv-web?", "what else touches 10.0.0.5?", "open the CVE from Slack".

**UX.** ⌘K palette becomes a unified search: type-ahead results grouped by entity (Assets, Findings, CVEs, Scans, Groups, Pages, Actions) with keyboard navigation; `↵` opens, `⌘↵` opens in a new tab; recent items; "search in this scope" toggle (site); and typed queries (`is:critical owner:me` / `cve:CVE-2026-0001`) for power users. The same component powers a dedicated `/search` page with facets and saved searches.

**Design.**
- **Backend:** extend `GET /search` to return typed hits with `kind`, `id`, `label`, `sublabel`, `score` (the endpoint already returns this shape) and add optional `type=` filters; implement it as one SQL `UNION ALL` over the asset/finding/CVE indexes with `ILIKE`/`tsvector` ranking — or a Postgres `pg_trgm` index for speed at scale (a materialised `search_index` table refreshed on write is acceptable if a `tsvector` approach proves complex).
- **Frontend:** replace the static `CommandPalette` (`AppShell.tsx:206`) with a data-driven implementation on top of `cmdk` (already a dependency), debounce the query with `useDebounced` (finally used), and keep the static actions as the empty state.
- **Permissions:** filter results by the caller's permissions; never surface an entity the user cannot open (a 403 on selection is a bad experience and leaks existence).
- **Deep links:** results navigate to canonical URL state (§6.5) so a shared link reproduces the exact view.

### 6.21 Platform quality program: RLS, OpenAPI, tests, backups, upgrades — *M (ongoing)*

**Purpose.** Several findings in this report are *classes* of bug (tenant isolation, docs drift, untested deployment paths). A small quality program removes whole classes rather than individual instances.

**Components**
1. **Row-level security.** Add `organization_id`-based policies to every tenant table with a non-superuser application role and per-transaction `SET LOCAL app.current_org`. The repository layer sets the GUC in one place (`pg.DB` wrapper); tests then assert that a repository query with a *missing* org filter returns zero rows — turning §2.1/§2.2 from "handler discipline" into "database guarantee". Keep the platform-admin path explicit and audited.
2. **OpenAPI as a build artifact.** Generate the spec from handler annotations, validate it in CI (`spectral` or `openapi-generator validate`), publish it in the image at `/openapi.json`, and generate the SPA's API types/client from it so `lib/api-types.ts` and the server cannot drift.
3. **Tests that match the product's risk profile.** Frontend: run Vitest + Playwright in CI (they exist and are never executed). Backend: add a `postgres` service container and run the repository/migration suite (not `-short`), plus an end-to-end smoke test (boot server + worker against compose services, create site → scan with the simulated engine → assert findings appear). Contract tests for the permission matrix (every route × every role).
4. **Deployment validation.** `helm lint`/`helm template` + `kubeconform` + `docker compose config` in CI; a compose smoke test on PRs touching `deploy/`.
5. **Backups, restore and upgrade tooling.** Documented and *tested* `pg_dump`/ClickHouse backup procedures, a `make backup`/`make restore` pair, migration-drill CI, and an upgrade guide that covers schema expansions for ClickHouse (which is the harder half). Add a `make doctor` diagnostic target that checks ports, credentials, migration versions and feed freshness — this would have caught §2.8/§2.9 instantly.
6. **Reliability targets.** Define SLOs for the API and scan pipeline, expose them on a Grafana dashboard (or extend the metrics page), and alert on the queue depths the alert engine already tracks.

### 6.22 Accessibility and internationalisation program — *M (ongoing)*

**Purpose.** WCAG 2.2 AA conformance is a hard requirement in public-sector and large-enterprise procurement; i18n matters for European and Latin-American markets. Both are cheaper to do continuously than to retrofit.

**Workstreams**
1. **Accessibility:** fix §4.6 findings; add axe-core checks to the Playwright suite for the eight highest-traffic pages; enforce a focus-visible ring token; add `prefers-reduced-motion` handling for the animated topology and chart transitions (they respect it today only by accident); audit colour contrast programmatically against the Tailwind v4 tokens (the dark palette makes contrast easy to break); publish an accessibility statement page.
2. **i18n:** introduce `i18next` (or a tiny typed dictionary), extract strings from pages/components, add `en` + one second locale (Spanish or German) as the pilot, format dates/numbers/relative times with `Intl` (replacing hand-rolled `timeAgo`/`formatDateTime`), and add a CI check that fails on new hard-coded user-visible strings in `src/pages`/`src/components`. Server-side: localise report templates and email/digest content via the same catalogs, selected from the user's preference.
3. **RTL readiness:** use logical CSS properties in new code and spot-check one page in `dir="rtl"` to avoid a future rewrite.

---

## 7. Prioritised roadmap

### Phase 0 — Stop the bleeding (1–2 weeks, one engineer)

| Item | Ref | Effort |
|---|---|---|
| Scope `AssetRepo.Update` by organization + resolve asset before write | §2.1 | S |
| Resolve asset org before the four sub-resource reads and topology evidence | §2.2 | S |
| Trusted-proxy allowlist + limiter key eviction + Redis-error fallback policy | §2.3 | S |
| `503` from `/readyz` when not ready | §2.4 | XS |
| Enforce suppressions in the correlation pipeline; fix the suppress handler (use `:id`, require a scope, validate the asset) | §2.5 | M |
| Make `/events` and `/sensors/{id}/events` require a write permission (see Appendix A) | §3.14 | XS |
| Correct the Helm chart/K8s Secret/K8s probe defects and add manifest validation to CI | §2.8, §3.11 | M |
| Commit `scripts/` (or delete the Makefile targets and rewrite the docs) | §2.9 | S |
| Resolve the webhook situation: deprecate or implement (§2.6) | §2.6 | S–M |
| Fix the notes endpoint or delete it | §2.7 | S |
| Add `helm lint`/`helm template`/`kubeconform` + frontend tests to CI | §3.11 | S |
| Delete the dead `var _ = …` statements, the hard-coded freshness chip, the dead `useDetectionRules`/`useSearch`/`useAddNote` paths | §3.6, §4.2, §4.3 | XS |
| Production guardrails for demo defaults (refuse to boot with demo secrets in `AEGIS_ENV=production`) | §3.12 | S |

### Phase 1 — A console operators can trust (4–8 weeks)

1. **Query state architecture.** Server-side filtering + pagination and accurate totals on Findings/Scans/Detections/Events; one aggregate endpoint for dashboard/nav counters; skeletons, error states and stale indicators everywhere (§4.1, §4.5).
2. **One design system.** Migrate the five legacy-kit consumers, delete `components/ui/index.tsx`, `table/DataTable.tsx`, `tailwind.config.ts`, and recharts; unify severity colours and confirmation patterns (§4.4, §4.10).
3. **Frontend test coverage in CI.** Vitest + Playwright on every PR; add axe-core to the eight main pages (§4.6, §3.11).
4. **Accessibility and keyboard pass.** Focusable rows, dialog focus management, shortcut sheet, density toggle (§4.6, §5.15).
5. **Documentation truth.** Fix every drift item in §3.13; add a docs-lint CI job.
6. **Realtime hardening.** WS ticket instead of a query-string token; real "live" mode for Events; catch-up semantics documented (§4.8, §3.7).
7. **API tokens + audit completeness** (§6.3) — unblocks automation and CI smoke tests.

### Phase 2 — Enterprise readiness (2–4 months)

SSO/SCIM (§6.1), MFA + step-up (§6.2), finding workflow with SLA/acceptance/comments (§6.4), saved views + exports (§6.5), fleet management (§6.10), scheduled/branded reporting (§6.11), notification preferences and escalation (§6.19), global search/palette v2 (§6.20), RLS + OpenAPI + repository/migration test suites (§6.21), scan governance (§6.12).

### Phase 3 — Differentiators (4–6 months)

Attack-path analytics (§6.8), compliance mapping and evidence export (§6.14), asset lifecycle/EOL/software intelligence (§6.13), data governance/portability (§6.15), multi-tenant MSSP mode with a platform-admin role (§6.16), air-gapped operation (§6.17), event subscriptions/OpenAPI SDK (§6.18), i18n (§6.22), detection rule authoring (§6.9), ticketing/chat integrations (§6.6), watchlists (§6.7).

### Impact × effort snapshot

| Proposal | Impact | Effort | Depends on |
|---|---|---|---|
| §6.3 API tokens | High | M | — |
| §6.4 Finding workflow | High | M | notes decision (§2.7) |
| §6.1 SSO + §6.2 MFA | High (procurement) | M+M | §2.11 revocation |
| §6.21 RLS/OpenAPI/tests | High (structural) | M ongoing | — |
| §6.11 Report schedules/branding | High | M | PDF images (§3.9) |
| §6.10 Fleet management | Medium-High | M | task APIs |
| §6.5 Saved views/exports | Medium-High | S–M | URL state refactor |
| §6.20 Search/palette v2 | Medium-High | S–M | — |
| §6.8 Attack paths | High (differentiation) | L | topology quality |
| §6.14 Compliance mapping | High (procurement) | L | exports (§6.5) |
| §6.16 MSSP mode | Medium-High | L | RLS (§6.21) |
| §6.9 Detection rules UI | Medium-High | M | — |
| §6.13 Asset lifecycle/EOL | Medium | M | — |
| §6.15 Data governance | Medium (compliance) | M | retention worker |
| §6.17 Air-gapped mode | Medium (segments) | M | — |
| §6.12 Scan governance | Medium | L | scheduler hooks |
| §6.6 Ticketing | Medium | M | alert destinations |
| §6.7 Watchlists | Medium | S–M | correlation worker |
| §6.19 Notification prefs | Medium | S–M | destinations/chat |
| §6.22 A11y + i18n | Medium (procurement) | M ongoing | Phase 1 |

---

## 8. Verification plan

Because this review was static, every backend finding should be confirmed before and after the fix. The commands below are ordered so that the cheap structural checks run first.

**Build and static analysis (requires the Go toolchain, absent in the review sandbox)**

```
go build ./... && go vet ./... && gofmt -l cmd internal api
go test ./... -count=1            # full suite (not -short)
go test ./... -race -count=1      # race detector, as the Makefile already intends
golangci-lint run                 # .golangci.yml exists; currently skipped when not installed
cd web && npm ci && npm test && npm run build && npx playwright test
helm lint deploy/helm/aegis && helm template deploy/helm/aegis >/dev/null
kubectl apply --dry-run=client -f deploy/kubernetes/
docker compose -f deploy/compose/docker-compose.yml config
```

**Targeted manual checks for the P0/P1 defects**

| Finding | Check | Expected after fix |
|---|---|---|
| §2.1 cross-tenant write | With org A's token: `curl -XPATCH …/assets/<org B asset id> -d '{"owner":"x"}'` | `404`; the row in B is unchanged (verify in psql) |
| §2.2 unscoped reads | Same token: `GET …/assets/<org B id>/{services,software,findings,interfaces}`, `GET /topology/evidence/<B edge>` | `404` |
| §2.3 XFF | `curl -H 'X-Forwarded-For: 1.2.3.4'` ×21 against `/auth/login` | `429` on the 21st; audit rows show the real peer IP |
| §2.4 readyz | Stop PostgreSQL, call `/readyz` | `503 {"status":"not_ready"}`; `/healthz` stays `200` |
| §2.5 suppressions | Suppress a finding, re-run correlation for that asset | Finding stays suppressed (or is marked `suppressed`), with reason and expiry visible |
| §2.6 webhooks | Create a webhook, trigger a detection match | Either a signed delivery arrives, or the endpoint is gone/`410` |
| §2.7 notes | `POST /assets/<id>/notes` as a viewer; then `GET` notes | `403` for viewer; notes readable by authorised users |
| §2.8 Helm/K8s | `helm lint`, `helm template`, deploy to a kind cluster, `env | grep AEGIS_` in the pod | Chart renders; env vars present; readiness passes on the metrics port |
| §2.9 scripts | `make dev-hybrid`, `make seed`, `make migrate-version`, `make e2e` | Each runs or the target/docs no longer exist |
| §2.10 gRPC TLS | Connect a connector over a public address; inspect with `tcpdump`/`openssl s_client` | TLS handshake; secrets not in clear text |
| §2.11 revocation | Log out, then replay a captured access token | `401` (or the documented short-TTL behaviour) |
| §3.14 ingest perms | `POST /events` as a viewer | `403` |

**Frontend checks**

- Findings page with >50 resolved rows in the window: the "Active" tab's rows and total must agree with `curl '…/findings?status=active&limit=1'`.
- Throttle the network or return 500 from a list endpoint: every page must show the error state (not "no data").
- Keyboard-only walkthrough of Findings/Assets/Scans (Tab/Enter/Space/⌘K/`?`).
- Lighthouse/axe on the eight main pages at 375/768/1280 px; record scores as the accessibility baseline.
- Bundle analysis (`npx vite-bundle-visualizer`) to confirm route splitting and the removal of recharts.

**Ongoing gates to add to CI** (from §3.11/§6.21): full Go test suite with a Postgres service, frontend Vitest + Playwright, `helm template` + `kubeconform`, OpenAPI validation, docs-path lint, migration up→down→up drill, image scan + SBOM.

---

## 9. Appendices

### Appendix A — Permission-gating inventory (authentication is universal; *authorisation* is not)

**Properly permission-gated (representative):** scan create/cancel (`scan:create`), report create (`report:create`), webhook create (`settings:manage`), asset write/delete/rediscover (`asset:write`, `finding:write`), finding read/write/bulk/suppress (`finding:read`/`finding:write`), detection rule create (`detection:manage`), match status (`finding:write`), vulnerability read (`vuln:read`), events read (`event:read`), alerts read/manage (`alert:read`), settings (`settings:manage`), users (`user:manage`), audit (`audit:read`), search actions (`vuln:read`/`finding:write`).

**Authenticated but not permission-gated (org-scoped only)** — verify each is intentional, because a `viewer` can call all of them: all asset reads and sub-resource reads, `GET /assets/{id}/traces`, `GET /scan-*` list/get/changes/tasks/logs, `GET /scanners`, `GET /schedules`, `GET /topology` + evidence, `GET /search`, `GET /metrics/*`, `GET /reports` + jobs + download, `GET /feeds`, `GET /webhooks`, `GET /detections/rules`, `GET /detections/matches`, `GET /vulnerability-search-actions/capabilities`.

**Inconsistent/wrong:**
- `POST /events` and `POST /sensors/{sensorID}/events` require **`event:read`** (`handlers_events.go:197,218`) — event *ingestion* must require a write permission (e.g. a new `event:write` granted to analyst/operator roles, or sensor-scoped credentials). Today any read-only account can inject telemetry that drives detections, alerts and the audit trail.
- `handleAddNote` (§2.7) — no permission check at all.
- The four asset sub-resource reads and topology evidence (§2.2) — no ownership resolution.
- `handleVulnSearchCapabilities` — informational, but runs a `count(*)` on shared tables without a permission check.

**Recommendation.** Generate this inventory mechanically: table-drive the route table with an explicit required-permission column, and add a test that enumerates every route in `server.go` and asserts it declares either a permission or an `OrgScopedOnly` marker. That prevents the next forgotten `requirePerm` without relying on review.

### Appendix B — Dead code and unused artefacts found

| Artefact | Location | Note |
|---|---|---|
| `var _ = <pkg>.<sym>` ×8 | `platform/objectstore.go:114`, `repository/postgres/repo_assets.go:713`, `repo_tenancy.go:602`, `transport/http/handlers_agents.go:200`, `handlers_core.go:432`, `handlers_core.go:453`, `handlers_events.go:241`, `middleware.go:396` | Import-keeping statements |
| `useDebounced` | `web/src/components/ui/index.tsx:400` | Zero callers (needed by §4.3) |
| `useSearch` | `web/src/lib/queries.ts:1460` | Zero callers; `/search` endpoint unused by the UI |
| `useDetectionRules`, `useCreateRule`, `useUpdateRule` | `web/src/lib/queries.ts:988-1019` | No rule-authoring UI |
| `useAddNote` + `const addNote` | `web/src/lib/queries.ts:1407`, `AssetDetailPage.tsx:98` | Unused and mis-contracted |
| `DataTable` + legacy kit | `web/src/components/table/DataTable.tsx`, `web/src/components/ui/index.tsx` | 5 importers remain |
| `tailwind.config.ts` | `web/tailwind.config.ts` | Dead under Tailwind v4 (`@theme` in `index.css`) |
| recharts | `web/src/pages/OverviewPage.tsx` only | Second chart library in the bundle |
| `SuppressionRepo.Active` | `repo_findings.go:387` | Zero callers (§2.5) |
| `NoteRepo.List` | `repo_findings.go:430` | No route exposes it |
| `WebhookRepo.Enabled/MarkFired`, `DetectionsEngine.Notifier` | `repo_detections.go`, `internal/detections` | Legacy webhook path (§2.6) |
| `ParseCSR` / dev CA path | `internal/transport/grpc/agent_server.go:424`, `internal/ca/ca.go` | Certificate issuance exists but nothing verifies client certs (§2.10) |
| `configs/*.yaml` | `configs/` | The loader is env-first and reads none of these files; they are documentation — state that in each file's header to avoid operators editing them expecting effect |

### Appendix C — Suggested tests to add (highest value first)

1. **Cross-tenant matrix:** a table-driven HTTP test that, for every route taking an object id, asserts a foreign-org id yields `404` and the object is unmodified. This single suite would have caught §2.1 and §2.2.
2. **Permission matrix:** every route × every role (5 roles) with expected status codes; fails on any new route without an explicit expectation.
3. **Suppression lifecycle:** suppress → correlate → assert no re-open → expire → assert re-open.
4. **Scope/denylist table tests:** bare IPs, ranges, CIDRs, deny subsets/supersets, public targets with/without `AllowPublicScope`, profile `max_targets` interaction (§3.1).
5. **Deployment smoke:** `helm template` + `kubeconform` in CI; a kind-based install that asserts the pod reaches Ready and `/readyz` returns `200` (§2.8).
6. **Frontend data-correctness:** MSW-backed tests asserting that the Findings "Active" filter sends `status=active` and renders the server total; that a 500 renders `ErrorState`; and that search inputs debounce (§4.1–§4.5).
7. **Realtime:** a Playwright test that connects the WS with a ticket (post-fix) and asserts re-subscription after a forced disconnect.
8. **Migration drill:** apply → roll back → apply on a scratch database (§3.8).

---

### Closing note

The engineering culture visible in this repository — the security model documents, the idempotency-by-construction alert engine, the scope-validation comments, the compose file's "never use `privileged: true`" note — is exactly the culture that fixes the findings above quickly. The highest-leverage hour of work in this report is the trusted-proxy + tenant-scoping pair (§2.1–§2.3); the highest-leverage quarter is the RLS/OpenAPI/test program (§6.21); and the features with the best value-to-effort ratio for the next release are API tokens (§6.3), the finding workflow (§6.4), and saved views/exports (§6.5).
