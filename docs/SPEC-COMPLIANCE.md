# Spec compliance map

MVP checklist (spec §186) → implementation locations:

| # | Requirement | Where |
|---|---|---|
| 1 | Organization/site creation | `internal/organizations`, `cmd/server` bootstrap |
| 2 | Network scope | `internal/scanning/scope.go`, sites/networks API |
| 3 | Scanner registration | `cmd/scanner` `register()`, scanners API |
| 4 | Discovery scan | `internal/scanning/orchestrator.go`, `cmd/scanner` |
| 5 | TCP/UDP ports | `internal/scanner/engine.go` (nmap/simulated) |
| 6 | Service/version fingerprinting | nmap `-sV` adapter, `parseNmapService` |
| 7 | Basic topology | `internal/transport/http/handlers_assets.go` topology API, TopologyPage |
| 8 | Asset inventory | `internal/assets/inventory.go` |
| 9 | CVE/NVD/KEV/EPSS data | `internal/feeds`, `cmd/feed-worker` |
| 10 | Vulnerability matching | `internal/vulnerabilities/matcher.go` (+ table-driven tests) |
| 11 | Findings | `internal/vulnerabilities/correlate.go`, findings API/UI |
| 12 | Risk scoring | `internal/risk/engine.go` (explainable, §37) |
| 13 | Asset UI | `web/src/features/assets` |
| 14 | Finding UI | `web/src/features/findings` (bulk ops + confirmations) |
| 15 | Scan UI | `web/src/features/scans` (progress, tasks, changes, cancel) |
| 16 | Dashboard | `web/src/features/dashboard` |
| 17 | Docker Compose | `deploy/compose/docker-compose.yml` |
| 18 | Swagger | per-handler annotations; `make swagger` target |
| 19 | Agent registration | gRPC enroll (`api/proto`, `internal/transport/grpc`), enrollment tokens UI |
| 20 | Endpoint inventory | `internal/endpoint` (linux collectors), agent UI |

## Documented assumptions (§191)

- **gRPC transport security**: TLS terminates at the LB in container deployments; local dev runs plaintext gRPC with warnings. mTLS device-cert verification hook is present (`CertAgentID`).
- **Windows/macOS agent collectors**: stdlib basics; native registry/WMI/system_profiler integration planned.
- **OSV sync**: package-scoped matching instead of full-ecosystem dumps in v1.
- **CRON subset**: `M H * * *` daily and `@every <duration>` schedules; full parser is future work.
- **Swagger UI**: annotations exist on all handlers; generated docs served when `swag` output is committed by CI.
- **PG partitioning** deferred until measured (§77); ClickHouse carries high-volume history with TTL.
