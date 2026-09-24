# Operations

## Health & observability

- `/healthz` (liveness), `/readyz` (readiness with per-dependency status), Prometheus `/metrics`.
- Structured JSON logs with request IDs; OpenTelemetry OTLP export optional via config.

## Backups

| Store | Method | Notes |
|---|---|---|
| PostgreSQL | `pg_dump`/`pg_basebackup` or managed snapshots | authoritative operational data |
| ClickHouse | `clickhouse-backup` or per-table `BACKUP` statements | time-bounded telemetry; loss is acceptable within retention |
| Object storage | bucket versioning/replication | report artifacts, feed snapshots |
| NATS | file-based JetStream volumes | queue data is re-derivable |
| Redis | none required | strictly non-authoritative |

See `scripts/backup.sh` / `scripts/restore.sh` (require `CONFIRM=yes`).

## Routine tasks

- **Migrations** — applied on server boot via embedded golang-migrate; `make migrate-up` / `migrate-down` for manual control.
- **Feed rebuild** — restart `feed-worker` with `full=true` semantics; per-feed status in Settings → Feeds; failures are per-feed isolated.
- **ClickHouse retention** — TTL policies per table; tune to your storage budget.
- **Agent certificate revocation** — revoke agent in UI/API; tasks stop immediately, telemetry rejected.
- **Scanner rotation** — re-register scanner (name+site identity) or redeploy container; registration is idempotent.
- **Kill switch** — `POST /api/v1/scans/{id}/cancel` engages the scan kill switch; scanners stop between probes.

## Capacity notes

Targets: small site hundreds of assets, medium thousands, large tens of thousands. Horizontal scaling: worker replicas, scanner-per-site, ClickHouse/NATS clustering for enterprise profiles. Benchmark before optimizing.
