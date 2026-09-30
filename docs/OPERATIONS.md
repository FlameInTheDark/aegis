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

### Backup drill (quarterly)

A backup that has never been restored is a hypothesis, not a backup. Once a
quarter, in a maintenance window:

1. Restore Postgres from the latest dump into an **empty** volume
   (`scripts/restore.sh` against a scratch database, never the live one).
2. Boot the server against the restored volume.
3. Confirm `GET /readyz` reports every dependency healthy.
4. Confirm one organization's asset count matches the pre-drill value
   (`SELECT COUNT(*) FROM assets WHERE organization_id = '<org>'`), and
   spot-check one asset's identifiers and software rows.
5. Record the drill date and result in your run log. ClickHouse stays
   recoverable only inside its TTL window — telemetry older than the TTL is
   not expected to survive a restore and is not a drill failure.

### Transport path

One supported production transport: TLS terminates at a trusted ingress, and
device identity for agents comes from the agent CA (`AEGIS_AGENT_CA_CERT` /
`AEGIS_AGENT_CA_KEY`). A server started with `AEGIS_ENV=production` **refuses
to start** when the agent CA is absent — the same fail-fast rule the worker
applies to an unknown schema. Plaintext gRPC behind a trusted ingress remains
a development-only configuration.

## Routine tasks

- **Migrations** — applied on server boot via embedded golang-migrate; `make migrate-up` / `migrate-down` for manual control.
- **Feed rebuild** — restart `feed-worker` with `full=true` semantics; per-feed status in Settings → Feeds; failures are per-feed isolated.
- **ClickHouse retention** — TTL policies per table; tune to your storage budget.
- **Agent certificate revocation** — revoke agent in UI/API; tasks stop immediately, telemetry rejected.
- **Scanner rotation** — re-register scanner (name+site identity) or redeploy container; registration is idempotent.
- **Kill switch** — `POST /api/v1/scans/{id}/cancel` engages the scan kill switch; scanners stop between probes.

## Capacity notes

Targets: small site hundreds of assets, medium thousands, large tens of thousands. Horizontal scaling: worker replicas, scanner-per-site, ClickHouse/NATS clustering for enterprise profiles. Benchmark before optimizing.

### Scale measurements (fill in from a synthetic run)

Partitioning of `audit_logs`, `scan_observations`, and `finding_status_history`
(see `docs/DATA-MODEL.md`) is deferred **until a measured run shows sequential
scans of those heaps**. When you run a synthetic load, record the numbers here
so the decision is grounded in data, not vibes:

| Measurement | Value | How |
|---|---|---|
| `audit_logs` row count at measurement | | `SELECT COUNT(*) FROM audit_logs;` |
| `scan_observations` row count at measurement | | `SELECT COUNT(*) FROM scan_observations;` |
| asset list p95 (page of 100) | | timed `GET /api/v1/assets?limit=100` under load |
| finding list p95 (page of 100) | | timed `GET /api/v1/findings?limit=100` under load |
| audit list p95 (page of 100) | | timed `GET /api/v1/audit-log?limit=100` under load |
| scan observation insert rate | | scans/min x observations/scan during synthetic run |
| `pg_stat_user_tables.seq_scan` deltas on the three tables | | before/after the run |

Partition `audit_logs` and `scan_observations` by month only when the seq-scan
delta on those tables grows superlinearly with row count at acceptable list
latency. Do not re-open the question without new numbers.
