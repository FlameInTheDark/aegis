# Alerts: Trigger Engine

The alert-trigger engine evaluates operator-defined conditions against
reliable domain transitions and device metrics, persists every episode in
PostgreSQL, and delivers notifications to configured destinations. It is
independent of the sensor detection engine (`DETECTION-ENGINE.md`):
detection rules correlate security events inside a time window; alert
triggers evaluate business-level conditions (new devices, findings, scan
and feed state, metric thresholds) with activation, recovery, cooldown and
repeat semantics.

## Concepts

- **Event** — a versioned envelope (`TriggerEvent`) describing one domain
  transition: `asset.discovered`, `service.discovered`, `software.installed`,
  `finding.created`, `finding.status_changed`, `scan.state_changed`,
  `agent.state_changed`, `device.bound`, `feed.sync.completed/partial/failed`,
  `feed.stale`/`feed.recovered`, `detection.match.created`,
  `vulnerability.index.updated`. Events are written to a transactional
  outbox next to the mutation that caused them, relayed to a dedicated
  JetStream stream, and applied to triggers by the worker's evaluator.
- **Trigger** — an organization-scoped rule of two kinds:
  - `event` — fires on selected event types, optionally narrowed by a
    typed condition DSL (`all`/`any` groups over fields with `eq`, `in`,
    `gt`, `contains`, `regex`, …). Optional recovery event types resolve
    matching open occurrences (e.g. `feed.recovered` resolves `feed.stale`).
  - `device_metric` — evaluates a ClickHouse rolling window per device
    (`cpu_percent`, `mem_used_percent`, `rx_bps`, `tx_bps`, `load1/5/15`)
    with an aggregation (`avg`, `min`, `max`, `p95`, `sum`, `count`), a
    comparison threshold, an activation duration, a recovery duration and
    an optional hysteresis threshold.
- **Occurrence** — one alert episode (`firing` → `acknowledged` →
  `recovered`, or `suppressed`). A partial unique index guarantees one
  open occurrence per trigger/fingerprint, so duplicate, replayed or
  delayed events can never open a second episode. Every lifecycle change
  is an append-only transition row.
- **Delivery** — per occurrence and destination. Webhook deliveries carry
  an HMAC-SHA256 signature (`X-Aegis-Signature: sha256=<hex>`), retry with
  exponential backoff up to five attempts, and dead-letter afterwards for
  manual replay. The console alert itself is always available regardless
  of destinations.

## Safety properties

- Missing metric data never reads as healthy: the missing-data policy
  (`ignore`, `trigger`, `resolve`) decides, and a ClickHouse outage leaves
  prior state untouched while marking the trigger degraded.
- Alert state lives in PostgreSQL only; NATS/WebSocket notifications are
  post-commit hints, and the REST list is the recovery path.
- Webhook URLs must be HTTPS in production (an explicit development flag
  allows plain HTTP and loopback targets), redirect targets are never
  followed, link-local metadata addresses are always rejected, and
  response size plus request timeout are bounded.
- Deleting or disabling a trigger preserves occurrences and history.

## Using the console

The **Alerts** area has four views:

- **Active** — open occurrences with severity filters, evidence snapshot,
  transition timeline, delivery attempts, and acknowledge/resolve actions.
- **History** — resolved and suppressed occurrences with their timeline.
- **Trigger rules** — the visual editor (basics, scope, trigger source,
  conditions, behavior, destinations, review) with server-side preview and
  bounded test runs. Preview validates against current data without
  creating alerts; a test distinguishes "no sample", "no match" and
  "matched" instead of presenting an empty result as success.
- **Destinations** — webhook management with masked secrets, test
  delivery, per-destination delivery health and dead-letter replay.

Every alert is visible in the console by itself; destinations add
delivery, they do not gate visibility.

## API surface

All endpoints are organization-scoped and require `alert:read`
(`viewer` and up) or `alert:manage` (`security_analyst` and up):

```
GET    /api/v1/alerts/capabilities
GET    /api/v1/alerts
GET    /api/v1/alerts/:id
POST   /api/v1/alerts/:id/acknowledge
POST   /api/v1/alerts/:id/resolve
GET    /api/v1/alerts/triggers
POST   /api/v1/alerts/triggers
GET    /api/v1/alerts/triggers/:id
PUT    /api/v1/alerts/triggers/:id
PATCH  /api/v1/alerts/triggers/:id/enabled
DELETE /api/v1/alerts/triggers/:id
POST   /api/v1/alerts/triggers/preview
POST   /api/v1/alerts/triggers/:id/test
GET    /api/v1/alerts/destinations
POST   /api/v1/alerts/destinations
PATCH  /api/v1/alerts/destinations/:id
DELETE /api/v1/alerts/destinations/:id
POST   /api/v1/alerts/destinations/:id/test
POST   /api/v1/alerts/destinations/:id/replay
GET    /api/v1/alerts/health
```

Trigger updates use optimistic concurrency: the stored `revision` must
match on update, otherwise the API returns `409` and the editor keeps the
draft.

## Vulnerability search actions

Configured search actions complement the automatic matcher. An action
selects inventory targets (software packages or network services) by a
bounded field selector and evaluates them against the local indexes only
(`cpe`, `cve_affected`, `osv`, `oval`). Sources are an allowlist — an
action cannot encode a URL, command, SQL or script. Modes: `shadow`
(explains matches without writing findings), `augment` (writes findings
with per-match provenance recording the action revision, source, CPE key
and observed identity), `fallback_only`. Runs are durable, idempotent
jobs executed by the worker; preview is read-only.

```
GET    /api/v1/vulnerability-search-actions/capabilities
GET    /api/v1/vulnerability-search-actions
POST   /api/v1/vulnerability-search-actions
GET    /api/v1/vulnerability-search-actions/:id
PUT    /api/v1/vulnerability-search-actions/:id
DELETE /api/v1/vulnerability-search-actions/:id
POST   /api/v1/vulnerability-search-actions/preview
POST   /api/v1/vulnerability-search-actions/:id/runs
GET    /api/v1/vulnerability-search-runs/:id
POST   /api/v1/vulnerabilities/match/search
GET    /api/v1/assets/:id/vulnerability-diagnostics
```

The asset page exposes the match workbench per service/software row
(Diagnostics), and the vulnerabilities page hosts action management under
Search actions.

## Worker operations

The worker runs the outbox relay, the event evaluator, the periodic
metric evaluator (30s), the delivery worker and the correlation-job
worker. It exposes `/metrics`, `/healthz` and `/readyz` on the metrics
listener (`AEGIS_METRICS_ADDR`, default `:9100`); readiness requires a
reachable PostgreSQL and a schema at the embedded migration version — a
worker against a missing, dirty or older schema refuses job claims and
reports 503 rather than evaluating on incomplete state.

Rollback of the feature does not require destructive migrations: the
tables are additive, and disabling evaluation leaves state and history
intact for later re-enabling.
