# HTTP API

Base: `/api/v1` · Bearer JWT · JSON · structured errors `{error:{code,message,request_id}}` · offset pagination `{items,total,page,limit}`; cursor pagination for events.

## Endpoint map

| Group | Endpoints |
|---|---|
| auth | `POST /auth/login` `POST /auth/refresh` `POST /auth/logout` `GET /auth/me` |
| tenancy | `GET|POST /organizations` `GET|POST /sites` `GET|PATCH|DELETE /sites/{id}` `GET|POST /sites/{id}/networks` |
| groups | `GET|POST /asset-groups` `PATCH|DELETE /asset-groups/{id}` `PUT /asset-groups/{id}/assets` |
| assets | `GET /assets` `GET|PATCH|DELETE /assets/{id}` `GET /assets/{id}/{services,software,findings,interfaces,traces,metrics}` `POST /assets/{id}/notes` `POST /assets/{id}/rediscover` `GET /services` |
| topology | `GET /topology` `GET /topology/evidence/{edge}` |
| scans | `GET|POST /scans` `GET /scans/{id}` `POST /scans/{id}/cancel` `GET /scans/{id}/{changes,tasks}` `GET /scanners` `GET|POST /schedules` |
| vulnerabilities | `GET /vulnerabilities` `GET /vulnerabilities/{cve_id}` `GET|POST /findings` `GET|PATCH /findings/{id}` `POST /findings/bulk` `POST /findings/{id}/suppress` `GET /feeds` |
| detections | `GET|POST /detections/rules` `PATCH /detections/rules/{id}` `GET /detections/matches` `PATCH /detections/matches/{id}` |
| events | `GET /events` (cursor) `POST /events/ingest` `POST /sensors/{id}/events` |
| connections | `GET|POST /connectors` `GET|PATCH|DELETE /connectors/{id}` `PUT /connectors/{id}/config` `POST /connectors/{id}/{enroll-token,revoke}` |
| reports | `GET|POST /reports` `GET /reports/jobs/{id}` `GET /reports/jobs/{id}/download` |
| platform | `GET /search` `GET /metrics/{summary,timeseries}` `GET|PATCH /settings` `POST /settings/metrics/cleanup` `GET /audit-log` `GET|POST /webhooks` |
| health (unauthenticated) | `GET /healthz` `GET /readyz` |

## Examples

```bash
# login
curl -s localhost:8080/api/v1/auth/login -d '{"email":"admin@aegis.local","password":"aegis-demo-admin-2026"}'

# create a conservative discovery scan
curl -s localhost:8080/api/v1/scans -H "Authorization: Bearer $TOKEN" \
  -d '{"site_id":"<site>","name":"nightly","profile":"inventory","targets":["192.168.1.0/24"],"denylist":["192.168.1.1"]}'

# agent-less SSH inventory: per-scan hosts, each with its own credentials
# (auth: "password" or "key"; omit ssh_hosts entirely to reuse the SSH hosts
# configured on the scanner connection). Credentials are redacted ("***") in
# every read-back response.
curl -s localhost:8080/api/v1/scans -H "Authorization: Bearer $TOKEN" \
  -d '{"site_id":"<site>","profile":"ssh_inventory","targets":[],"ssh_hosts":[{"host":"10.0.0.5","port":22,"username":"scan","auth":"password","password":"s3cret"},{"host":"web.local","username":"deploy","auth":"key","key_pem":"-----BEGIN OPENSSH PRIVATE KEY-----..."}]}'
# pinned_key (optional, authorized_keys format) pins the host's SSH host key;
# ssh_insecure_host_key: true accepts any host key for this scan (lab use only).
# Scan detail exposes the per-host collection record under stats.ssh_hosts:
# OS fingerprint, package count, duration and the exact read-only commands
# executed (cmd/ok/lines) plus the per-host error, if any.

# poll progress (scope -> discovery -> ports -> services -> correlation -> completed)
curl -s localhost:8080/api/v1/scans/<id> -H "Authorization: Bearer $TOKEN"

# ingest a Suricata EVE record
curl -s localhost:8080/api/v1/events/ingest -H "Authorization: Bearer $TOKEN" \
  -d '{"source":"suricata","raw":{"timestamp":"2026-09-15T10:00:00Z","event_type":"alert","alert":{"signature_id":2027865,"severity":2},"src_ip":"10.0.0.9","dest_ip":"10.0.0.5","dest_port":445}}'
```

## Version normalization (CVE matching)

Every collected version — SSH `dpkg`/`rpm`/`apk`/`pacman` sweeps, endpoint agents, connector scanners, nmap `-sV` fingerprints — passes one ingestion normalization pass before it is stored:

- `software.version` keeps the raw collected string **verbatim** (audit evidence; dpkg-exact epoch/upstream/revision semantics are never rewritten).
- `software.version_norm` is the cleaned, grammar-canonical form the CVE pipeline compares against: scanner/banner noise stripped (`OpenSSH_10.0p2 Debian 7` -> `10.0p2`), validated and canonicalized under the package grammar (`0:1.0-1` -> `1.0-1`, Debian Policy / rpm / apk / SemVer / PEP 440). Empty until the row's next report refresh; matching falls back to the raw value meanwhile.
- Orderings are grammar-exact, overflow-free and never guessed: Debian versions follow dpkg's `verrevcmp` (`1.0~rc1 < 1.0 < 1.0-1 < 1.0-2ubuntu2 < 1.0-2ubuntu10`, revision-only Ubuntu security fixes compare correctly); malformed values are flagged (`well_formed=false` upstream) and treat as incomparable — they never match by accident.
- Vulnerability checks run on the normalized form: OSV ranges (`installed >= introduced && installed < fixed`), NVD/CVE-v5 CPE ranges and distro advisories (OVAL: `installed < fixed_in`, confidence 1.0). Findings evidence carries both sides (`version` normalized + `version_raw`, `installed` raw + `installed_norm`).
- **Version bounds are domain-aware**: a feed bound and the installed version may live in different comparison domains, and every comparison resolves the domain per bound before ordering. A distro-format bound (Ubuntu OVAL fixed-in `1:10.0p1-5ubuntu5.5`, rpm `8.0p1-6.el8`, apk `-rN`) orders fully under the distro grammar. An upstream-only bound — the `affected < 10.5` shape of OpenSSH CVEs — is projected to the installed version's upstream component first (`1:10.0p1-5ubuntu5.4` -> upstream `10.0p1`): the epoch and distro revision are packaging artifacts the CVE boundary must never see. When both sides are OpenSSH releases (`<release>[p<update>]`) the verdict is made in the structured OpenSSH domain (`10.0 < 10.0p1 < 10.0p2 < 10.1`, `10.0p1 < 10.5`, `10.5p1 > 10.5`); other upstream bounds (letter patch levels `1.0.2k`, tilde pre-releases `2.0~rc1`) order under dpkg upstream rules. Malformed or incomparable pairs never match.
- **Match evidence names the domain**: findings evidence carries `bound_domain` (the comparison grammar the verdict was made in: `debian`, `openssh`, `rpm`, `apk`, `upstream`, `semver`, `python`, `generic`), `projected_version` (the upstream part actually compared when a projection fired) and `constraint` (the domain-tagged `{domain, introduced, fixed, less_than, less_than_or_equal}` statement of the CVE's applicability window), so every verdict is auditable.
- **Service fingerprints normalize too**: banner-derived `service.detected_version` values like `10.0p2 Ubuntu 5ubuntu5.4` are composed into grammar-canonical deb versions (`10.0p2-5ubuntu5.4`) and stored in `service.version_norm`; `CorrelateService` matches CPE ranges against the normalized form, never the raw banner string.
- **`version_meta` on read**: the asset detail payload (`GET /api/v1/assets/{id}`) attaches a computed `version_meta` object to every service and software row — `{raw, normalized, well_formed, grammar, epoch?, upstream?, revision?}` — so clients can render the reported-vs-normalized breakdown (the UI shows it in the version tooltip) without re-parsing, including for rows whose raw value never normalizes.

Rate limits: auth 20/min/IP, events+ingest 120/min; scan/report creation permission-gated. Swagger/OpenAPI annotations live on every handler; generated docs served at `/swagger/index.html` when built (`make swagger`).

## Asset groups

Analyst-curated grouping of assets ("Room 1", "IoT devices") persisted in Postgres. Groups carry `name`, `description`, `color`/`icon` palette keys (resolved client-side) and a `kind` (`location|function|owner|custom`); `GET /asset-groups` returns every group with its member `asset_ids` inline so a UI can render per-asset chips from one call. Mutations (`POST/PATCH/DELETE`, `PUT /asset-groups/{id}/assets` with `{add:[], remove:[]}`) require `asset:write` and are audited; the insert's org guard silently skips asset ids from another organization. Membership cascades on group or asset deletion.

## Asset deletion

`DELETE /assets/{id}` (requires `asset:write`, audited, answers 204) removes a false discovery, a temporary host or a device that left the network. The asset row and every dependent record are removed in one cascading delete: identifiers, interfaces with their addresses, MACs, services with observations, software with observations, findings and group memberships. Scan-change history and traceroute evidence carry no foreign key and survive as the audit trail of what was observed. An endpoint device collecting data for the asset survives but is unlinked — its next inventory report re-provisions the asset (adopting a matching scan-side record when the evidence is unambiguous), and the next scan that sees the address re-creates a scan-side asset, so deletion is safe whenever rediscovery is acceptable and destructive to collected history regardless.

## Detection triage status

Detection matches carry a workflow `status` (`new|investigating|contained|closed`, default `new`). `PATCH /detections/matches/{id}` `{status}` transitions a match (requires `finding:write`) and writes an audit entry; `GET /detections/matches?status=` filters by state. The match queue is a workable triage list, not just a stream.

## List enrichment

- `GET /sites` rows include `asset_count` (one aggregate; the scope dropdown shows coverage per site).
- `GET /assets` rows include `findings: {critical, high, medium, low}` — open-finding severity counts per asset (matches the asset-detail `findings_count` semantics: open/acknowledged/in_progress count as open) and an `endpoint` object with the device collecting data for the asset (`null` for scan-only assets).
- `GET /connectors` and `GET /connectors/{id}` rows include a `device` object when the connection performs the agent function and has bound an endpoint: `{id, hostname, platform, platform_version, arch, version, status, last_seen, asset_id}`.
- `GET /assets/{id}` includes an `endpoint` object (`id`, `status`, `last_seen`, `version`, `platform`, `connector_id`, `connector_name`) describing the collector behind the asset.
- `GET /metrics/timeseries?metric=events` returns daily `{ts, value, by_category}` points (ClickHouse-backed) for stacked event-volume charts; `value` stays the day total for older clients.

## Device metrics

`GET /assets/{id}/metrics` returns the performance history collected by the asset's endpoint device. Two mutually exclusive query modes:

- **Tail (live)** — `?window=`, a preset (`1h|6h|24h|7d`), a duration (`30s`, `90`, `5m`, `2h`, `3d`) or bare seconds. The window always ends at *now*; clients poll it (`window=24h` at 30s is the historical default).
- **Range (static)** — `?from=<RFC3339>&to=<RFC3339>` (`to` defaults to now; span 10s…366d). A historical span never changes, so clients do not poll it.

The response carries the effective window so charts can label themselves:

```
{"points":[{"ts":"...","cpu_avg":12.4,"cpu_max":38.0,"mem_used":...,"mem_total":...,"rx_bps":...,"tx_bps":...,"uptime_secs":...}],
 "latest":{"timestamp":"...","cpu_percent":14.2,"rx_bps":...,"tx_bps":...,"mem_total":...,"mem_used":...,"uptime_secs":...,
            "ifaces":[{"name":"eth0","mac":"...","rx_bytes":...,"tx_bytes":...,"rx_bps":...,"tx_bps":...}]},
 "ifaces":[{"name":"eth0","rx":[...],"tx":[...]}],
 "window":"24h","from":"...","to":"...","bucket":900,"tail":true}
```

Bucket size is chosen automatically from a density ladder (10s … 1d) so a series renders ~240 points in tail mode and ~360 in range mode; the presets keep their historical buckets (1m / 5m / 15m / 1h). `ifaces` holds the per-NIC receive/transmit rate history (coarser buckets, ~60 points per interface) for sparklines. Samples arrive over gRPC (`SubmitMetricsBatch`) and are stored in the ClickHouse `device_metrics` table; retention is operator-configurable (see Platform settings), defaulting to 30 days. A deployment without the ClickHouse tier returns empty series. Assets without a bound endpoint return empty series as well.

## Platform settings

Deployment-wide operator settings, backed by the `settings` KV table. Reads are open to every authenticated user; changes require `settings:manage` and are audited.

- `GET /settings` returns the effective view plus a storage snapshot:

```
{"metrics":{"retention_days":30,"applied_days":30,
            "stats":{"rows":1234567,"oldest":"...","newest":"..."}}}
```

- `PATCH /settings` with `{"metrics":{"retention_days":N}}` — N days (0 keeps everything forever, max 3650). The retention loop syncs the ClickHouse `device_metrics` TTL immediately and purges everything beyond the new window; the response echoes the saved value.
- `POST /settings/metrics/cleanup` — run a purge at the configured retention right away (rejected while retention is 0). Waits up to 30s for the ClickHouse mutation and returns `{"status":"cleanup started","retention_days":30,"cutoff":"...","estimate_rows":N}`.

## WebSocket streaming

Realtime events ride one socket instead of short polling. Endpoint: `GET /api/v1/ws` (WebSocket upgrade; plain GET is answered 401 without a token, 426 with one).

Auth: the access JWT rides the `access_token` query parameter of the upgrade request (browsers hold the token in memory; a WS handshake cannot carry custom headers). The refresh cookie is deliberately not accepted for the socket. The server answers the same JWT rules as the HTTP middleware.

Client -> server frames (JSON):

```
{"type":"sub",   "channel":"scan:<scan_id>"}   // scan channels are org-checked (403-style error frame on foreign ids)
{"type":"sub",   "channel":"notify"}           // org notifications (scan lifecycle, findings raised)
{"type":"unsub", "channel":"..."}
{"type":"ping"}                                // keepalive; server answers {"type":"pong"}
```

Server -> client frames:

```
{"type":"hello",       "org":"...","user":"...","ts":"..."}   // on connect
{"type":"subscribed",  "channel":"..."} / {"type":"unsubscribed","channel":"..."}
{"type":"event",       "channel":"scan:<id>","kind":"log"|"state","data":{...},"ts":"..."}
{"type":"event",       "channel":"notify","kind":"notification","data":{...},"ts":"..."}
{"type":"pong"} / {"type":"error","message":"..."}
```

Event payloads: `log` is a `JobLogEvent` `{seq, scan_id, task_id, scanner_id, org_id, ts, level, source, msg, fields}` — `level` is `debug|info|warn|error`, `source` is `exec` (pipeline phases), `engine` (raw engine output, e.g. nmap stderr + argv), `ssh` (authenticated collection), `corr` (correlation), `server`. `state` is `{scan_id, org_id, state, phase, progress, stats, ts}`. `notification` is `{id, org_id, type, title, body, severity, ref, ts}` with types `scan.completed | scan.failed | findings.created`.

Job log history (persisted in `scan_job_logs`):

```
GET /api/v1/scans/{id}/logs?limit=500          # newest 500, ascending seq
GET /api/v1/scans/{id}/logs?limit=500&before=<seq>   # strictly older pages
-> {"items":[JobLogEvent...],"has_more":bool}
```

Sources: the shared scan pipeline (`internal/scanexec`) emits phase transitions, per-host results, port/service/OS/topology summaries, kill-switch and completion lines; the nmap engine tees argv and stderr lines; the SSH collector emits per-host connect/auth/collect results; hub/connector agents stream their lines inside hub `Report`s. Log lines are batched (250ms / 128 events) on persist and broadcast over core-NATS (`security.scan.log.v1`, `security.scan.state.v1`, `security.notification.v1`) so every replica fans out to its sockets while exactly one replica persists. Retention: `AEGIS_JOBLOG_RETENTION_DAYS` (default 7), swept by the worker.
