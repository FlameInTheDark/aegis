# Aegis Security Platform — Compose quickstart

This directory contains the full local deployment of the Aegis Security
Platform: control plane, workers, scanner, frontend and the data layer
(PostgreSQL, Redis, NATS JetStream, ClickHouse, RustFS).

> **Authorization notice.** Aegis is a *defensive* platform for networks you
> own or are explicitly authorized to assess. Scanning and monitoring targets
> without permission is illegal in most jurisdictions. The platform refuses
> public-internet scopes unless explicitly enabled (`AEGIS_SCAN_ALLOW_PUBLIC_SCOPES`).

## Quickstart

```bash
# from the repository root — the one-command path:
make dev                              # builds ALL images + starts the full stack
# equivalent by hand (use --build after pulling code changes):
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker compose -f deploy/compose/docker-compose.yml ps   # wait for healthy
```

Everything runs in containers: postgres, redis, nats, clickhouse, rustfs,
**server** (API :8080), **worker**, **feed-worker**, **scanner** and the
**frontend** (nginx-served SPA on :3000 proxying `/api` to the server). You
never need to start binaries by hand.

Open the UI at **http://localhost:3000** and log in with the bootstrap admin:

| Setting | Value (demo default) |
| -------- | ------------------------------------- |
| URL | http://localhost:3000 |
| User | `admin@aegis.local` |
| Password | `aegis-demo-admin-2026` |
| API | http://localhost:8080/api/v1 |
| Swagger | http://localhost:8080/swagger/index.html |

## What happens on first boot

1. **Migrations** — the server applies the embedded PostgreSQL migrations
 (`migrations/postgres/*.up.sql`) with golang-migrate, then applies the
 ClickHouse schema (`migrations/clickhouse/001_schema.sql`).
2. **Bootstrap admin** — the user from `AEGIS_BOOTSTRAP_ADMIN_EMAIL` /
 `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` is created with the `owner` role.
3. **Demo mode** — with `AEGIS_DEMO_MODE=true` (the compose default) a
 synthetic dataset is seeded: one organization (`aegis-demo`), HQ /
 Datacenter / Branch sites, VLANs, 14 assets, services, software, six CVEs
 with KEV/EPSS context, findings, detection rules and matches, and a 48-hour
 window of ClickHouse security events. Every demo row is tagged
 `demo_source = true`. To start clean instead, set `AEGIS_DEMO_MODE=false`
 and follow the first-run wizard (organization → site → networks → scanner
 → first discovery).

## First-run walkthrough

1. Log in and review the **Dashboard** (demo mode shows populated tiles).
2. **Sites & networks** — inspect the seeded sites or create your own; define
 the CIDRs/VLANs you are authorized to scan.
3. **Scanner** — the compose scanner registers as `scanner-local` and, when
 no `AEGIS_SCANNER_SITE_ID` is pinned, attaches itself to the platform's
 first site. Launch a `discovery_safe` scan against a small scope first
 (e.g. one /29).
4. **Inventory & findings** — watch assets, services and findings appear;
 findings carry risk scores with an explanation of every contributing factor.
5. **Feeds** — the feed-worker syncs KEV/EPSS/NVD/cvelistV5 concurrently on
 an interval (a slow NVD full pull never blocks the others); watch the
 `running`/`stale`/`healthy` status under **Feeds**, and kick a feed
 immediately with the sync button (POST `/api/v1/feeds/:name/sync`).
 Optional: set `AEGIS_NVD_API_KEY` for 50 req/30s on NVD. Air-gapped
 installs: see `scripts/generate-demo-vulns.sh` and `testdata/feeds/`.
6. **Agents** (optional) — create an enrollment token, install the agent
 binary on an endpoint, see docs/AGENT.md.
7. **Sensors** (optional) — enable the `sensors` profile for Suricata/Zeek
 log shipping (see the compose file comments and configs/suricata, configs/zeek).

## Common operations

```bash
# rebuild one service after code changes
docker compose -f deploy/compose/docker-compose.yml build server
docker compose -f deploy/compose/docker-compose.yml up -d server

# logs
docker compose -f deploy/compose/docker-compose.yml logs -f server worker

# monitoring profile (Prometheus on :9090, Grafana on :3300)
docker compose -f deploy/compose/docker-compose.yml --profile monitoring up -d

# stop everything, keep data
docker compose -f deploy/compose/docker-compose.yml down

# stop and delete all Aegis data (destructive!)
docker compose -f deploy/compose/docker-compose.yml down -v
```

## Environment & overrides

All services read the `x-common-env` anchor in `docker-compose.yml`; every
value can be overridden from a repo-root `.env` (see `.env.example`) or real
environment variables — for example `AEGIS_DEMO_MODE=false`,
`AEGIS_JWT_SECRET=<48+ random chars>`, `AEGIS_FEEDS_INTERVAL=1h`.

Only the server needs to be reachable by browsers/agents: the compose file
already publishes `8080` (HTTP API), `9090` (gRPC: agent transport **and**
external-connection enrollment) and `9091` (metrics). The data-layer
ports are bound to `127.0.0.1` by default so your workstation tools (and the
hybrid `./scripts/dev.sh` workflow with native binaries) can reach them
without exposing them to the LAN:

| Service | Host (127.0.0.1) | Container | Notes |
| ---------- | ---------------- | --------- | -------------------------------------- |
| PostgreSQL | 5432 | 5432 | `postgres://aegis:aegis@localhost:5432/aegis` |
| Redis | 6379 | 6379 | `redis://localhost:6379/0` |
| NATS | 4222 | 4222 | `nats://localhost:4222` |
| ClickHouse | 9000 | 9000 | native protocol, `?database=aegis` |
| RustFS S3 | 9001 | 9000 | host 9000 is taken by ClickHouse |
| RustFS UI | 9002 | 9001 | web console (login = S3 access/secret) |
| Server gRPC | 9090 | 9090 | published on all interfaces — endpoint agents, remote scanners and collectors enroll here |

### External connections (agents, remote scanners, collectors)

Create them under **Connections** in the UI: pick the kind, name it, and you
get a one-time command like

```bash
aegis-connector --connect localhost:9090/<one-time-token>
```

Run it on the target host once — the component enrolls over gRPC (port
`9090`, published by the compose file), receives its long-lived secret and
configuration, and from then on runs `aegis-connector start` (or
`aegis-connector install` for a systemd service). Reconnecting after a
network/address change: **Reconnect** in the UI rotates the token and hands
you a fresh one-time command.

The address inside the command comes from `AEGIS_CONNECTOR_PUBLIC_ADDR`
(default `localhost:9090` — correct for components running on the compose
host itself). If components join **from other machines**, set it in `.env`
to the host's DNS name or LAN IP, e.g. `AEGIS_CONNECTOR_PUBLIC_ADDR=aegis.example.com:9090`,
then `docker compose -f deploy/compose/docker-compose.yml up -d server`.
Details and the full protocol: `docs/CONNECTORS.md`.

### Traceroute & topology from containers

The `trace` profile maps LAN topology (device ↔ gateway ↔ device) reliably, but
**full hop-by-hop WAN traceroutes need ICMP Time Exceeded messages**, which the
NAT inside Docker Desktop (Windows/macOS) does not pass back into containers —
you will see only the first hop (`172.22.0.1`) followed by `* * *`. This is a
host virtualization limitation, not a scanner defect; the scanner already
falls back through TCP → UDP → ICMP → TCP-connect probes and finally `tracepath`
so at least the target-facing hops are visible, and marks partial paths instead of
reporting "no route". The container runs with a single capability (`cap_drop: ALL`
+ `cap_add: NET_RAW`) — never `privileged` — and ships `traceroute`, `tracepath`
and a self-check script. Verify capabilities and live paths with:

```bash
docker compose -f deploy/compose/docker-compose.yml exec scanner verify-traceroute
```

For complete paths run the
scanner on a Linux host with `network_mode: host` (see the commented block in
`docker-compose.yml`) or register a natively deployed scanner from another
machine on the LAN. Details: `docs/DEVELOPMENT.md → "Traceroute from containers"`.

## Demo data by hand

The demo dataset also exists as plain SQL for air-gapped installs or manual
seeding (the compose stack seeds automatically):

```bash
docker compose -f deploy/compose/docker-compose.yml exec -T postgres \
  psql -U aegis -d aegis < scripts/seed/demo.sql

docker compose -f deploy/compose/docker-compose.yml exec -T clickhouse \
  clickhouse-client --multiquery < scripts/seed/demo_clickhouse.sql
```

Backups, upgrades and operational procedures: see `docs/OPERATIONS.md`.
