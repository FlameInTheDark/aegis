# Development

## Prerequisites

Go 1.27+, Node 22+ (npm), Docker (for the data layer), buf (protobuf, for regenerating agent protocol code).

## Setup

```bash
make dev              # FULL stack in docker compose: builds images for
                      # server/worker/scanner/feed-worker/frontend, starts
                      # everything (UI on :3000, API on :8080)

make dev-hybrid       # alternative: docker data layer only + one server boot
                      # (migrations + bootstrap); run Go binaries natively
                      # with make run-server / run-worker / run-scanner /
                      # run-feed-worker
```

For the hybrid workflow the data layer is reachable from the host (ports
published on 127.0.0.1 — 5432 postgres, 6379 redis, 4222 nats, 9000
clickhouse-native, 9001 rustfs S3 API):

```bash
AEGIS_DATABASE_URL=postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable \
AEGIS_REDIS_URL=redis://localhost:6379/0 AEGIS_NATS_URL=nats://localhost:4222 \
AEGIS_CLICKHOUSE_URL='clickhouse://aegis:aegis-ch-dev@localhost:9000?database=aegis' \
AEGIS_S3_ENDPOINT=http://localhost:9001 AEGIS_S3_BUCKET=aegis \
AEGIS_S3_ACCESS_KEY=aegis AEGIS_S3_SECRET_KEY=aegis-secret-change-me \
AEGIS_JWT_SECRET=change-me-32-bytes-min-secret-key \
AEGIS_BOOTSTRAP_ADMIN_EMAIL=admin@aegis.local \
AEGIS_BOOTSTRAP_ADMIN_PASSWORD=aegis-demo-admin-2026 \
./bin/aegis-server
```

Config accepts both the `AEGIS_`-prefixed names above and the bare names in
`.env.example` (`DATABASE_URL`, `REDIS_URL`, …) — `AEGIS_` wins when both are
set.

Migrations are embedded and applied on boot; `make migrate-up` / `make migrate-down` / `make migrate-version` for manual control.

## Testing & quality

```bash
make test             # go test ./...
make lint             # gofmt -l + go vet
cd web && npm ci && npm run build
```

Test suites cover the matching engine (table-driven CPE/range/OSV/heuristic cases), scope safety validation, the risk engine and RBAC. Feed and sensor fixtures live in `testdata/` — synthetic only; the suite never touches real networks.

## Adding a migration

Create `migrations/postgres/00NN_name.{up,down}.sql` (embedded automatically). Never mutate schema in startup code. The CI job fails when an `.up.sql` lacks its `.down.sql` pair.

## Frontend

Vite dev server proxies `/api` to `:8080`. Components live under `src/components` (primitives: DataTable, charts with a shared ECharts theme); features under `src/features/*`. URL-persisted filters, command palette (⌘K), keyboard chords (`g a`, `g s`, `g v`, `g e`).

## Traceroute from containers

Traceroute (and nmap `--traceroute`) has a hard physical limit: **intermediate hops are only ever visible via ICMP Time Exceeded messages**, which the routers on the path generate when a probe's TTL expires. The target itself always answers with a normal reply (TCP RST / SYN-ACK / ICMP echo), but every hop in between requires that ICMP error to travel back through the network stack to the scanner.

Inside Docker this fails frequently:

- **Docker Desktop (Windows/macOS)** runs containers inside a VM whose user-space NAT (VPNKit/WSL2 stack) does not translate ICMP Time Exceeded messages back into the container. Symptom: hop 1 (the Docker bridge gateway, e.g. `172.22.0.1`) responds, everything beyond shows `* * *`. No probe type fixes this from inside the VM — it is the host's NAT behavior, not a scanner bug.
- **Plain Docker Engine (Linux)** uses iptables/nftables conntrack, which handles RELATED ICMP correctly in the default configuration, so traceroute usually works; the scanner container already ships with `cap_add: NET_RAW`.

What Aegis does to cope:

1. The traceroute engine uses a five-step probe ladder, most NAT-friendly first:
 TCP SYN+ACK probes (`-PS`/`-PA`) → **UDP probes (`-PU`, elicit ICMP port-unreachable from the target)** → ICMP echo (`-PE -PP`) → TCP-connect trace (`-sT --traceroute`, whose *target* reply is a plain RST that survives NATs) → **the standalone `tracepath` binary** (UDP-based, needs no raw sockets at all; the scanner image ships it, `AEGIS_SCANNER_TRACEPATH_PATH` overrides the lookup). The first attempt that returns any hops wins; the chosen method is recorded on the topology observation.
2. **Blocked probes are never "no route"**: unresponsive hops are simply absent from the path (TTL gaps), partial paths link the deepest reachable hop to the asset with an `observed_through` edge, and when *every* method fails the observation is emitted as `method: gateway-guess` at low confidence (0.5) instead of being dropped — the topology still shows the subnet structure while honestly flagging it as inferred.
3. The scanner container ships `traceroute` (UDP/ICMP/TCP probe methods), `tracepath` and `iproute2`, and a built-in verification script: `docker compose exec scanner verify-traceroute` checks the container's capabilities (NET_RAW), file caps on nmap/traceroute, `ip route`, and runs live UDP/ICMP/TCP traceroutes plus tracepath against 1.1.1.1, ending with plain-language verdicts (whether TCP/443 reached the target — the decisive signal — and whether nmap emitted traceroute XML).

If you need full WAN paths:

- On **Linux** hosts, run the scanner with `network_mode: host` (uncomment in `deploy/compose/docker-compose.yml`) — probes then leave with the host's own stack and every hop is visible.
- On **Docker Desktop**, accept partial paths inside the container, or deploy the scanner binary natively on the Windows/macOS host (or another machine on the LAN) and register it against the server — `cmd/scanner` runs outside Docker fine.

## Regenerating protobuf

```bash
cd api/proto && buf generate   # writes api/gen
```
