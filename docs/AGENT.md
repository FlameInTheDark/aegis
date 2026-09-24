# Endpoint devices (connections performing the agent function)

An endpoint is a **connection performing the agent function** running
`aegis-connector` (see [CONNECTORS.md](CONNECTORS.md)): one enrollment
protocol, one credential file, one liveness system for every externally
connected component. An agent-kind connection carries the function by
default; any other kind with `agent.enabled` toggled on in its settings
binds a device the same way (hybrid operation).

A bound device is an **asset**: its inventory merges into the asset record
(never a separate registry), the Connections page shows the device on its
connection, and the asset detail's Performance tab charts its CPU, memory
and network history.

## Enrollment

```mermaid
sequenceDiagram
  Admin->>Platform: create agent-kind connection (one-time connect command)
  Admin->>Endpoint: aegis-connector --connect host:port/<token>
  Endpoint->>Platform: ConnectorService.Enroll(token)
  Platform-->>Endpoint: connector_id + long-lived secret + config
  Endpoint->>Endpoint: generate EC keypair locally
  Endpoint->>Platform: ConnectorService.BindDevice(csr) [connector secret auth]
  Platform->>Platform: create/refresh bound device record, sign CSR with agent CA
  Platform-->>Endpoint: device certificate
  Note over Endpoint,Platform: the private key never leaves the endpoint; the device record is bound 1:1 to the connector
```

Connect tokens are stored hashed, single-use, expiring, revocable, and audited at creation.

## Identity and isolation

- Every data-plane RPC (inventory, tasks, telemetry) authenticates with the
  **connector credentials** (`x-aegis-connector-id` / `x-aegis-connector-secret`
  metadata) and is resolved to the connector's **bound device record**.
- A client-asserted `agent_id` is ignored by the server: the data plane cannot
  be used to impersonate another endpoint.
- Revoking a connector instantly cuts off its device: authentication fails and
  the device row stops reporting.

## Typed tasks only

`inventory_refresh · software_inventory · network_inventory · socket_inventory · security_posture · local_configuration_check · local_scan · diagnostic · configuration_sync`

There is **deliberately no arbitrary command execution capability** — the server cannot turn a device into a remote shell.

## Collection

| Capability | Linux source | Windows/macOS |
|---|---|---|
| system inventory | `/proc`, `/etc/os-release`, gopsutil | gopsutil (CPU model/cores, memory, uptime, kernel) plus the registry edition/release/build |
| software | `dpkg-query`, `rpm -qa`, `apk list` | none at `basic` level |
| network | `/proc/net/tcp*`, `/proc/net/route`, resolv.conf, gopsutil NICs | gopsutil NICs (name, MAC, IPs, MTU, up/down) |
| disks | gopsutil per-mount capacity | gopsutil per-mount capacity |
| posture | `/sys/firmware/efi` secure boot, heuristics | explicit `unknown` — never guessed |
| performance metrics | gopsutil (all platforms) | gopsutil (all platforms) |

The inventory additionally names the device's **management address**: the
source address of its connection toward the hub (deterministically
probed through the routing table, with an interface-scan fallback). The
hub records it — together with every interface MAC, the usable
addresses, machine id, serial, hostname and FQDN — as identity
identifiers of the device's asset.

Every address observed on a NIC is recorded — IPv4 and IPv6, global and
link-local — so the interface table is a complete view of the host's
addressing, and each interface carries exactly one primary address chosen
by reachability: the management address when the interface carries it,
else the first global IPv4, else the first global IPv6. The displayed
address never depends on the operating system's enumeration order (which
frequently reports IPv6 before IPv4).

Capabilities are configuration-gated (`basic_inventory`, `software_inventory`, `network_inventory`, `security_posture`, `process_inventory`, `local_scan`); collection levels map to `basic|standard|full` and are set per connection in the UI (`agent.collection_level` connection setting — the `agent` section — hot-reloaded; the legacy flat `collection_level` key is still honored). The device never collects passwords, browser secrets, process memory, or private files by default.

## Asset identity

The operating system is reported from the platform's own identity source:
the registry (`ProductName`, `DisplayVersion`, build with update revision)
on Windows, `PRETTY_NAME`/`VERSION_ID` from `/etc/os-release` on Linux and
the product version on macOS — displayed as e.g. "Windows 11 Pro 24H2
(build 26100.2894)". Interface addresses are reported as plain literals
(prefix length and IPv6 zone stripped).

When a bound device submits its first inventory, the hub resolves its
asset instead of always creating one: machine id and serial first, then
any interface MAC, then hostname/FQDN (ambiguous values match nothing),
then the reported addresses within the site. A machine the scanner
already discovered therefore gains its endpoint data on the existing
asset record; a device whose linked asset was deleted re-resolves the
same way on the next inventory.

A connection created without a site assignment binds its device to the
organization's first site — a device (and its asset) cannot exist without
one.

A device that is already linked re-checks its link once it reports
hardware identity: if the linked asset claims none of the reported
addresses while another asset of the organization shares a reported MAC
and holds a reported address (the machine's original, scan-created
record), the device adopts it. A link whose asset already holds a
reported address is converged and never re-evaluated; a shared MAC alone
never moves a link.

## Performance metrics

The endpoint collector takes one performance sample per **probe rate** and
flushes the buffered samples to the hub at the **pull rate**, so a fast
probe never turns into one request per sample:

- **probe rate** (`agent.probe_rate_ms`, default 5000 — floor 100ms,
 ceiling 1h) — how often a sample is taken from the system,
- **pull rate** (`agent.pull_rate_ms`, default 30000) — how often every
 buffered sample is sent in ONE batched call; a pull faster than the
 probe is clamped up on the agent, and the buffer is cut off at 1200
 samples so pathological rate combinations stay bounded,
- both keys live in the connection settings (`agent` section, editable in
 the connector configuration dialog's Agent tab) and hot-reload within
 one loop iteration — no restart,

Each sample carries:

- **CPU** utilization (0-100) measured over the interval since the previous SAMPLE (not the previous pull),
- **memory** total/used/available,
- **per-NIC counters** (bytes/packets since boot) with byte rates computed over the sample interval,
- **load averages** (1/5/15 min; zeros on platforms without load averages) and host uptime.

On shutdown the loop flushes whatever is still buffered (5s best-effort),
so a graceful stop does not discard the samples since the last pull. The
batched submission degrades to per-sample requests against an older hub
that predates the batch RPC.

The hub stores samples in the ClickHouse `device_metrics` table
(30-day retention, partitioned by month) and serves them at
`GET /assets/{id}/metrics` — charted in the asset detail's Performance
tab (current load, CPU, memory, throughput, per-interface table).
Without the ClickHouse tier the collector still runs; samples are
dropped with a one-time note in the connector log.

## Operational behavior

- connector heartbeats carry version/uptime/role status; missed heartbeats mark the connection offline (worker housekeeping),
- the endpoint loop retries transient data-plane failures with backoff while the connector session stays in charge of liveness,
- device state (`agent.json`, key material, device certificate) lives next to the connector config file (`<dir>/endpoint/`),
- the connector secret is never copied into the device state file,
- bounded offline queue with event expiration when disconnected,
- config sync is a server-pushed typed payload, never executable content.
