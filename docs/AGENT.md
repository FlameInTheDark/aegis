# Endpoint agent

One small Go binary (`cmd/agent`) for **Windows, Linux and macOS** (spec §16).

## Enrollment (spec §16)

```mermaid
sequenceDiagram
  Admin->>Platform: create enrollment token (one-time, 24h)
  Admin->>Endpoint: install agent with token
  Endpoint->>Endpoint: generate EC keypair locally
  Endpoint->>Platform: Enroll(token, CSR)
  Platform->>Platform: validate token, sign CSR with agent CA
  Platform-->>Endpoint: device certificate
  Note over Endpoint,Platform: all later traffic uses the device identity; private key never leaves the endpoint
```

Tokens are stored hashed, single-use, expiring, revocable, and audited at creation.

## Typed tasks only (spec §19)

`inventory_refresh · software_inventory · network_inventory · socket_inventory · security_posture · local_configuration_check · local_scan · diagnostic · configuration_sync`

There is **deliberately no arbitrary command execution capability** — the server cannot turn an agent into a remote shell.

## Collection (spec §17/§125)

| Capability | Linux source | Windows/macOS |
|---|---|---|
| system inventory | `/proc`, `/etc/os-release` | stdlib basics (native APIs planned) |
| software | `dpkg-query`, `rpm -qa`, `apk list` | none at `basic` level |
| network | `/proc/net/tcp*`, `/proc/net/route`, resolv.conf | fallback (empty) |
| posture | `/sys/firmware/efi` secure boot, heuristics | explicit `unknown` — never guessed |

Capabilities are configuration-gated (`basic_inventory`, `software_inventory`, `network_inventory`, `security_posture`, `process_inventory`, `local_scan`); collection levels map to `basic|standard|full`. The agent never collects passwords, browser secrets, process memory, or private files by default.

## Operational behavior (§124)

- heartbeats carry version/uptime; missed heartbeats mark the agent offline (worker housekeeping),
- bounded offline queue with event expiration when disconnected,
- config sync is a server-pushed typed payload, never executable content.
