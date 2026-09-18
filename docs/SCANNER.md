# Scanner architecture

## Safety model (spec §13)

| Profile | Discovery | Ports | Service detect | OS detect | NSE | Validation | Requires |
|---|---|---|---|---|---|---|---|
| `discovery_safe` | yes | top 100 | — | — | no | no | — |
| `inventory` | yes | top 1000 + UDP 50 | yes | yes | safe only | no | — |
| `vulnerability_safe` | yes | top 1000 | yes | yes | safe only | safe templates | — |
| `active_validation` | yes | top 1000 | yes | yes | safe only | active probes | `scan:elevated` + explicit confirmation |
| `full_audit` | yes | all 65535 | yes | yes | — | no | warning (loud + slow) |
| `trace` | yes | — | — | — | no | no | — (ping sweep + traceroute only) |
| `fingerprint` | yes | top 100 | light (`-sV --version-light` batch) | yes | no | no | — (device/OS classification pass) |

### Phase timeouts (`--host-timeout`)

The engine sizes the budget **per phase** — a single fixed 30s used to abort
the `-O` run (which first performs its own port scan) and full-range sweeps
before nmap emitted any data:

| Phase | Budget |
|---|---|
| host discovery | 60s |
| port scan | scaled: `ports/rate × 4 + 60s`, min 2 min, max 25 min |
| service fingerprint (per port) | 90s |
| OS fingerprint | 5 min, `--osscan-guess` reports near matches |
| traceroute (per attempt) | 90s |
| light service pass (per host) | 120s |

`AEGIS_SCAN_TIMEOUT` / scan config `timeout_secs` act as a floor — explicit
values can only extend a phase budget, never strangle it.

### Software + OS from service fingerprints

`-sV` product/version/CPE results are persisted twice: as the service entry
(services tab) and as a **software** row (software tab), so "what is running
behind the port" is visible without an endpoint agent. The OS CPE nmap
appends to service fingerprints (`cpe:/o:linux:linux_kernel`, the "Service
Info: OS: Linux" line) feeds `os_family`/`os_name` even on hosts whose raw
`-O` probes are filtered — typical for container-born scans.

Every scan records its exact, reproducible configuration (§11). Cancellation polls the kill switch between probes.

## Scope safety (spec §70)

`internal/scanning/scope.go` normalizes and validates every target set before execution:

- CIDR/IP-range/hostname parsing with hard error on garbage input,
- expansion ceiling + profile max-target enforcement,
- public-address rejection unless the deployment explicitly allows public scopes,
- hostname SSRF/injection screening (localhost, metadata endpoints, shell metacharacters),
- denylist overrides everything.

## Engine adapters (spec §12)

External engines are wrapped, never reimplemented: `internal/scanner`.

- **Nmap** (`NmapEngine`) — `-sn` discovery, `-sS` SYN port scan, `-sV --version-intensity 5` fingerprinting (plus a batched `-sV --version-light` pass for light profiles), `-O --osscan-guess` with bounded port specs (no `--osscan-limit`: it skips hosts whose closed ports NAT renders as filtered), NSE restricted to `--script safe` (never `vuln`/`exploit` categories, §145).
- **Simulated** (`SimulatedEngine`) — deterministic synthetic results for demo mode, tests and air-gapped evaluation; all records tagged `simulated`.
- ZGrab2 / Nuclei extension points follow the same adapter shape (typed config → argument arrays).

All external execution (§12/§82/§71): `exec.CommandContext`, argument arrays (never a shell), validated targets, hard runtime timeout, capped stdout/stderr, exit codes captured, stderr separated, engine versions recorded.

## Distributed scanners (spec §69)

Scanners register with `{scanner_id, site_id, capabilities[], version, health, last_seen}` and are site-bound so the scheduler only dispatches work they can actually reach. Capabilities: `ipv4 ipv6 raw_packets snmp nmap zgrab nuclei masscan simulated`.

## Resource limits (spec §71)

| Limit | Default |
|---|---|
| max runtime per engine run | 30 min |
| max stdout / stderr | 64 MiB / 1 MiB |
| max targets per scan | profile-bound (4096–8192) |
| max packet rate | profile-bound (100–300 pps) |

## Change detection (spec §26)

Observations flow through the inventory service which records deltas (`NEW_ASSET`, `SERVICE_OPENED`, `VERSION_CHANGED`, …) shown per site and per scan.
