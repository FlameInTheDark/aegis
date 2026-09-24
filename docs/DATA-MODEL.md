# Data model

## Identity strategy

UUIDv7 identifiers everywhere (`internal/ids`) — time-sortable and natively storable in UUID columns; **IP addresses are never primary keys** — the same RFC1918 address can exist at many sites.

## Core relationships

```
organization ─< site ─< network (CIDR/VLAN)
organization ─< user (membership w/ role)
site ─< asset ─< network_interface ─< ip_observation
asset ─< service (port/protocol identity, fingerprints, CPEs)
asset ─< software (PURL, ecosystem)
scan ─< scan_scope, scan_task, scan_observation
scan ─< change (deltas: NEW_ASSET, SERVICE_OPENED, ...)
service/software ─< finding ─< finding_evidence, finding_status_history
vulnerabilities (cve_id) ─< cpe_matches, references, epss snapshots, kev
detection_rule ─< detection_match
```

## Asset correlation

Identity weights: strong `agent_id/certificate 1.0`, `serial/machine_id 0.95`, `mac 0.9`, `ssh_hostkey 0.8`; medium `hostname/fqdn 0.6`; weak `ip 0.2`. Merges require strong or corroborated identity — **never** an IP match alone across time; stale IP observations (>14d) do not merge.

Endpoint inventory participates in the same identity model: applying a device's inventory records its identifiers (`machine_id`, `serial`, one `mac` per NIC, `hostname`, `fqdn`, and every usable interface address as `ip`) on the linked asset, and resolves an unlinked device to an existing asset in that order — machine id/serial, MAC, hostname/FQDN (ambiguous values match nothing), then the reported addresses within the device's site. An asset's displayed address is its highest-weighted `ip` identifier, recency as tie-break; the endpoint reports which of its addresses carries the management connection, and that one is stored above the plain `ip` weight. A device already linked to an asset adopts the organization asset that shares a reported MAC **and** holds one of its reported addresses (oldest first) when the linked asset claims none of them — the machine's original record wins over a pre-identity duplicate; converged links and MAC-only overlaps never move a link.

## Confidence & evidence

Fingerprints store `confidence` + `sources[]`; every finding carries structured evidence rows (`nmap_service`, `agent_package`, `http_header`, `tls_cert`, `cpe_match`, `banner`) — not just a sentence.

## Device metrics tier

Endpoint performance samples live in ClickHouse (`device_metrics`), one row per device per heartbeat interval (roughly every 30s): CPU utilization, device-total network rates, memory total/used/available, load averages, uptime and a JSON array of per-NIC counters. Ordered by `(timestamp, tenant_id, agent_id)`, partitioned by month, TTL 30 days — history older than 30 days expires in place, no sweep job. Chart queries aggregate with `toStartOfInterval` buckets (1m/5m/15m/1h) and never scan raw rows for rendering. Connection and asset views in Postgres join nothing from this tier; `asset.agent_id` is the key.

## Partitioning & retention

Current-state in Postgres; high-volume telemetry in ClickHouse with TTL (security/network/DNS/HTTP/TLS events and IDS alerts 90-180 days, device metrics 30 days); raw evidence in object storage; Redis strictly ephemeral. PostgreSQL partitioning is reserved for `scan_observations` / `audit_logs` / `finding_status_history` when measured workloads justify it.
