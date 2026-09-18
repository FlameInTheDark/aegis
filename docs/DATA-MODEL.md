# Data model (spec §75)

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

## Asset correlation (spec §25)

Identity weights: strong `agent_id/certificate 1.0`, `serial/machine_id 0.95`, `mac 0.9`, `ssh_hostkey 0.8`; medium `hostname/fqdn 0.6`; weak `ip 0.2`. Merges require strong or corroborated identity — **never** an IP match alone across time; stale IP observations (>14d) do not merge.

## Confidence & evidence (§9/§73)

Fingerprints store `confidence` + `sources[]`; every finding carries structured evidence rows (`nmap_service`, `agent_package`, `http_header`, `tls_cert`, `cpe_match`, `banner`) — not just a sentence.

## Partitioning & retention (§74/§77)

Current-state in Postgres; high-volume telemetry in ClickHouse with TTL; raw evidence in object storage; Redis strictly ephemeral. PostgreSQL partitioning is reserved for `scan_observations` / `audit_logs` / `finding_status_history` when measured workloads justify it.
