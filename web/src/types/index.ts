// Domain types mirroring the Go API contract.
export interface User {
  id: string
  email: string
  name: string
}

export interface Org {
  id: string
  name: string
  slug: string
  role: string
}

export interface Me {
  user: User
  organizations: Org[]
  current_organization_id: string
}

export interface Site {
  id: string
  organization_id: string
  name: string
  description?: string
  site_type: string
  created_at: string
  updated_at: string
}

export interface Network {
  id: string
  site_id: string
  cidr: string
  name?: string
  vlan_id?: number | null
  gateway?: string
  exposure: string
}

export interface Asset {
  id: string
  organization_id: string
  site_id: string
  hostname?: string
  fqdn?: string
  vendor?: string
  model?: string
  device_type: string
  os_family?: string
  os_name?: string
  os_version?: string
  os_confidence: number
  os_sources?: string[]
  exposure: string
  criticality: string
  risk_score: number
  risk_explanation?: string
  has_agent: boolean
  agent_id?: string | null
  tags?: string[]
  owner?: string
  notes?: string
  primary_ip?: string
  first_seen: string
  last_seen: string
  demo_source?: boolean
}

// deviceTypeLabels mirrors the backend taxonomy (domain.DeviceType.Label).

/**
 * Read-time normalization detail attached to version fields: the verbatim
 * reported string, the normalized form CVE matching actually compares,
 * and the parsed structure (epoch/upstream/revision) behind it.
 */
export interface VersionMeta {
  raw: string
  normalized: string
  well_formed: boolean
  grammar: string
  epoch?: number
  upstream?: string
  revision?: string
}

export interface Service {
  id: string
  asset_id: string
  protocol: string
  port: number
  service_name?: string
  product?: string
  vendor?: string
  detected_version?: string
  /** Ingestion-normalized banner version ("10.0p2 Ubuntu 5ubuntu5.4" → "10.0p2-5ubuntu5.4") — what CVE matching compares. */
  version_norm?: string
  version_meta?: VersionMeta
  version_confidence?: number
  cpes?: string[]
  banner?: string
  confidence: number
  exposure: string
  flags?: string[]
  state: string
  first_seen: string
  last_seen: string
}

export interface Software {
  id: string
  name: string
  version?: string
  /** Ingestion-normalized form (noise stripped, grammar-canonical) — what CVE matching compares. */
  version_norm?: string
  version_meta?: VersionMeta
  ecosystem?: string
  purl?: string
  source?: string
}

export interface Finding {
  id: string
  organization_id: string
  asset_id: string
  service_id?: string | null
  cve_id?: string
  osv_id?: string
  title: string
  match_type: string
  confidence: number
  risk_score: number
  severity: Severity
  status: string
  owner?: string
  remediation?: string
  first_seen: string
  last_seen: string
}

export interface Evidence {
  id: string
  kind: string
  statement: string
  detail?: Record<string, unknown>
  source: string
  created_at: string
}

// CVE List v5 affected-product statement (stored verbatim from the feed
// and rendered on the CVE detail page).
export interface AffectedChange {
  at?: string
  status?: string
}

export interface AffectedVersion {
  version?: string
  status?: string
  lessThan?: string
  lessThanOrEqual?: string
  versionType?: string
  changes?: AffectedChange[]
}

export interface AffectedProduct {
  vendor: string
  product: string
  defaultStatus?: string
  cpes?: string[]
  platforms?: string[]
  versions?: AffectedVersion[]
}

export interface CPEMatchRow {
  cpe: string
  vendor: string
  product: string
  version?: string
  version_start_incl?: string
  version_start_excl?: string
  version_end_incl?: string
  version_end_excl?: string
  version_type?: string
}

export interface VulnerabilityRow {
  cve_id: string
  state: string
  description: string
  cvss_score: number
  cvss_vector?: string
  published_at?: string
  known_exploited: boolean
  affected_assets: number
  open_findings: number
  epss?: number
}

export interface SSHScanHost {
  host: string
  port?: number // 0 / undefined = default 22
  username: string
  auth?: 'password' | 'key'
  password?: string
  key_pem?: string
  pinned_key?: string // authorized_keys-format host key; handshake must match exactly
}

// One read-only command the SSH collector executed on a host (command
// strings are compile-time constants server-side; the log adds outcome and
// output line counts).
export interface SSHCommandRun {
  cmd: string
  ok: boolean
  lines: number
  err?: string
}

// Per-host summary of an SSH inventory scan, rendered by the scan view.
export interface SSHHostSummary {
  host: string
  port?: number
  user?: string
  os_family?: string
  os_name?: string
  os_version?: string
  os_ok: boolean
  package_count: number
  commands?: SSHCommandRun[]
  duration_ms: number
  error?: string
}

export interface Scan {
  id: string
  organization_id: string
  site_id: string
  name: string
  profile: string
  engine: string
  state: string
  progress: number
  phase?: string
  config?: {
    ssh_hosts?: SSHScanHost[] // credentials are redacted ("***") in API responses
    ssh_insecure_host_key?: boolean
  }
  stats: {
    targets: number
    reachable: number
    unreachable: number
    ports_discovered: number
    services_fingerprinted: number
    packages_collected: number
    findings_created: number
    critical_findings: number
    tasks_total: number
    tasks_done: number
    tasks_failed: number
    ssh_hosts?: SSHHostSummary[]
  }
  error?: string
  kill_switch?: boolean
  created_at: string
  started_at?: string
  completed_at?: string
}

export interface ScanTask {
  id: string
  type: string
  state: string
  target?: string
  attempt: number
  error?: string
}

export interface Change {
  id: string
  type: string
  asset_id?: string
  entity?: string
  before?: string
  after?: string
  created_at: string
}

export interface Scanner {
  id: string
  name: string
  site_id: string
  version: string
  capabilities: string[]
  health: string
  last_seen: string
  transport?: string // nats (embedded) | grpc (hub agent) | connector (aegis-connector)
  is_default?: boolean
  connector_id?: string // set when the scanner is managed via Connections
}

export interface DetectionRule {
  id: string
  title: string
  identifier: string
  status: string
  description?: string
  level: Severity
  type: string
  window?: string
  enabled: boolean
  tags?: string[]
}

export interface DetectionMatch {
  id: string
  rule_id: string
  rule_title: string
  level: Severity
  src_ip?: string
  entity?: string
  summary: string
  count: number
  timestamp: string
}

export interface SecEvent {
  event_id: string
  timestamp: string
  event_type: string
  source: string
  src_ip?: string
  src_port?: number
  dst_ip?: string
  dst_port?: number
  protocol?: string
  severity?: Severity
  rule_name?: string
  application?: string
  hostname?: string
  tags?: string[]
}

export interface Agent {
  id: string
  hostname: string
  platform: string
  agent_version?: string
  status: string
  site_id: string
  last_seen: string
  asset_id?: string | null
}

export interface ReportJob {
  id: string
  definition_id: string
  state: string
  progress: number
  artifact_key?: string
  error?: string
  created_at: string
  finished_at?: string
}

export interface FeedSource {
  name: string
  enabled: boolean
  last_sync_at?: string
  last_status?: string
  records_ingested?: number
  last_error?: string
  license?: string
}

export interface AuditEntry {
  id: string
  actor_id?: string
  action: string
  target?: string
  actor_ip?: string
  result: string
  created_at: string
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | ''

export interface Page<T> {
  items: T[]
  total: number
  page: number
  limit: number
}

export interface CursorPage<T> {
  items: T[]
  next_cursor?: string
}

export interface MetricsSummary {
  assets: number
  open_ports: number
  vulnerabilities: number
  critical: number
  high: number
  kev: number
  high_risk_assets: number
  active_alerts: number
  by_severity: Record<string, number>
}

export interface TopologyNode {
  id: string
  label: string
  kind: string
  asset_id?: string
  risk?: number
  device_type?: string
}

export interface TopologyEdge {
  id: string
  src_node_id: string
  dst_node_id: string
  kind: string
  confidence?: number
  last_seen?: string
}

export interface TraceHop {
  ttl: number
  ip: string
  hostname?: string
  rtt_ms?: number
}

// One stored traceroute result (per site+target): parsed hop path plus the
// raw probe output for auditing. hop_ips is every address on the path, so
// an asset page lists traces covering its address, not only traces aimed
// at it.
export interface AssetTrace {
  id: string
  site_id: string
  scan_id: string
  target_ip: string
  method: string
  probe: string
  complete: boolean
  hops_count: number
  path: TraceHop[]
  raw?: string
  confidence?: number
  first_seen: string
  last_seen: string
}
