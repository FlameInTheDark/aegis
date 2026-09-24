// Raw backend response shapes (snake_case, mirroring the Go JSON tags).
// The mapper layer turns these into the UI model in @/data/types.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | ''

export interface Page<T> {
  items: T[]
  total: number
  page: number
  limit: number
}

export interface Me {
  user: { id: string; email: string; name: string }
  organizations: { id: string; name: string; slug: string; role: string }[]
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
  asset_count?: number
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

/** Read-time version normalization metadata (raw vs canonical form). */
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

export interface SoftwareRow {
  id: string
  name: string
  version?: string
  version_norm?: string
  version_meta?: VersionMeta
  ecosystem?: string
  purl?: string
  source?: string
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
  endpoint?: DeviceSummary
  tags?: string[]
  owner?: string
  notes?: string
  primary_ip?: string
  /** analyst overrides (migration 0031) — the effective hostname/device_type
   *  already carry the override; these flag that it is active so the UI can
   *  badge the asset and offer a reset to the scanned value */
  name_override?: string | null
  device_type_override?: string | null
  /** analyst topology parent (migration 0032) — asset id of the pinned
   *  parent node; NULL = follow the evidence-derived topology */
  parent_override?: string | null
  first_seen: string
  last_seen: string
  /** assets-list only: per-asset open-finding severity counts */
  findings?: Record<string, number>
}

export interface Interface {
  id?: string
  asset_id?: string
  name: string
  /** flattened by the backend interfaceView: primary observed address */
  ip?: string
  mac?: string
  /** OUI organization resolved by nmap for this interface's MAC */
  vendor?: string
  vlan?: number | null
  /** raw domain shape, used as fallback by the bundle mapping */
  vlan_id?: number | null
  addresses?: { ip: string; is_primary?: boolean }[]
  is_primary?: boolean
}

export interface AssetBundle {
  asset: Asset
  interfaces: Interface[]
  services: Service[]
  software: SoftwareRow[]
  findings_count: { open: number; critical: number; high: number; medium: number; low: number }
  group_ids: string[]
  endpoint?: DeviceSummary
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
  notes?: string
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

export interface StatusHistoryRow {
  from: string
  to: string
  changed_by: string
  reason?: string
  created_at: string
}

export interface AffectedProduct {
  vendor: string
  product: string
  defaultStatus?: string
  cpes?: string[]
  platforms?: string[]
  versions?: {
    version?: string
    status?: string
    lessThan?: string
    lessThanOrEqual?: string
    versionType?: string
    changes?: { at?: string; status?: string }[]
  }[]
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

export interface VulnerabilityDetail {
  cve_id: string
  state: string
  description: string
  cvss_v2?: { score: number; vector?: string } | null
  cvss_v3?: { score: number; vector?: string } | null
  cvss_v4?: { score: number; vector?: string } | null
  cwe?: string[]
  references?: string[]
  affected?: AffectedProduct[]
  cpe_matches?: CPEMatchRow[]
  known_exploited?: { cve_id?: string; date_added?: string; due_date?: string; known_ransomware?: boolean } | null
  epss?: { score: number; percentile?: number; date?: string } | null
  source: string
  published_at?: string
  updated_at?: string
  ingested_at: string
}

export interface VulnListRow {
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
  /** feed the record was ingested from: nvd | cvelistv5 */
  source?: string
}

export interface AffectedAssetRow {
  asset_id: string
  hostname?: string
  risk_score: number
  finding_id: string
  status: string
}

export interface SSHScanHost {
  host: string
  port?: number
  username: string
  auth?: 'password' | 'key'
  password?: string
  key_pem?: string
  pinned_key?: string
}

export interface SSHCommandRun {
  cmd: string
  ok: boolean
  lines: number
  err?: string
}

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
    ssh_hosts?: SSHScanHost[]
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
  transport?: string
  is_default?: boolean
  connector_id?: string
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
  status?: string
  asset_id?: string
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

/** Bound endpoint device summary (embedded in connector views). */
export interface DeviceSummary {
  id: string
  hostname: string
  platform?: string
  platform_version?: string
  arch?: string
  version?: string
  status: string
  last_seen?: string
  asset_id?: string
}

export interface Connector {
  id: string
  kind: string
  name: string
  status: string
  online?: boolean
  conn_state?: string
  hostname?: string
  platform?: string
  arch?: string
  version?: string
  capabilities?: string[]
  config: Record<string, unknown>
  config_version?: number
  device?: DeviceSummary
  last_seen?: string
  last_status?: Record<string, unknown>
  enrolled_at?: string
  created_at: string
  site_id?: string
}

export interface ReportDefinition {
  id: string
  name: string
  type: string
  format: string
  site_id?: string
  asset_id?: string
  scan_id?: string
  sections?: string[]
  created_by: string
  created_at: string
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
  last_status?: string // healthy | stale | failed | never_synced | running
  records_ingested?: number // processed by the most recent sync run
  records_total?: number // live COUNT(*) of the rows this feed owns in its table
  records_new?: number
  records_updated?: number
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

export interface UserRow {
  id: string
  email: string
  name: string
  role: string
  disabled: boolean
  last_login_at?: string
  created_at: string
  member_since: string
}

export interface ProfileDef {
  name: string
  description: string
  host_discovery?: boolean
  top_tcp_ports: number
  top_udp_ports?: number
  full_port_scan: boolean
  service_detect: boolean
  service_lite: boolean
  os_detect: boolean
  traceroute: boolean
  safe_nse?: boolean
  zgrab_enrich?: boolean
  safe_validation?: boolean
  elevated_reqs?: boolean
  ssh_collect?: boolean
  max_targets: number
  max_packet_rate: number
  warning?: string
  extra_args?: string[]
  builtin?: boolean
}

export interface ScanSchedule {
  id: string
  site_id: string
  name: string
  profile: string
  cron: string
  scope: string[]
  engine: string
  enabled: boolean
  created_by: string
  last_run_at?: string
  next_run_at?: string
}

export interface WebhookRow {
  id: string
  name: string
  url: string
  events: string[]
  enabled: boolean
}

export interface AssetGroup {
  id: string
  organization_id: string
  name: string
  description?: string
  color: string
  icon: string
  kind: string
  created_at: string
  updated_at: string
  asset_ids: string[]
}

export interface TopologyNode {
  id: string
  label: string
  kind: string
  asset_id?: string
  /** for non-asset nodes: the referenced IP (router/gateway hops) */
  ref_id?: string
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

export interface SearchHit {
  type: string
  id: string
  label: string
  sublabel?: string
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

export interface CursorPage<T> {
  items: T[]
  next_cursor?: string
}
