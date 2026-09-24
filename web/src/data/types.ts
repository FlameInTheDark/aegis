// UI model — the shapes the redesigned interface renders. The data layer
// (lib/queries.ts) maps the raw snake_case API responses (lib/api-types.ts)
// into these, so pages never touch transport encoding. Fields the backend
// does not produce are optional and every consumer renders a fallback.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanEngine = "nmap" | "ssh";

/** User-defined grouping of assets, e.g. "Room 1", "IoT devices". */
export interface AssetGroup {
  id: string;
  name: string;
  description?: string;
  /** key into groupPalette */
  color: string;
  /** key into groupIcons */
  icon: string;
  kind: "location" | "function" | "owner" | "custom";
  assetIds: string[];
}
export type Criticality = "critical" | "high" | "medium" | "low" | "none";
export type Exposure = "internet" | "dmz" | "internal" | "unknown";
export type AssetType =
  | "router"
  | "switch"
  | "firewall"
  | "access_point"
  | "camera"
  | "server"
  | "virtual_machine"
  | "container_host"
  | "workstation"
  | "printer"
  | "iot"
  | "nas"
  | "mobile"
  | "hypervisor"
  | "unknown";

export interface Port {
  port: number;
  proto: "tcp" | "udp";
  service: string;
  product?: string;
  version?: string;
  versionMeta?: {
    raw: string;
    normalized: string;
    wellFormed: boolean;
    grammar: string;
    epoch?: number;
    upstream?: string;
    revision?: string;
  };
  state: string;
  banner?: string;
  exposure?: string;
  confidence?: number;
}

export interface Software {
  id: string;
  name: string;
  version: string;
  versionNorm?: string;
  versionMeta?: {
    raw: string;
    normalized: string;
    wellFormed: boolean;
    grammar: string;
    epoch?: number;
    upstream?: string;
    revision?: string;
  };
  ecosystem?: string;
  purl?: string;
  source?: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Asset {
  id: string;
  ip: string;
  hostname?: string;
  fqdn?: string;
  vendor?: string;
  model?: string;
  type: AssetType;
  os?: string;
  osConfidence: number;
  osSources: string[];
  criticality: Criticality;
  exposure: Exposure;
  risk: number;
  riskExplanation?: string;
  hasAgent: boolean;
  agentId?: string;
  site: string;
  tags: string[];
  owner?: string;
  notes?: string;
  /** analyst overrides (migration 0031) — set when the displayed hostname /
   *  type is an analyst correction; clearing it reveals the scanned value */
  nameOverride?: string | null;
  typeOverride?: string | null;
  /** analyst topology parent (migration 0032) — asset id of the pinned
   *  parent node; the topology graph always wires this asset beneath it */
  parentOverride?: string | null;
  firstSeen: string;
  lastSeen: string;
  /** assets-list only: open-finding counts by severity */
  findings?: SeverityCounts;
  /** assets-list only: the endpoint device collecting data for this asset */
  endpoint?: EndpointDevice;
}

export interface AssetDetailBundle {
  asset: Asset;
  ports: Port[];
  software: Software[];
  interfaces: {
    name: string;
    ip: string;
    /** every address observed on the interface, primary first */
    addresses: { ip: string; is_primary: boolean }[];
    mac?: string;
    vendor?: string;
    vlan?: number;
  }[];
  findingsCounts: { open: number; critical: number; high: number; medium: number; low: number };
  groupIds: string[];
  /** the endpoint device collecting data for this asset (undefined: scan-only) */
  endpoint?: EndpointDevice;
}

/** A reference URL attached to a CVE record */
export interface CveReference {
  url: string;
  source?: string;
  tags?: string[];
}

/** CPE-style affected product statement from the CVE record */
export interface AffectedProduct {
  vendor: string;
  product: string;
  /** human-readable version statement, e.g. "6.49.0 through 6.49.7" */
  versionStatement: string;
  status: string;
  /** semver, custom, git, rpm… */
  versionType?: string;
  platforms?: string[];
}

/** CWE weakness entry */
export interface CweEntry {
  id: string;
  name: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  /** feed that supplied the normalized CVE record */
  source?: string;
  state?: string;
  severity: Severity;
  cvss: number;
  cvssVector?: string;
  epss?: number;
  kev: boolean;
  kevDateAdded?: string;
  publishedAt?: string;
  affectedAssetCount: number;
  openFindings: number;
  summary: string;
  cwe?: string[];
  product?: string;
  references?: CveReference[];
  affectedProducts?: AffectedProduct[];
  cpeMatches?: { cpe: string; version?: string; ranges: string[] }[];
  /** detail only: inventory rows affected by this CVE */
  affectedAssets?: { assetId: string; hostname?: string; riskScore: number; findingId: string; status: string }[];
}

export type FindingStatus = "open" | "acknowledged" | "in_progress" | "resolved" | "accepted_risk" | "false_positive" | "suppressed";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  assetId: string;
  cve?: string;
  osv?: string;
  category: string;
  confidence: number;
  riskScore: number;
  remediation?: string;
  notes?: string;
  firstSeen: string;
  lastSeen: string;
  assignee?: string;
}

export type ScanState = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Scan {
  id: string;
  name: string;
  profile: string;
  engine: string;
  state: ScanState;
  progress: number;
  phase?: string;
  targets: string;
  site: string;
  reachable: { up: number; total: number };
  ports: number;
  services: number;
  packages: number;
  findings: number;
  criticalFindings: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  tasks: { total: number; done: number; failed: number };
  sshHosts?: {
    host: string;
    port?: number;
    user?: string;
    os?: string;
    osOk: boolean;
    packageCount: number;
    durationMs: number;
    error?: string;
    commands?: { cmd: string; ok: boolean; lines: number; err?: string }[];
  }[];
}

export type DetectionStatus = "new" | "investigating" | "contained" | "closed";

export interface Detection {
  id: string;
  title: string;
  severity: Severity;
  ruleType?: string;
  source: "correlation";
  assetId?: string;
  srcIp?: string;
  entity?: string;
  status: DetectionStatus;
  timestamp: string;
  description: string;
  count: number;
  indicators: string[];
}

export type EventLevel = "info" | "warning" | "error" | "critical";
export type EventCategory = string;

export interface PlatformEvent {
  id: string;
  timestamp: string;
  level: EventLevel;
  category: EventCategory;
  message: string;
  actor?: string;
  assetId?: string;
  srcIp?: string;
  meta?: Record<string, string>;
}

export interface EndpointDevice {
  id: string;
  hostname: string;
  platform?: string;
  version: string;
  status: string;
  lastSeen?: string;
  assetId?: string;
}

export type ConnectionKind = "agent" | "scanner" | "collector";

export interface Connection {
  id: string;
  name: string;
  kind: ConnectionKind;
  site?: string;
  provider: string;
  status: "pending" | "active" | "revoked";
  online: boolean;
  connState?: string;
  lastSync?: string;
  endpoint?: string;
  platform?: string;
  version?: string;
  capabilities: string[];
  config?: Record<string, unknown>;
  configVersion?: number;
  lastStatus?: Record<string, unknown>;
  enrolledAt?: string;
  createdAt: string;
  /** Endpoint device bound to this connection (agent function). */
  device?: EndpointDevice;
}

/** One bucket of an asset's performance series. */
export interface AssetMetricPoint {
  ts: string;
  cpu_avg: number;
  cpu_max: number;
  mem_used: number;
  mem_total: number;
  rx_bps: number;
  tx_bps: number;
  uptime_secs: number;
}

/** The newest stored performance sample of a device. */
export interface AssetMetricLatest {
  timestamp: string;
  cpu_percent: number;
  rx_bps: number;
  tx_bps: number;
  mem_total: number;
  mem_used: number;
  uptime_secs: number;
  ifaces: { name: string; mac?: string; rx_bytes: number; tx_bytes: number; rx_bps: number; tx_bps: number }[];
}

/** One NIC's rate history for the interface table sparklines. */
export interface AssetIfaceSeries {
  name: string;
  mac?: string;
  rx: number[];
  tx: number[];
}

/** Full response of the asset metrics endpoint (charts + sparklines + window echo). */
export interface AssetMetricsResponse {
  points: AssetMetricPoint[];
  latest: AssetMetricLatest | null;
  ifaces: AssetIfaceSeries[];
  window: string;
  from: string;
  to: string;
  bucket: number;
  tail: boolean;
}

export interface Report {
  id: string;
  name: string;
  type: string;
  scope: string;
  format: "pdf" | "html" | "csv";
  createdAt: string;
  createdBy: string;
  status: "queued" | "generating" | "ready" | "failed";
  progress: number;
  jobId?: string;
  artifactKey?: string;
  error?: string;
}

export interface Site {
  id: string;
  name: string;
  description?: string;
  kind: string;
  assets: number;
  networks: { id: string; cidr: string; name?: string; vlan?: number | null; gateway?: string; exposure: string }[];
  createdAt: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  status: "active" | "disabled";
  lastActive?: string;
  createdAt: string;
}

export interface Scanner {
  id: string;
  name: string;
  version: string;
  transport: string;
  health: string;
  lastSeen: string;
  capabilities: string[];
  siteId: string;
  isDefault: boolean;
  connectorId?: string;
}

export interface Feed {
  id: string;
  name: string;
  provider: string;
  kind: "cve" | "kev" | "epss" | "ioc" | "fingerprint" | "oval" | string;
  lastSync?: string;
  status: "ok" | "running" | "stale" | "error" | "disabled";
  /** Rows this feed owns in its table — live count from the DB. */
  entries?: number;
  /** Records processed by the most recent sync run. */
  lastProcessed?: number;
  recordsNew?: number;
  recordsUpdated?: number;
  autoSync: boolean;
  license?: string;
  lastError?: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  ip: string;
  outcome: "success" | "denied" | "failure" | string;
}

export interface Preset {
  name: string;
  description: string;
  engine: string;
  ports: string;
  timing: string;
  scripts: string[];
  builtin: boolean;
  maxTargets: number;
  maxPacketRate: number;
}

export interface Schedule {
  id: string;
  name: string;
  siteId: string;
  profile: string;
  cron: string;
  scope: string[];
  engine: string;
  enabled: boolean;
  lastRunAt?: string;
  nextRunAt?: string;
}

export interface TraceHop {
  ttl: number;
  address: string;
  hostname?: string;
  rtt?: number;
}

export interface Trace {
  id: string;
  assetId?: string;
  targetIp: string;
  status: "complete" | "partial" | "failed";
  hops: TraceHop[];
  confidence: number;
  lastSeen: string;
  raw: string;
}
