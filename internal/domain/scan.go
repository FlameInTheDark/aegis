package domain

import (
	"time"
)

// ScanProfile is a named safety envelope for scans.
type ScanProfile string

const (
	ProfileDiscoverySafe    ScanProfile = "discovery_safe"
	ProfileInventory        ScanProfile = "inventory"
	ProfileVulnSafe         ScanProfile = "vulnerability_safe"
	ProfileActiveValidation ScanProfile = "active_validation"
	ProfileFullAudit        ScanProfile = "full_audit"
	ProfileTrace            ScanProfile = "trace"
	ProfileFingerprint      ScanProfile = "fingerprint"
)

// ProfileDefinition describes what a profile permits. Scans are only allowed
// to request capabilities contained in their profile.
type ProfileDefinition struct {
	Name          ScanProfile
	Description   string
	HostDiscovery bool
	TopTCPPorts   int // 0 = top 100, explicit numbers override
	TopUDPPorts   int
	FullPortScan  bool
	ServiceDetect bool
	// ServiceLite runs ONE batched `nmap -sV --version-light` pass per host
	// over the ports found in phase 2, instead of the per-port intensity-5
	// probing ServiceDetect does. Cheap, but enough to harvest the service
	// table's ostype and OS CPEs — the OS signal that keeps working where
	// -O cannot (raw-socket-less environments, NATs that filter the
	// open+closed port pair TCP/IP fingerprinting needs).
	ServiceLite    bool
	OSDetect       bool
	Traceroute     bool // build network topology by tracing the path to each host
	SafeNSE        bool
	ZgrabEnrich    bool
	SafeValidation bool
	ElevatedReqs   bool // requires PermScanElevated + confirmation
	MaxTargets     int
	MaxPacketRate  int
	Warning        string
	// ExtraArgs are additional, server-validated nmap arguments that custom
	// presets append to every nmap phase (allowlist-checked by
	// scanning.ValidateNmapArgs before storage; never user-raw).
	ExtraArgs []string `json:"extra_args,omitempty"`
	// Builtin marks registry profiles (vs org-created presets).
	Builtin bool `json:"builtin,omitempty"`
}

// Profiles is the registry of scan safety profiles. Defaults are conservative.
var Profiles = map[ScanProfile]ProfileDefinition{
	ProfileDiscoverySafe: {
		Name:          ProfileDiscoverySafe,
		Description:   "Host discovery, topology tracing and basic port scan at low rate. No intrusive checks.",
		HostDiscovery: true, TopTCPPorts: 100, ServiceDetect: false, Traceroute: true,
		MaxTargets: 4096, MaxPacketRate: 100,
	},
	ProfileInventory: {
		Name:          ProfileInventory,
		Description:   "Discovery, topology tracing, broad ports, service and OS detection, safe NSE, zgrab2 enrichment.",
		HostDiscovery: true, TopTCPPorts: 1000, TopUDPPorts: 50, ServiceDetect: true,
		OSDetect: true, Traceroute: true, SafeNSE: true, ZgrabEnrich: true,
		MaxTargets: 8192, MaxPacketRate: 300,
	},
	ProfileVulnSafe: {
		Name:          ProfileVulnSafe,
		Description:   "Inventory plus vulnerability intelligence correlation and safe remote validation.",
		HostDiscovery: true, TopTCPPorts: 1000, TopUDPPorts: 50, FullPortScan: false,
		ServiceDetect: true, OSDetect: true, Traceroute: true, SafeNSE: true, ZgrabEnrich: true,
		SafeValidation: true,
		MaxTargets:     8192, MaxPacketRate: 300,
	},
	ProfileActiveValidation: {
		Name:          ProfileActiveValidation,
		Description:   "Elevated active validation. Requires explicit permission and confirmation.",
		HostDiscovery: true, TopTCPPorts: 1000, TopUDPPorts: 100, ServiceDetect: true,
		OSDetect: true, Traceroute: true, SafeNSE: true, ZgrabEnrich: true, SafeValidation: true,
		ElevatedReqs: true,
		MaxTargets:   2048, MaxPacketRate: 150,
		Warning: "This profile performs active validation probes against the target scope. " +
			"Ensure every target is inside your authorized scope. All actions are audit-logged.",
	},
	ProfileFullAudit: {
		Name:          ProfileFullAudit,
		Description:   "Security-audit sweep: all 65535 TCP ports, service+version and OS detection, topology tracing. Loud and slow.",
		HostDiscovery: true, TopTCPPorts: 65535, FullPortScan: true, ServiceDetect: true,
		OSDetect: true, Traceroute: true,
		MaxTargets: 1024, MaxPacketRate: 500,
		Warning: "This profile scans ALL 65535 TCP ports of every discovered host with full version and OS " +
			"fingerprinting. It is noticeably louder and slower than inventory scans. Only run it against " +
			"networks you are authorized to assess.",
	},
	ProfileTrace: {
		Name:          ProfileTrace,
		Description:   "Fast topology trace: ping sweep + traceroute only — no port scans. Maps how devices connect (gateway → routers → hosts) in seconds.",
		HostDiscovery: true, TopTCPPorts: 0, ServiceDetect: false, OSDetect: false, Traceroute: true,
		MaxTargets: 4096, MaxPacketRate: 400,
	},
	ProfileFingerprint: {
		Name:          ProfileFingerprint,
		Description:   "Device-type and OS fingerprinting pass: classifies each host (router, computer, phone, iot, …) and refreshes the OS data on the asset. Light port scan (top 100) as detection fuel plus a batched light service pass — nmap -O stays authoritative where raw sockets work.",
		HostDiscovery: true, TopTCPPorts: 100, ServiceLite: true, OSDetect: true, Traceroute: false,
		MaxTargets: 2048, MaxPacketRate: 200,
	},
}

// ScanState is the lifecycle state of a scan.
type ScanState string

const (
	ScanQueued     ScanState = "queued"
	ScanRunning    ScanState = "running"
	ScanPaused     ScanState = "paused"
	ScanCancelling ScanState = "cancelling"
	ScanCompleted  ScanState = "completed"
	ScanFailed     ScanState = "failed"
	ScanCancelled  ScanState = "cancelled"
)

// TaskType enumerates orchestrator task kinds.
type TaskType string

const (
	TaskDiscoverHosts            TaskType = "discover_hosts"
	TaskScanPorts                TaskType = "scan_ports"
	TaskFingerprintServices      TaskType = "fingerprint_services"
	TaskFingerprintOS            TaskType = "fingerprint_os"
	TaskQuerySNMP                TaskType = "query_snmp"
	TaskCorrelateVulnerabilities TaskType = "correlate_vulnerabilities"
	TaskSafeValidation           TaskType = "safe_validation"
)

// TaskState is the state of an individual scan task.
type TaskState string

const (
	TaskPending    TaskState = "pending"
	TaskDispatched TaskState = "dispatched"
	TaskRunning    TaskState = "running"
	TaskSucceeded  TaskState = "succeeded"
	TaskFailed     TaskState = "failed"
	TaskRetrying   TaskState = "retrying"
	TaskCancelled  TaskState = "cancelled"
)

// ScanScope defines the explicit authorized target set of a scan.
type ScanScope struct {
	ID           string   `json:"id"`
	ScanID       string   `json:"scan_id"`
	CIDRs        []string `json:"cidrs,omitempty"`
	IPRanges     []string `json:"ip_ranges,omitempty"`
	Hostnames    []string `json:"hostnames,omitempty"`
	Allowlist    []string `json:"allowlist,omitempty"`
	Denylist     []string `json:"denylist,omitempty"`
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`
}

// ScanConfig is the exact, reproducible configuration of a scan.
type ScanConfig struct {
	Profile           ScanProfile `json:"profile"`
	TCPPorts          []int       `json:"tcp_ports,omitempty"`
	UDPPorts          []int       `json:"udp_ports,omitempty"`
	TopTCPPorts       int         `json:"top_tcp_ports,omitempty"`  // nmap --top-ports semantics
	FullTCPPorts      bool        `json:"full_tcp_ports,omitempty"` // scan 1-65535
	MaxRate           int         `json:"max_rate"`
	Concurrency       int         `json:"concurrency"`
	TimeoutSecs       int         `json:"timeout_secs"`
	Retries           int         `json:"retries"`
	SourceIface       string      `json:"source_iface,omitempty"`
	SourceAddress     string      `json:"source_address,omitempty"`
	MaintenanceWindow *TimeRange  `json:"maintenance_window,omitempty"`
	Engine            string      `json:"engine"` // nmap | simulated
	// ExtraArgs carries a custom preset's validated nmap arguments so any
	// engine (and later re-runs) reproduces the exact same probes.
	ExtraArgs []string `json:"extra_args,omitempty"`
}

// Scan is one orchestration unit.
type Scan struct {
	ID             string      `json:"id"`
	OrganizationID string      `json:"organization_id"`
	SiteID         string      `json:"site_id"`
	Name           string      `json:"name"`
	Profile        ScanProfile `json:"profile"`
	Engine         string      `json:"engine"`
	ScannerID      string      `json:"scanner_id,omitempty"`
	CreatedBy      string      `json:"created_by"`
	State          ScanState   `json:"state"`
	Progress       float64     `json:"progress"`
	Phase          string      `json:"phase,omitempty"`
	Config         *ScanConfig `json:"config,omitempty"`
	Stats          ScanStats   `json:"stats"`
	Error          string      `json:"error,omitempty"`
	KillSwitch     bool        `json:"kill_switch"`
	Scheduled      bool        `json:"scheduled"`
	ScheduleCRON   string      `json:"schedule_cron,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	StartedAt      *time.Time  `json:"started_at,omitempty"`
	CompletedAt    *time.Time  `json:"completed_at,omitempty"`
}

// ScanStats are live counters shown in the UX (spec §116).
type ScanStats struct {
	Targets               int `json:"targets"`
	Reachable             int `json:"reachable"`
	Unreachable           int `json:"unreachable"`
	PortsDiscovered       int `json:"ports_discovered"`
	ServicesFingerprinted int `json:"services_fingerprinted"`
	FindingsCreated       int `json:"findings_created"`
	CriticalFindings      int `json:"critical_findings"`
	TasksTotal            int `json:"tasks_total"`
	TasksDone             int `json:"tasks_done"`
	TasksFailed           int `json:"tasks_failed"`
}

// ScanTask is a unit of work within a scan.
type ScanTask struct {
	ID         string     `json:"id"`
	ScanID     string     `json:"scan_id"`
	Type       TaskType   `json:"type"`
	State      TaskState  `json:"state"`
	ScannerID  string     `json:"scanner_id,omitempty"`
	Target     string     `json:"target,omitempty"`
	Attempt    int        `json:"attempt"`
	Payload    []byte     `json:"-"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Observation is a normalized scanner result (spec §137).
type Observation struct {
	ID              string         `json:"id"`
	ScanID          string         `json:"scan_id"`
	TaskID          string         `json:"task_id,omitempty"`
	SiteID          string         `json:"site_id"`
	OrganizationID  string         `json:"organization_id"`
	Target          string         `json:"target"`
	ObservationType string         `json:"observation_type"` // host_up|host_down|port_open|service|os|device|route|snmp
	Timestamp       time.Time      `json:"timestamp"`
	Source          Source         `json:"source"`
	Payload         []byte         `json:"-"`
	Normalized      map[string]any `json:"normalized,omitempty"`
	Confidence      Confidence     `json:"confidence"`
	Error           string         `json:"error,omitempty"`
}

// Scanner is a registered distributed scanning worker.
type Scanner struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	SiteID         string    `json:"site_id"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Capabilities   []string  `json:"capabilities"`
	Interfaces     []string  `json:"interfaces,omitempty"`
	Health         string    `json:"health"`     // healthy|degraded|offline
	Transport      string    `json:"transport"`  // nats (embedded) | grpc (hub agent)
	IsDefault      bool      `json:"is_default"` // org-level default scanner
	LastSeen       time.Time `json:"last_seen"`
	CreatedAt      time.Time `json:"created_at"`
}

// ScanSchedule is a recurring scan definition.
type ScanSchedule struct {
	ID             string      `json:"id"`
	OrganizationID string      `json:"organization_id"`
	SiteID         string      `json:"site_id"`
	Name           string      `json:"name"`
	Profile        ScanProfile `json:"profile"`
	CRON           string      `json:"cron"`
	Scope          []string    `json:"scope"`
	Engine         string      `json:"engine"`
	Enabled        bool        `json:"enabled"`
	CreatedBy      string      `json:"created_by"`
	LastRunAt      *time.Time  `json:"last_run_at,omitempty"`
	NextRunAt      *time.Time  `json:"next_run_at,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}

// ChangeType enumerates deltas produced between scans (spec §26).
type ChangeType string

const (
	ChangeNewAsset          ChangeType = "NEW_ASSET"
	ChangeRemovedAsset      ChangeType = "REMOVED_ASSET"
	ChangeIPChanged         ChangeType = "IP_CHANGED"
	ChangeMACChanged        ChangeType = "MAC_CHANGED"
	ChangeOSChanged         ChangeType = "OS_CHANGED"
	ChangeServiceOpened     ChangeType = "SERVICE_OPENED"
	ChangeServiceClosed     ChangeType = "SERVICE_CLOSED"
	ChangeServiceChanged    ChangeType = "SERVICE_CHANGED"
	ChangeVersionChanged    ChangeType = "VERSION_CHANGED"
	ChangeSoftwareInstalled ChangeType = "SOFTWARE_INSTALLED"
	ChangeSoftwareRemoved   ChangeType = "SOFTWARE_REMOVED"
	ChangeVulnNew           ChangeType = "VULNERABILITY_NEW"
	ChangeVulnResolved      ChangeType = "VULNERABILITY_RESOLVED"
	ChangeVulnChanged       ChangeType = "VULNERABILITY_CHANGED"
	ChangeTopology          ChangeType = "TOPOLOGY_CHANGED"
	ChangeAgentMissing      ChangeType = "AGENT_MISSING"
	ChangePosture           ChangeType = "SECURITY_POSTURE_CHANGED"
)

// Change is one delta event of a scan comparison.
type Change struct {
	ID        string     `json:"id"`
	ScanID    string     `json:"scan_id"`
	SiteID    string     `json:"site_id"`
	Type      ChangeType `json:"type"`
	AssetID   string     `json:"asset_id,omitempty"`
	Entity    string     `json:"entity,omitempty"`
	Before    string     `json:"before,omitempty"`
	After     string     `json:"after,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
