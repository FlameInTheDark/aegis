package domain

import (
	"time"
)

// Agent is a registered endpoint agent (device identity based).
type Agent struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	SiteID         string     `json:"site_id"`
	AssetID        *string    `json:"asset_id,omitempty"`
	Hostname       string     `json:"hostname"`
	Platform       string     `json:"platform"` // windows|linux|darwin
	PlatformVer    string     `json:"platform_version,omitempty"`
	Arch           string     `json:"arch,omitempty"`
	AgentVersion   string     `json:"agent_version,omitempty"`
	Status         string     `json:"status"` // online|offline|degraded
	CertSerial     string     `json:"cert_serial,omitempty"`
	CertNotAfter   *time.Time `json:"cert_not_after,omitempty"`
	Capabilities   []string   `json:"capabilities,omitempty"` // basic_inventory|software_inventory|network_inventory|security_posture|process_inventory|local_events|local_scan
	LastSeen       time.Time  `json:"last_seen"`
	EnrolledAt     time.Time  `json:"enrolled_at"`
	Revoked        bool       `json:"revoked"`
}

// AgentTask is a typed task assigned to an agent (spec §19).
// There is deliberately NO arbitrary shell execution capability.
type AgentTaskType string

const (
	AgentTaskInventoryRefresh  AgentTaskType = "inventory_refresh"
	AgentTaskSoftwareInventory AgentTaskType = "software_inventory"
	AgentTaskNetworkInventory  AgentTaskType = "network_inventory"
	AgentTaskSocketInventory   AgentTaskType = "socket_inventory"
	AgentTaskSecurityPosture   AgentTaskType = "security_posture"
	AgentTaskLocalConfigCheck  AgentTaskType = "local_configuration_check"
	AgentTaskLocalScan         AgentTaskType = "local_scan"
	AgentTaskDiagnostic        AgentTaskType = "diagnostic"
	AgentTaskConfigSync        AgentTaskType = "configuration_sync"
)

var ValidAgentTaskTypes = map[AgentTaskType]bool{
	AgentTaskInventoryRefresh: true, AgentTaskSoftwareInventory: true,
	AgentTaskNetworkInventory: true, AgentTaskSocketInventory: true,
	AgentTaskSecurityPosture: true, AgentTaskLocalConfigCheck: true,
	AgentTaskLocalScan: true, AgentTaskDiagnostic: true, AgentTaskConfigSync: true,
}

// AgentTask is one assignable unit for an agent.
type AgentTask struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	Type      AgentTaskType  `json:"type"`
	IssuedBy  string         `json:"issued_by"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Args      map[string]any `json:"args,omitempty"`
	State     string         `json:"state"` // pending|delivered|running|succeeded|failed|expired
	Result    map[string]any `json:"result,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// SystemInventory is the endpoint-authoritative inventory payload.
type SystemInventory struct {
	Hostname     string       `json:"hostname"`
	FQDN         string       `json:"fqdn,omitempty"`
	OSFamily     string       `json:"os_family,omitempty"`
	OSName       string       `json:"os_name,omitempty"`
	OSVersion    string       `json:"os_version,omitempty"`
	Kernel       string       `json:"kernel,omitempty"`
	Arch         string       `json:"arch,omitempty"`
	UptimeSecs   uint64       `json:"uptime_secs,omitempty"`
	BootTime     *time.Time   `json:"boot_time,omitempty"`
	CPUModel     string       `json:"cpu_model,omitempty"`
	CPUCores     int          `json:"cpu_cores,omitempty"`
	MemoryTotal  uint64       `json:"memory_total,omitempty"`
	SerialNumber string       `json:"serial_number,omitempty"`
	MachineID    string       `json:"machine_id,omitempty"`
	Interfaces   []AgentIface `json:"interfaces,omitempty"`
	Disks        []AgentDisk  `json:"disks,omitempty"`
}

// AgentIface is one network interface reported by the agent.
type AgentIface struct {
	Name   string   `json:"name"`
	MAC    string   `json:"mac,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	MTU    int      `json:"mtu,omitempty"`
	Status string   `json:"status,omitempty"`
}

// AgentDisk is one mount point.
type AgentDisk struct {
	Device     string `json:"device,omitempty"`
	MountPoint string `json:"mountpoint,omitempty"`
	FSType     string `json:"fs_type,omitempty"`
	TotalBytes uint64 `json:"total_bytes,omitempty"`
	FreeBytes  uint64 `json:"free_bytes,omitempty"`
	Encrypted  *bool  `json:"encrypted,omitempty"`
}

// Socket is a listening socket observation.
type Socket struct {
	Protocol  string `json:"protocol"` // tcp|tcp6|udp|udp6
	LocalIP   string `json:"local_ip"`
	LocalPort int    `json:"local_port"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
}

// SecurityPosture is endpoint security state (spec §17).
type SecurityPosture struct {
	FirewallEnabled *bool    `json:"firewall_enabled,omitempty"`
	FirewallProduct string   `json:"firewall_product,omitempty"`
	AVEnabled       *bool    `json:"av_enabled,omitempty"`
	AVProduct       string   `json:"av_product,omitempty"`
	DiskEncryption  string   `json:"disk_encryption,omitempty"` // enabled|partial|disabled|unknown
	AutoUpdates     string   `json:"auto_updates,omitempty"`    // enabled|disabled|unknown
	SecureBoot      string   `json:"secure_boot,omitempty"`     // enabled|disabled|unknown
	PrivilegedUsers []string `json:"privileged_users,omitempty"`
	LocalAdmins     []string `json:"local_admins,omitempty"`
}

// ProcessInfo is minimal process information (spec §17 limits).
type ProcessInfo struct {
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"` // only if permitted/configured
	User      string `json:"user,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	ParentPID int    `json:"parent_pid,omitempty"`
	Signed    *bool  `json:"signed,omitempty"`
}

// AgentEvent is telemetry streamed from an agent.
type AgentEvent struct {
	AgentID   string         `json:"agent_id"`
	Type      string         `json:"type"` // posture_change|process_start|service_state|config_change|local_scan_result
	Timestamp time.Time      `json:"timestamp"`
	Payload   map[string]any `json:"payload,omitempty"`
}
