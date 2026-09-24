package domain

import (
	"time"
)

// ReportType enumerates supported report types.
type ReportType string

const (
	ReportExecutive    ReportType = "executive_security"
	ReportTechnical    ReportType = "technical_vulnerability"
	ReportInventory    ReportType = "network_inventory"
	ReportTopology     ReportType = "topology"
	ReportSecurityEvts ReportType = "security_event"
	ReportAssetRisk    ReportType = "asset_risk"
	ReportScanDiff     ReportType = "scan_comparison"
	// ReportSiteDetail is the fully detailed report about one site.
	ReportSiteDetail ReportType = "site_detail"
	// ReportDeviceDetail is the fully detailed report about one device.
	ReportDeviceDetail ReportType = "device_detail"
)

// ReportFormat enumerates output formats.
type ReportFormat string

const (
	ReportPDF  ReportFormat = "pdf"
	ReportHTML ReportFormat = "html"
	ReportCSV  ReportFormat = "csv"
	ReportJSON ReportFormat = "json"
)

// ReportDefinition describes what a report includes.
type ReportDefinition struct {
	ID             string       `json:"id"`
	OrganizationID string       `json:"organization_id"`
	Name           string       `json:"name"`
	Type           ReportType   `json:"type"`
	Format         ReportFormat `json:"format"`
	SiteID         string       `json:"site_id,omitempty"`
	AssetID        string       `json:"asset_id,omitempty"` // device_detail target
	ScanID         string       `json:"scan_id,omitempty"`
	DateFrom       *time.Time   `json:"date_from,omitempty"`
	DateTo         *time.Time   `json:"date_to,omitempty"`
	Sections       []string     `json:"sections,omitempty"`
	MinSeverity    Severity     `json:"min_severity,omitempty"`
	CreatedBy      string       `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
}

// ReportJob tracks asynchronous report generation.
type ReportJob struct {
	ID          string     `json:"id"`
	Definition  string     `json:"definition_id"`
	OrgID       string     `json:"organization_id"`
	State       string     `json:"state"` // queued|running|completed|failed
	Progress    float64    `json:"progress"`
	ArtifactKey string     `json:"artifact_key,omitempty"` // object storage key
	SizeBytes   int64      `json:"size_bytes,omitempty"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// AuditEntry is one auditable action.
type AuditEntry struct {
	ID        string         `json:"id"`
	OrgID     string         `json:"organization_id"`
	ActorID   string         `json:"actor_id,omitempty"`
	ActorName string         `json:"actor_name,omitempty"`
	ActorIP   string         `json:"actor_ip,omitempty"`
	Action    string         `json:"action"`           // login|logout|token.revoked|scan.created|...
	Target    string         `json:"target,omitempty"` // resource type/id
	SiteID    string         `json:"site_id,omitempty"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	Result    string         `json:"result"` // success|denied|error
	Detail    map[string]any `json:"detail,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// Note is an analyst note on any entity.
type Note struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"organization_id"`
	Entity     string    `json:"entity"` // asset|finding|detection|scan
	EntityID   string    `json:"entity_id"`
	AuthorID   string    `json:"author_id"`
	AuthorName string    `json:"author_name"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
}

// Team is a simple grouping for ownership.
type Team struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"organization_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// WebhookConfig is an alerting channel.
type WebhookConfig struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"organization_id"`
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Events    []string   `json:"events"` // critical_finding|kev_finding|new_exposure|critical_detection|agent_offline|feed_failure
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	LastFired *time.Time `json:"last_fired,omitempty"`
}
