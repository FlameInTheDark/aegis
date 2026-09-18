package domain

import (
	"time"
)

// Event is the normalized common security event model (spec §22).
// All Suricata/Zeek/Snort/agent events normalize into this envelope.
type Event struct {
	EventID       string         `json:"event_id"`
	TenantID      string         `json:"tenant_id"`
	SiteID        string         `json:"site_id,omitempty"`
	SensorID      string         `json:"sensor_id,omitempty"`
	AgentID       string         `json:"agent_id,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
	EventType     string         `json:"event_type"` // alert|flow|dns|http|tls|ssh|fileinfo|anomaly|endpoint
	Source        string         `json:"source"`     // suricata|zeek|snort|agent
	SourceVersion string         `json:"source_version,omitempty"`
	SchemaVersion string         `json:"schema_version"` // e.g. "1"
	SrcAssetID    string         `json:"src_asset_id,omitempty"`
	SrcIP         string         `json:"src_ip,omitempty"`
	SrcPort       int            `json:"src_port,omitempty"`
	DstAssetID    string         `json:"dst_asset_id,omitempty"`
	DstIP         string         `json:"dst_ip,omitempty"`
	DstPort       int            `json:"dst_port,omitempty"`
	Protocol      string         `json:"protocol,omitempty"`
	Direction     string         `json:"direction,omitempty"` // inbound|outbound|internal
	Severity      Severity       `json:"severity,omitempty"`
	Action        string         `json:"action,omitempty"` // allowed|blocked|alert
	RuleID        string         `json:"rule_id,omitempty"`
	RuleName      string         `json:"rule_name,omitempty"`
	Application   string         `json:"application,omitempty"`
	Hostname      string         `json:"hostname,omitempty"`
	User          string         `json:"user,omitempty"`
	Process       string         `json:"process,omitempty"`
	PayloadMeta   map[string]any `json:"payload_metadata,omitempty"`
	RawReference  string         `json:"raw_reference,omitempty"` // object storage key
	Tags          []string       `json:"tags,omitempty"`
}

// SchemaVersion is the current event envelope version.
const EventSchemaVersion = "1"

// DetectionRule is a typed detection rule (internal representation that can
// also express Sigma-like concepts; spec §40/§41).
type DetectionRule struct {
	ID             string            `json:"id"`
	OrgID          string            `json:"organization_id"`
	Title          string            `json:"title"`
	Identifier     string            `json:"identifier"` // stable uuid-like id (Sigma style)
	Status         string            `json:"status"`     // stable|experimental|disabled
	Description    string            `json:"description,omitempty"`
	References     []string          `json:"references,omitempty"`
	Author         string            `json:"author,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	LogSource      map[string]string `json:"logsource,omitempty"`
	Level          Severity          `json:"level"`
	FalsePositives []string          `json:"false_positives,omitempty"`

	// Engine fields
	Type       string          `json:"type"` // single_event|threshold|temporal|sequence|entity_agg
	EventType  string          `json:"event_type,omitempty"`
	Conditions []RuleCondition `json:"conditions,omitempty"`
	Threshold  *ThresholdSpec  `json:"threshold,omitempty"`
	Window     string          `json:"window,omitempty"` // e.g. 60s, 5m
	GroupBy    []string        `json:"group_by,omitempty"`
	Enabled    bool            `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RuleCondition is a field/operator/value matcher.
type RuleCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"` // eq|neq|in|gt|gte|lt|lte|contains|regex|exists
	Values   []string `json:"values,omitempty"`
}

// ThresholdSpec describes count-based correlation.
type ThresholdSpec struct {
	Count    int    `json:"count"`
	Distinct string `json:"distinct,omitempty"` // field to count distinct values of
}

// DetectionMatch is a hit of a rule against the event stream.
type DetectionMatch struct {
	ID        string         `json:"id"`
	OrgID     string         `json:"organization_id"`
	RuleID    string         `json:"rule_id"`
	RuleTitle string         `json:"rule_title"`
	Level     Severity       `json:"level"`
	SiteID    string         `json:"site_id,omitempty"`
	AssetID   string         `json:"asset_id,omitempty"`
	SrcIP     string         `json:"src_ip,omitempty"`
	Entity    string         `json:"entity,omitempty"`
	Summary   string         `json:"summary"`
	Events    []string       `json:"event_ids,omitempty"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
	Timeline  map[string]any `json:"timeline,omitempty"`
}

// Baseline is a simple statistical baseline used for anomaly flagging (§189).
type Baseline struct {
	Entity     string    `json:"entity"` // asset id or ip
	Metric     string    `json:"metric"` // connections_per_hour|dns_queries|ports|peers
	Mean       float64   `json:"mean"`
	StdDev     float64   `json:"stddev"`
	SampleSize int       `json:"sample_size"`
	WindowDays int       `json:"window_days"`
	UpdatedAt  time.Time `json:"updated_at"`
}
