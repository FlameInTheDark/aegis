package domain

import (
	"time"
)

// FindingStatus is the analyst-controlled lifecycle of a finding.
type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"
	FindingAcknowledged  FindingStatus = "acknowledged"
	FindingInProgress    FindingStatus = "in_progress"
	FindingResolved      FindingStatus = "resolved"
	FindingAcceptedRisk  FindingStatus = "accepted_risk"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingSuppressed    FindingStatus = "suppressed"
)

// MatchType explains HOW a vulnerability was matched.
type MatchType string

const (
	MatchExactCPE       MatchType = "EXACT_CPE"
	MatchCPERange       MatchType = "CPE_RANGE"
	MatchPackageVersion MatchType = "PACKAGE_VERSION"
	MatchOSPackage      MatchType = "OS_PACKAGE"
	MatchServiceVersion MatchType = "SERVICE_VERSION"
	MatchHeuristic      MatchType = "HEURISTIC"
)

// Finding is a specific vulnerability on a specific asset, evidenced.
type Finding struct {
	ID              string        `json:"id"`
	OrganizationID  string        `json:"organization_id"`
	AssetID         string        `json:"asset_id"`
	ServiceID       *string       `json:"service_id,omitempty"`
	SoftwareID      *string       `json:"software_id,omitempty"`
	CVEID           string        `json:"cve_id,omitempty"`
	OSVID           string        `json:"osv_id,omitempty"`
	Title           string        `json:"title"`
	MatchType       MatchType     `json:"match_type"`
	Confidence      Confidence    `json:"confidence"`
	RiskScore       float64       `json:"risk_score"`
	Severity        Severity      `json:"severity"`
	Status          FindingStatus `json:"status"`
	Owner           string        `json:"owner,omitempty"`
	Notes           string        `json:"notes,omitempty"`
	Remediation     string        `json:"remediation,omitempty"`
	SuppressedUntil *time.Time    `json:"suppressed_until,omitempty"`
	FirstSeen       time.Time     `json:"first_seen"`
	LastSeen        time.Time     `json:"last_seen"`
	ResolvedAt      *time.Time    `json:"resolved_at,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// Evidence is a structured proof record backing a finding.
type Evidence struct {
	ID        string         `json:"id"`
	FindingID string         `json:"finding_id"`
	Kind      string         `json:"kind"` // nmap_service|agent_package|http_header|tls_cert|cpe_match|snmp|banner|manual
	Statement string         `json:"statement"`
	Detail    map[string]any `json:"detail,omitempty"`
	Source    Source         `json:"source"`
	CreatedAt time.Time      `json:"created_at"`
}

// FindingStatusChange preserves the audit trail of status transitions.
type FindingStatusChange struct {
	ID        string        `json:"id"`
	FindingID string        `json:"finding_id"`
	From      FindingStatus `json:"from"`
	To        FindingStatus `json:"to"`
	ChangedBy string        `json:"changed_by"`
	Reason    string        `json:"reason,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// SuppressionScope defines what a suppression covers.
type SuppressionScope struct {
	AssetID       *string `json:"asset_id,omitempty"`
	ServiceID     *string `json:"service_id,omitempty"`
	Vulnerability *string `json:"vulnerability,omitempty"` // CVE id
	SiteID        *string `json:"site_id,omitempty"`
	Tag           *string `json:"tag,omitempty"`
}

// Suppression is a scoped, reasoned, expiring false-positive control.
type Suppression struct {
	ID        string           `json:"id"`
	OrgID     string           `json:"organization_id"`
	Scope     SuppressionScope `json:"scope"`
	Reason    string           `json:"reason"`
	CreatedBy string           `json:"created_by"`
	CreatedAt time.Time        `json:"created_at"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
}
