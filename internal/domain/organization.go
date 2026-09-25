package domain

import (
	"time"
)

// Organization is the top-level tenant. All data is organization-scoped.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Role names, ordered from most to least privileged.
type Role string

const (
	RoleOwner           Role = "owner"
	RoleAdministrator   Role = "administrator"
	RoleSecurityAnalyst Role = "security_analyst"
	RoleOperator        Role = "operator"
	RoleViewer          Role = "viewer"
)

// Permission is a resource-aware capability string (e.g. "scan:create").
type Permission string

// Core permission set. RBAC maps roles to permission sets in internal/auth.
const (
	PermOrgManage       Permission = "org:manage"
	PermUserManage      Permission = "user:manage"
	PermSiteManage      Permission = "site:manage"
	PermAssetRead       Permission = "asset:read"
	PermAssetWrite      Permission = "asset:write"
	PermScanCreate      Permission = "scan:create"
	PermScanCancel      Permission = "scan:cancel"
	PermScanElevated    Permission = "scan:elevated" // ACTIVE_VALIDATION profiles
	PermAgentManage     Permission = "agent:manage"
	PermFindingRead     Permission = "finding:read"
	PermFindingWrite    Permission = "finding:write"
	PermVulnRead        Permission = "vuln:read"
	PermEventRead       Permission = "event:read"
	PermEventWrite      Permission = "event:write" // telemetry ingestion
	PermDetectionManage Permission = "detection:manage"
	PermReportCreate    Permission = "report:create"
	PermReportRead      Permission = "report:read"
	PermAuditRead       Permission = "audit:read"
	PermSettingsManage  Permission = "settings:manage"
	PermFeedManage      Permission = "feed:manage"
	PermAlertRead       Permission = "alert:read"
	PermAlertManage     Permission = "alert:manage"
)

// User is a human operator of the platform.
type User struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	PasswordHash string     `json:"-"` // argon2id; never serialized
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	Disabled     bool       `json:"disabled"`
}

// Membership links a user to an organization with a role.
type Membership struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	Role           Role      `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
}

// Site is a physical/logical network location and security boundary.
type Site struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	SiteType       string    `json:"site_type"` // hq|datacenter|cloud|branch|home|lab
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Network is a subnet/CIDR within a site, optionally on a VLAN.
type Network struct {
	ID             string    `json:"id"`
	SiteID         string    `json:"site_id"`
	OrganizationID string    `json:"organization_id"`
	CIDR           string    `json:"cidr"`
	VLANID         *int      `json:"vlan_id,omitempty"`
	Name           string    `json:"name,omitempty"`
	Gateway        string    `json:"gateway,omitempty"`
	Exposure       Exposure  `json:"exposure"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ConnectorEnrollToken (see connector.go) is the surviving one-time token
// type: the unified connect flow. The old standalone agent enrollment
// token was removed with the AgentService.Enroll protocol in v1.24.0.
