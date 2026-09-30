package domain

import "time"

// SSOConfig is one organization's OIDC identity-provider registration (F4).
// The client secret rides the plaintext-secret convention used elsewhere in
// this codebase (connectors.config, alert_destinations.secret): it is
// stored in Postgres, never serialized, and returned masked.
type SSOConfig struct {
	ID           string            `json:"id"`
	OrgID        string            `json:"organization_id"`
	Issuer       string            `json:"issuer"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"-"`
	GroupsClaim  string            `json:"groups_claim"`
	RoleMappings map[string]string `json:"role_mappings"`
	DefaultRole  Role              `json:"default_role"`
	AllowJIT     bool              `json:"allow_jit"`
	Enabled      bool              `json:"enabled"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`

	SecretMasked string `json:"client_secret_masked,omitempty"`
}

// SSORoles is the role set an IdP group claim may map to. Owner is
// deliberately absent: ownership is never granted by a group claim, only
// by an existing owner.
var SSORoles = []Role{RoleViewer, RoleOperator, RoleSecurityAnalyst, RoleAdministrator}

// ValidSSORole reports whether role may be assigned through SSO.
func ValidSSORole(role Role) bool {
	for _, r := range SSORoles {
		if r == role {
			return true
		}
	}
	return false
}

// RoleForGroups resolves the role for one login: the first group with a
// mapping wins, otherwise the default role. Unknown groups never escalate.
func (c *SSOConfig) RoleForGroups(groups []string) Role {
	for _, g := range groups {
		if r, ok := c.RoleMappings[g]; ok {
			if ValidSSORole(Role(r)) {
				return Role(r)
			}
		}
	}
	if c.DefaultRole != "" && ValidSSORole(c.DefaultRole) {
		return c.DefaultRole
	}
	return RoleViewer
}
