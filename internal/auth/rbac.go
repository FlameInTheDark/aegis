package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func fillRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

// splitPHC parses "$algo$v=..$params$salt$hash" strings.
func splitPHC(encoded string) map[string]string {
	if encoded == "" || encoded[0] != '$' {
		return nil
	}
	parts := strings.Split(encoded[1:], "$")
	if len(parts) != 5 {
		return nil
	}
	return map[string]string{
		"algo":   parts[0],
		"v":      parts[1],
		"params": parts[2],
		"salt":   parts[3],
		"hash":   parts[4],
	}
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// HasAudience reports whether the audience claim contains s.
func (c *Claims) HasAudience(s string) bool {
	for _, a := range c.Audience {
		if a == s {
			return true
		}
	}
	return false
}

// GenerateToken returns a high-entropy URL-safe token (enrollment tokens,
// refresh sessions). Callers store only the hash.
func GenerateToken(prefix string) (string, error) {
	raw := make([]byte, 32)
	if err := fillRandom(raw); err != nil {
		return "", err
	}
	return prefix + "_" + b64(raw), nil
}

// rolePermissions is the RBAC mapping. Resource-aware permission checks
// (org/site scoping) are enforced by services on top of these capabilities.
var rolePermissions = map[domain.Role][]domain.Permission{
	domain.RoleOwner: {
		domain.PermOrgManage, domain.PermUserManage, domain.PermSiteManage,
		domain.PermAssetRead, domain.PermAssetWrite, domain.PermScanCreate,
		domain.PermScanCancel, domain.PermScanElevated, domain.PermAgentManage,
		domain.PermFindingRead, domain.PermFindingWrite, domain.PermVulnRead,
		domain.PermEventRead, domain.PermDetectionManage, domain.PermReportCreate,
		domain.PermReportRead, domain.PermAuditRead, domain.PermSettingsManage,
		domain.PermFeedManage,
	},
	domain.RoleAdministrator: {
		domain.PermUserManage, domain.PermSiteManage, domain.PermAssetRead,
		domain.PermAssetWrite, domain.PermScanCreate, domain.PermScanCancel,
		domain.PermScanElevated, domain.PermAgentManage, domain.PermFindingRead,
		domain.PermFindingWrite, domain.PermVulnRead, domain.PermEventRead,
		domain.PermDetectionManage, domain.PermReportCreate, domain.PermReportRead,
		domain.PermAuditRead, domain.PermSettingsManage, domain.PermFeedManage,
	},
	domain.RoleSecurityAnalyst: {
		domain.PermAssetRead, domain.PermAssetWrite, domain.PermScanCreate,
		domain.PermScanCancel, domain.PermFindingRead, domain.PermFindingWrite,
		domain.PermVulnRead, domain.PermEventRead, domain.PermDetectionManage,
		domain.PermReportCreate, domain.PermReportRead, domain.PermAuditRead,
	},
	domain.RoleOperator: {
		domain.PermAssetRead, domain.PermScanCreate, domain.PermScanCancel,
		domain.PermFindingRead, domain.PermVulnRead, domain.PermEventRead,
		domain.PermReportRead,
	},
	domain.RoleViewer: {
		domain.PermAssetRead, domain.PermFindingRead, domain.PermVulnRead,
		domain.PermEventRead, domain.PermReportRead,
	},
}

// PermissionsFor returns the permission set of a role.
func PermissionsFor(role domain.Role) []domain.Permission {
	perms, ok := rolePermissions[role]
	if !ok {
		return nil
	}
	out := make([]domain.Permission, len(perms))
	copy(out, perms)
	return out
}

// HasPermission checks a role against a required permission.
func HasPermission(role domain.Role, required domain.Permission) bool {
	for _, p := range rolePermissions[role] {
		if p == required {
			return true
		}
	}
	return false
}

// ValidRole reports whether r is a known role.
func ValidRole(r domain.Role) bool {
	_, ok := rolePermissions[r]
	return ok
}
