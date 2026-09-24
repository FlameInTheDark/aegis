package scanning

import (
	"fmt"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// SSH credential bounds mirror the connector ssh_* settings validation:
// long enough for real credentials, short enough that a single scan row
// cannot bloat the config or dispatch payloads.
const (
	sshHostMaxLen     = 512
	sshUserMaxLen     = 128
	sshPasswordMaxLen = 512
	sshKeyPEMMaxLen   = 16 << 10
	sshPinnedKeyMax   = 8 << 10
)

// ValidateSSHHosts checks and normalizes a per-scan SSH inventory target
// list (ScanConfig.SSHHosts). Each host carries its own credentials, so
// mixed environments (password on legacy boxes, keys elsewhere) are
// expressible in one scan. An empty list is valid: the scanner then falls
// back to its own SSH collector configuration (connector settings or
// AEGIS_SSH_SCAN_HOSTS). The returned slice is a normalized copy —
// hostnames and usernames are trimmed; port 0 keeps its "default 22"
// meaning until the executor dials.
func ValidateSSHHosts(hosts []domain.SSHScanHost, max int) ([]domain.SSHScanHost, error) {
	if len(hosts) > max {
		return nil, fmt.Errorf("ssh_hosts supports at most %d entries", max)
	}
	out := make([]domain.SSHScanHost, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for i, h := range hosts {
		at := fmt.Sprintf("ssh_hosts[%d]", i)
		host := strings.TrimSpace(h.Host)
		switch {
		case host == "":
			return nil, fmt.Errorf("%s: host is required", at)
		case len(host) > sshHostMaxLen:
			return nil, fmt.Errorf("%s: host exceeds %d characters", at, sshHostMaxLen)
		case strings.ContainsAny(host, " \t\r\n"):
			return nil, fmt.Errorf("%s: host must not contain whitespace", at)
		}
		if h.Port < 0 || h.Port > 65535 {
			return nil, fmt.Errorf("%s: port must be between 1 and 65535", at)
		}
		user := strings.TrimSpace(h.Username)
		switch {
		case user == "":
			return nil, fmt.Errorf("%s: username is required", at)
		case len(user) > sshUserMaxLen:
			return nil, fmt.Errorf("%s: username exceeds %d characters", at, sshUserMaxLen)
		case strings.ContainsAny(user, " \t\r\n"):
			return nil, fmt.Errorf("%s: username must not contain whitespace", at)
		}
		auth := h.Auth
		if auth == "" {
			if h.Password != "" {
				auth = domain.SSHAuthPassword
			} else if h.KeyPEM != "" {
				auth = domain.SSHAuthKey
			}
		}
		switch auth {
		case domain.SSHAuthPassword:
			if h.KeyPEM != "" {
				return nil, fmt.Errorf("%s: set either password or key, not both", at)
			}
			if h.Password == "" {
				return nil, fmt.Errorf("%s: password is required for password auth", at)
			}
			if len(h.Password) > sshPasswordMaxLen {
				return nil, fmt.Errorf("%s: password exceeds %d characters", at, sshPasswordMaxLen)
			}
		case domain.SSHAuthKey:
			if h.Password != "" {
				return nil, fmt.Errorf("%s: set either password or key, not both", at)
			}
			if strings.TrimSpace(h.KeyPEM) == "" {
				return nil, fmt.Errorf("%s: private key is required for key auth", at)
			}
			if len(h.KeyPEM) > sshKeyPEMMaxLen {
				return nil, fmt.Errorf("%s: private key exceeds %d KiB", at, sshKeyPEMMaxLen>>10)
			}
		default:
			return nil, fmt.Errorf("%s: auth must be %q or %q", at, domain.SSHAuthPassword, domain.SSHAuthKey)
		}
		pinned := strings.TrimSpace(h.PinnedKey)
		if len(pinned) > sshPinnedKeyMax {
			return nil, fmt.Errorf("%s: pinned_key exceeds %d KiB", at, sshPinnedKeyMax>>10)
		}
		key := fmt.Sprintf("%s:%d@%s", strings.ToLower(host), h.Port, user)
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate target %s", at, key)
		}
		seen[key] = true
		out = append(out, domain.SSHScanHost{
			Host: host, Port: h.Port, Username: user,
			Auth: auth, Password: h.Password, KeyPEM: h.KeyPEM, PinnedKey: pinned,
		})
	}
	return out, nil
}
