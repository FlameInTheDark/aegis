//go:build darwin

package endpoint

import (
	"os"
	"strings"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// macOS collector (Phase 4.12): pkgutil receipts for software (raw receipts
// side by side with normalized versions via the platform's version normalizer),
// gopsutil sockets, and default gateways from `netstat -rn`. Posture stays
// explicitly unknown (FileVault and update-policy APIs are a later slice).

// SoftwarePackages enumerates pkgutil receipts. Ecosystem stays empty —
// no advisory plane exists for brew receipts yet; versions are the raw
// receipt values.
func (c *Collector) SoftwarePackages() []agentv1.SoftwareReport_Package {
	out, err := runCommand("pkgutil", "--pkgs")
	if err != nil {
		return nil
	}
	pkgs := make([]agentv1.SoftwareReport_Package, 0, 64)
	for _, id := range strings.Split(out, "\n") {
		id = strings.TrimSpace(id)
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		version := pkgutilVersion(id)
		pkgs = append(pkgs, agentv1.SoftwareReport_Package{
			Name: id, Version: version, Source: "pkgutil",
		})
		if len(pkgs) >= 2000 {
			break
		}
	}
	return pkgs
}

// pkgutilVersion reads one receipt's version via `pkgutil --pkg-info`.
// Failure returns "" — the receipt still lands, versionless and honest.
func pkgutilVersion(pkgID string) string {
	info, err := runCommand("pkgutil", "--pkg-info", pkgID)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "version: "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ListeningSockets enumerates listening endpoints via gopsutil (sysctl).
func (c *Collector) ListeningSockets() []agentv1.NetworkStateReport_Socket {
	return listeningSocketsViaGopsutil()
}

// DefaultGateways parses `netstat -rn` default rows.
func (c *Collector) DefaultGateways() []string {
	out, err := runCommand("netstat", "-rn")
	if err != nil {
		return nil
	}
	return parseDarwinDefaultGateways(out)
}

// DNSServers reads /etc/resolv.conf nameservers.
func (c *Collector) DNSServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(string(data))
}

// SecurityPosture reports explicit unknowns.
func (c *Collector) SecurityPosture() *agentv1.SecurityPostureReport {
	return securityPostureUnknown(c.Cfg.AgentID)
}
