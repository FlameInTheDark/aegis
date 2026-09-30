//go:build !linux && !windows && !darwin

package endpoint

import (
	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// Non-Linux, non-Windows, non-macOS collector fallbacks (BSDs and friends):
// best-effort, native APIs added incrementally; documented assumption.

// SoftwarePackages returns nothing on platforms without a collector yet.
func (c *Collector) SoftwarePackages() []agentv1.SoftwareReport_Package {
	return nil
}

// ListeningSockets falls back to empty pending native socket API support.
func (c *Collector) ListeningSockets() []agentv1.NetworkStateReport_Socket {
	return nil
}

// DefaultGateways is a fallback.
func (c *Collector) DefaultGateways() []string { return nil }

// DNSServers is a fallback.
func (c *Collector) DNSServers() []string { return nil }

// SecurityPosture reports explicit unknowns, never guesses.
func (c *Collector) SecurityPosture() *agentv1.SecurityPostureReport {
	return securityPostureUnknown(c.Cfg.AgentID)
}
