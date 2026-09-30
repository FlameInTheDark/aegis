//go:build windows

package endpoint

import (
	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"golang.org/x/sys/windows/registry"
)

// Windows collector (Phase 4.12): software inventory from the uninstall
// registry, listening sockets via gopsutil (IP helper APIs), and default
// gateways from the routing table. Posture stays explicitly unknown until
// a real API answers (BitLocker, Defender, update policies) — values are
// never inferred to fill a card.

// SoftwarePackages enumerates installed applications from the uninstall
// registry under both WOW64 views and HKCU (display name, publisher,
// version). No OSV ecosystem: Windows applications stay inventory data
// until an advisory source exists (F14's later slice).
func (c *Collector) SoftwarePackages() []agentv1.SoftwareReport_Package {
	out := make([]agentv1.SoftwareReport_Package, 0, 256)
	targets := []struct {
		root registry.Key
		path string
		view uint32
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_32KEY},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, 0},
	}
	for _, t := range targets {
		key, err := registry.OpenKey(t.root, t.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|t.view)
		if err != nil {
			continue
		}
		names, err := key.ReadSubKeyNames(-1)
		if err != nil {
			_ = key.Close()
			continue
		}
		for _, sub := range names {
			sk, err := registry.OpenKey(t.root, t.path+`\`+sub, registry.QUERY_VALUE|t.view)
			if err != nil {
				continue
			}
			dn, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			si, _, _ := sk.GetIntegerValue("SystemComponent")
			_ = sk.Close()
			if dn == "" || si == 1 { // skip unnamed rows and hidden system components
				continue
			}
			out = append(out, agentv1.SoftwareReport_Package{
				Name: dn, Version: ver, Vendor: pub, Source: "registry",
			})
			if len(out) >= 2000 {
				_ = key.Close()
				return out
			}
		}
		_ = key.Close()
	}
	return out
}

// ListeningSockets enumerates listening endpoints via gopsutil.
func (c *Collector) ListeningSockets() []agentv1.NetworkStateReport_Socket {
	return listeningSocketsViaGopsutil()
}

// DefaultGateways parses `route print -4` output; the parser is a pure
// function with its own tests.
func (c *Collector) DefaultGateways() []string {
	out, err := runCommand("route", "print", "-4")
	if err != nil {
		return nil
	}
	return parseWindowsDefaultGateways(out)
}

// DNSServers is not collected yet; an empty list stays honest.
func (c *Collector) DNSServers() []string { return nil }

// SecurityPosture reports explicit unknowns.
func (c *Collector) SecurityPosture() *agentv1.SecurityPostureReport {
	return securityPostureUnknown(c.Cfg.AgentID)
}
