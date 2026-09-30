package endpoint

import (
	"os/exec"
	"strings"
)

// Platform-neutral parsing helpers for collector output (Phase 4.12).
// Build-tag-free so the parsers stay unit-testable on any development OS;
// the platform files decide when to call them.

// runCommand executes a system command with a bounded capture (routing
// tables and package receipts are small; the cap keeps pathological output
// from ballooning).
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	s := string(out)
	if len(s) > 1<<20 {
		s = s[:1<<20]
	}
	return s, nil
}

// parseWindowsDefaultGateways extracts gateway addresses from `route print`
// output: rows whose destination and netmask are both 0.0.0.0. "On-link"
// rows are not gateways.
func parseWindowsDefaultGateways(routePrint string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(routePrint, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gw := fields[2]
		if gw == "On-link" || gw == "" || seen[gw] {
			continue
		}
		seen[gw] = true
		out = append(out, gw)
	}
	return out
}

// parseDarwinDefaultGateways extracts gateway addresses from `netstat -rn`
// default rows ("default 192.168.1.1 UGSc ...").
func parseDarwinDefaultGateways(netstat string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(netstat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || (fields[0] != "default" && fields[0] != "0/0" && fields[0] != "::/0") {
			continue
		}
		gw := fields[1]
		if gw == "" || seen[gw] {
			continue
		}
		seen[gw] = true
		out = append(out, gw)
	}
	return out
}

// parseResolvConf extracts nameserver addresses from resolv.conf content.
func parseResolvConf(resolvConf string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(resolvConf, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		ns := fields[1]
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, ns)
	}
	return out
}
