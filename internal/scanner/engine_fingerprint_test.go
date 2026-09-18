package scanner

import (
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// The fingerprint profile's only OS source was `nmap -O` with no port spec
// (nmap's implicit top-1000) and --osscan-limit, which skips every host that
// lacks an open AND closed TCP port — behind NATs that swallow RSTs, closed
// ports show as filtered and the check fails exactly where scans run. Both
// are fixed: explicit bounded port args, no --osscan-limit.
func TestOSScanArgs(t *testing.T) {
	limits := DefaultLimits()
	fingerprintCfg := &domain.ScanConfig{Profile: domain.ProfileFingerprint, TopTCPPorts: 100, MaxRate: 200}
	argv := osScanArgs("/usr/bin/nmap", "192.168.1.2", fingerprintCfg, limits, 5*time.Minute)
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "--osscan-limit") {
		t.Errorf("osscan-limit must not be used (skips hosts behind filtered NATs): %s", joined)
	}
	if !strings.Contains(joined, "--osscan-guess") {
		t.Errorf("osscan-guess missing: %s", joined)
	}
	if !strings.Contains(joined, "--top-ports 100") {
		t.Errorf("fingerprint -O should reuse the profile's top-100 spec: %s", joined)
	}

	// Full audit: capped at top-1000 — re-probing 65535 ports inside -O
	// doubles the audit runtime for no fingerprint gain.
	fullCfg := &domain.ScanConfig{Profile: domain.ProfileFullAudit, FullTCPPorts: true}
	argv = osScanArgs("/usr/bin/nmap", "192.168.1.2", fullCfg, limits, 5*time.Minute)
	if !strings.Contains(strings.Join(argv, " "), "--top-ports 1000") {
		t.Errorf("full-range -O must cap at --top-ports 1000: %s", strings.Join(argv, " "))
	}

	// Explicit port lists pass through as -p spec (up to 1000 ports).
	listCfg := &domain.ScanConfig{TCPPorts: []int{22, 80, 443}}
	argv = osScanArgs("/usr/bin/nmap", "192.168.1.2", listCfg, limits, 5*time.Minute)
	if !strings.Contains(strings.Join(argv, " "), "-p 22,80,443") {
		t.Errorf("explicit ports must pass as -p spec: %s", strings.Join(argv, " "))
	}

	// >1000 explicit ports fall back to the capped top-ports table.
	bigCfg := &domain.ScanConfig{TCPPorts: make([]int, 0, 1500)}
	for p := 1; p <= 1500; p++ {
		bigCfg.TCPPorts = append(bigCfg.TCPPorts, p)
	}
	argv = osScanArgs("/usr/bin/nmap", "192.168.1.2", bigCfg, limits, 5*time.Minute)
	if !strings.Contains(strings.Join(argv, " "), "--top-ports 1000") {
		t.Errorf(">1000 explicit ports must cap at --top-ports 1000: %s", strings.Join(argv, " "))
	}
}

// The traceroute ladder is a contract: NAT-friendliest probe first, each
// fallback reaching a different probe protocol, so a blocked probe type
// degrades to the next instead of reporting "no route".
func TestTracerouteLadder(t *testing.T) {
	limits := DefaultLimits()
	argvs := tracerouteLadder("/usr/bin/nmap", "1.1.1.1", nil, limits, "90s")
	if len(argvs) != 4 {
		t.Fatalf("want 4 nmap attempts (tcp-syn, udp, icmp, tcp-connect), got %d", len(argvs))
	}
	kinds := make([]string, 0, len(argvs))
	for _, argv := range argvs {
		if argv[len(argv)-1] != "1.1.1.1" {
			t.Errorf("attempt must end with the target: %v", argv)
		}
		if !strings.Contains(strings.Join(argv, " "), "--traceroute") {
			t.Errorf("attempt missing --traceroute: %v", argv)
		}
		kinds = append(kinds, probeKind(argv))
	}
	want := []string{"tcp-syn", "udp", "icmp", "tcp-connect"}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("attempt %d kind = %q, want %q", i, kinds[i], want[i])
		}
	}
	// The UDP attempt must probe ports that elicit ICMP port-unreachable.
	if !strings.Contains(strings.Join(argvs[1], " "), "-PU53,123,161,500,4500") {
		t.Errorf("udp attempt probes missing: %v", argvs[1])
	}
}
