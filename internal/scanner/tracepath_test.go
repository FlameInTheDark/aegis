package scanner

import (
	"os"
	"strings"
	"testing"
)

// Blocked probes ("no reply") must be TTL gaps, never "no route": the path
// keeps the hops that DID answer, in order, with their TTLs preserved.
func TestParseTracepathFull(t *testing.T) {
	out := ` 1?: [LOCALHOST]                      pmtu 1500
 1:  gateway (192.168.65.1)             0.296ms
 1:  gateway (192.168.65.1)             0.281ms
 2:  no reply
 3:  other-router (10.0.0.1)            4.100ms
 4:  1.1.1.1                           12.345ms reached
     Resume: pmtu 1500
`
	hops := parseTracepath([]byte(out), "1.1.1.1")
	// 3 hops: TTL1 gateway (retransmit deduped), TTL2 "no reply" gap, TTL3
	// router, TTL4 target. The target already answered at TTL 4, so no
	// synthetic append — the gap stays a gap.
	if len(hops) != 3 {
		t.Fatalf("want 3 hops (retransmit deduped, no-reply skipped), got %d: %+v", len(hops), hops)
	}
	if hops[0].TTL != 1 || hops[0].IP != "192.168.65.1" || hops[0].Hostname != "gateway" {
		t.Errorf("hop0 = %+v", hops[0])
	}
	if hops[0].RTTms != 0.296 {
		t.Errorf("hop0 rtt = %v, want first probe's 0.296", hops[0].RTTms)
	}
	if hops[1].TTL != 3 || hops[1].IP != "10.0.0.1" || hops[1].Hostname != "other-router" {
		t.Errorf("hop1 = %+v (TTL 2 must stay a gap, not renumber)", hops[1])
	}
	if hops[2].TTL != 4 || hops[2].IP != "1.1.1.1" {
		t.Errorf("hop2 = %+v", hops[2])
	}
	// "reached" present and last hop != target would append; here last IS target.
	if last := hops[len(hops)-1]; last.IP != "1.1.1.1" {
		t.Errorf("final hop = %+v", last)
	}
}

// Path cut short by filtering: partial hops come back as-is, the target is
// NOT fabricated onto the end — "blocked" must not read as "reached".
func TestParseTracepathPartial(t *testing.T) {
	out := ` 1:  gateway (192.168.65.1)             0.296ms
 2:  no reply
 3:  no reply
`
	hops := parseTracepath([]byte(out), "1.1.1.1")
	if len(hops) != 1 {
		t.Fatalf("want 1 hop, got %d: %+v", len(hops), hops)
	}
	if hops[0].IP != "192.168.65.1" {
		t.Errorf("hop0 = %+v", hops[0])
	}
}

// Bare-IP lines (tracepath -n on unresolvable hops) and the reached-append
// when the final line names a different responding hop than the target.
func TestParseTracepathBareIPAndAppend(t *testing.T) {
	out := ` 1:  192.168.65.1                        0.300ms
 2:  no reply
 3:  10.9.9.9                           5.000ms reached
`
	hops := parseTracepath([]byte(out), "1.1.1.1")
	// The path "reached" a destination that is not literally our target
	// (NAT rewrite); the parser appends the target as the nmap parser does
	// so downstream shapes stay identical.
	if len(hops) != 3 {
		t.Fatalf("want 3 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].Hostname != "" {
		t.Errorf("bare-IP hop must have no hostname, got %q", hops[0].Hostname)
	}
	if last := hops[len(hops)-1]; last.IP != "1.1.1.1" || last.TTL != 4 {
		t.Errorf("appended final hop = %+v", last)
	}
}

func TestParseTracepathGarbage(t *testing.T) {
	for _, in := range []string{"", "Resume: pmtu 1500", "1?: [LOCALHOST] pmtu 1500", "total garbage"} {
		if hops := parseTracepath([]byte(in), "1.1.1.1"); hops != nil {
			t.Errorf("parseTracepath(%q) = %+v, want nil", in, hops)
		}
	}
}

func TestParseTracepathRejectsInvalidIPs(t *testing.T) {
	out := ` 1:  gateway (999.168.65.1)             0.296ms
 2:  no reply
`
	if hops := parseTracepath([]byte(out), "1.1.1.1"); len(hops) != 0 {
		t.Errorf("invalid dotted quad must be skipped, got %+v", hops)
	}
}

// An explicit AEGIS_SCANNER_TRACEPATH_PATH that does not exist must disable
// the fallback (no PATH guessing) — deployments point it at a known binary.
func TestTracepathBinOverride(t *testing.T) {
	t.Setenv("AEGIS_SCANNER_TRACEPATH_PATH", "/nonexistent/tracepath")
	if got := tracepathBin(); got != "" {
		t.Errorf("missing explicit override = %q, want \"\"", got)
	}
	t.Setenv("AEGIS_SCANNER_TRACEPATH_PATH", "")
	// Empty override falls through to PATH; here it may or may not exist.
	_ = tracepathBin()
	if _, err := os.Stat("/nonexistent"); !os.IsNotExist(err) {
		t.Log("unexpected: /nonexistent exists")
	}
}

// End-to-end fallback check without the real binary: a fake tracepath on
// PATH proves the env override resolves, the subprocess runs through the
// engine's hardened exec plumbing, and the text output becomes Hop data.
func TestTracepathTracerouteWithFakeBinary(t *testing.T) {
	dir := t.TempDir()
	fake := dir + "/tracepath"
	script := "#!/bin/sh\n# mimic `tracepath -n 1.1.1.1` output shape\ncat <<'EOF'\n 1:  gateway (192.168.65.1)             0.296ms\n 2:  no reply\n 3:  1.1.1.1                           12.345ms reached\n     Resume: pmtu 1500\nEOF\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	t.Setenv("AEGIS_SCANNER_TRACEPATH_PATH", fake)

	tr, ok := tracepathTraceroute(t.Context(), "1.1.1.1", DefaultLimits())
	if !ok {
		t.Fatal("fallback reported not-ok for a working binary")
	}
	if len(tr.Hops) != 2 {
		t.Fatalf("want 2 hops, got %+v", tr.Hops)
	}
	if tr.Hops[0].IP != "192.168.65.1" || tr.Hops[1].IP != "1.1.1.1" {
		t.Errorf("hops = %+v", tr.Hops)
	}
	// v1.5.6: the trace must carry the probe family and the RAW text the
	// binary printed — the asset trace view stores and displays both.
	if tr.Method != "tracepath" {
		t.Errorf("method = %q, want tracepath", tr.Method)
	}
	if !strings.Contains(tr.Raw, "192.168.65.1") || !strings.Contains(tr.Raw, "Resume: pmtu") {
		t.Errorf("raw output not captured: %q", tr.Raw)
	}
	// Non-IPv4 targets are refused (nmap attempts cover v6).
	if _, ok := tracepathTraceroute(t.Context(), "2001:db8::1", DefaultLimits()); ok {
		t.Error("IPv6 target must not be traced by the v4 tracepath fallback")
	}
	// A binary that exits non-zero degrades to not-ok, not a crash.
	broken := dir + "/broken"
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	t.Setenv("AEGIS_SCANNER_TRACEPATH_PATH", broken)
	if _, ok := tracepathTraceroute(t.Context(), "1.1.1.1", DefaultLimits()); ok {
		t.Error("failing binary must degrade to ok=false")
	}
}

func TestIPv4Validation(t *testing.T) {
	for _, ok := range []string{"1.1.1.1", "192.168.65.1", "0.0.0.0"} {
		if !isIPv4(ok) {
			t.Errorf("isIPv4(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"999.1.1.1", "1.2.3", "1.2.3.4.5", "abc", "1.2.3.", "1.2.3.256", "1::2", ""} {
		if isIPv4(bad) {
			t.Errorf("isIPv4(%q) = true, want false", bad)
		}
	}
}
