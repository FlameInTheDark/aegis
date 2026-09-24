package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Trace contract (v1.5.6): a successful nmap traceroute must surface
// the probe family that answered AND the raw XML the run printed, so the
// per-asset trace view can show real evidence next to the parsed hops.
// A fake nmap on PATH keeps this hermetic.
func TestNmapTracerouteCapturesProbeAndRaw(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\ncat <<'EOF'\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun>\n<host starttime=\"1\">\n <status state=\"up\" reason=\"reset\"/>\n <address addr=\"192.168.1.55\" addrtype=\"ipv4\"/>\n <trace proto=\"icmp\">\n  <hop ttl=\"1\" ipaddr=\"192.168.1.1\" rtt=\"1.23\"/>\n  <hop ttl=\"2\" ipaddr=\"192.168.1.55\" rtt=\"5.0\"/>\n </trace>\n</host>\n</nmaprun>\nEOF\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}

	engine := &NmapEngine{BinPath: fake}
	tr, err := engine.Traceroute(t.Context(), "192.168.1.55", nil, DefaultLimits())
	if err != nil {
		t.Fatalf("traceroute: %v", err)
	}
	// The first ladder attempt carries -PS/-PA probes: probeKind names it
	// tcp-syn regardless of the -PE flags riding along.
	if tr.Method != "tcp-syn" {
		t.Errorf("method = %q, want tcp-syn (first ladder attempt)", tr.Method)
	}
	if len(tr.Hops) != 2 || tr.Hops[0].IP != "192.168.1.1" || tr.Hops[1].IP != "192.168.1.55" {
		t.Fatalf("hops = %+v", tr.Hops)
	}
	if !strings.Contains(tr.Raw, "192.168.1.1") || !strings.Contains(tr.Raw, "<trace proto=\"icmp\">") {
		t.Errorf("raw output not captured: %q", tr.Raw)
	}

	// A ladder where every probe errors degrades to the error path (the
	// executor then falls back to tracert/tracepath/gateway-guess).
	broken := filepath.Join(dir, "broken-nmap")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatalf("write broken nmap: %v", err)
	}
	engine2 := &NmapEngine{BinPath: broken}
	if _, err := engine2.Traceroute(t.Context(), "192.168.1.55", nil, DefaultLimits()); err == nil {
		t.Error("all-probes-failed must surface the last nmap error")
	}
}
