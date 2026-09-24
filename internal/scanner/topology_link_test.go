package scanner

import "testing"

func hopIPs(hops []Hop) []string {
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		out = append(out, h.IP)
	}
	return out
}

func ipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEnsureGatewayLinkDirectSingleHop(t *testing.T) {
	// tracert.exe / nmap to a same-subnet host returns exactly one hop: the
	// target itself. The graph needs a second node, so the default gateway
	// of the target's /24 is synthesized in front of it.
	got := EnsureGatewayLink([]Hop{{TTL: 1, IP: "192.168.1.55", RTTms: 0.8}}, "192.168.1.55")
	want := []string{"192.168.1.1", "192.168.1.55"}
	if !ipsEqual(hopIPs(got), want) {
		t.Fatalf("hops = %v, want %v", hopIPs(got), want)
	}
	if got[0].TTL != 1 || got[1].TTL != 2 {
		t.Fatalf("TTLs = %d,%d want 1,2", got[0].TTL, got[1].TTL)
	}
	if got[1].RTTms != 0.8 {
		t.Fatalf("target RTT not carried over: %v", got[1].RTTms)
	}
}

func TestEnsureGatewayLinkMultiHopUnchanged(t *testing.T) {
	in := []Hop{{TTL: 1, IP: "10.0.0.1"}, {TTL: 2, IP: "10.0.0.254"}, {TTL: 3, IP: "10.1.2.3"}}
	got := EnsureGatewayLink(in, "10.1.2.3")
	if !ipsEqual(hopIPs(got), hopIPs(in)) {
		t.Fatalf("multi-hop route was rewritten: %v", hopIPs(got))
	}
}

func TestEnsureGatewayLinkPartialSingleHopUnchanged(t *testing.T) {
	// A single responsive hop that is NOT the target is a partial route;
	// the orchestrator links the deepest hop to the asset — do not touch it.
	in := []Hop{{TTL: 4, IP: "10.0.0.254"}}
	got := EnsureGatewayLink(in, "10.1.2.3")
	if !ipsEqual(hopIPs(got), hopIPs(in)) {
		t.Fatalf("partial path was rewritten: %v", hopIPs(got))
	}
}

func TestEnsureGatewayLinkTargetIsGateway(t *testing.T) {
	// The .1 address has no gateway of its own to link to.
	in := []Hop{{TTL: 1, IP: "192.168.1.1"}}
	got := EnsureGatewayLink(in, "192.168.1.1")
	if !ipsEqual(hopIPs(got), hopIPs(in)) {
		t.Fatalf("gateway target was rewritten: %v", hopIPs(got))
	}
}

func TestEnsureGatewayLinkNonIPv4AndEmpty(t *testing.T) {
	in := []Hop{{TTL: 1, IP: "fe80::1"}}
	if got := EnsureGatewayLink(in, "fe80::1"); !ipsEqual(hopIPs(got), hopIPs(in)) {
		t.Fatalf("IPv6 target was rewritten: %v", hopIPs(got))
	}
	if got := EnsureGatewayLink(nil, "192.168.1.55"); len(got) != 0 {
		t.Fatalf("empty path was rewritten: %v", got)
	}
}
