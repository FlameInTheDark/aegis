package scanning

import (
	"encoding/json"
	"testing"
)

func jsonPath(t *testing.T, raw string) any {
	t.Helper()
	var path any
	if err := json.Unmarshal([]byte(raw), &path); err != nil {
		t.Fatalf("bad json fixture: %v", err)
	}
	return path
}

func hopList(hops []hopNode) []string {
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		out = append(out, h.ip)
	}
	return out
}

func sameIPs(a, b []string) bool {
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

// The in-memory shape built by the scanner executor.
func TestTopologyHopsInMemoryShape(t *testing.T) {
	path := []map[string]any{
		{"ip": "192.168.1.1", "ttl": 1},
		{"ip": "192.168.1.55", "ttl": 2, "rtt_ms": 3.5},
	}
	got := topologyHops("192.168.1.55", path)
	if !sameIPs(hopList(got), []string{"192.168.1.1", "192.168.1.55"}) {
		t.Fatalf("hops = %v", hopList(got))
	}
	if !got[1].tgt || got[0].tgt {
		t.Fatalf("target flag wrong: %+v", got)
	}
}

// The JSON round-trip shape of replayed observations.
func TestTopologyHopsJSONShape(t *testing.T) {
	path := jsonPath(t, `[{"ip":"10.0.0.1","ttl":1},{"ip":"10.0.0.254","ttl":2},{"ip":"10.1.2.3","ttl":3}]`)
	got := topologyHops("10.1.2.3", path)
	if !sameIPs(hopList(got), []string{"10.0.0.1", "10.0.0.254", "10.1.2.3"}) {
		t.Fatalf("hops = %v", hopList(got))
	}
}

// TTL timeouts carry no address and are skipped.
func TestTopologyHopsSkipsAddresslessHops(t *testing.T) {
	path := jsonPath(t, `[{"ip":"10.0.0.1","ttl":1},{"ttl":2},{"ip":"10.1.2.3","ttl":3}]`)
	got := topologyHops("10.1.2.3", path)
	if !sameIPs(hopList(got), []string{"10.0.0.1", "10.1.2.3"}) {
		t.Fatalf("hops = %v", hopList(got))
	}
}

// Garbage payloads degrade to an empty hop list (caller then no-ops).
func TestTopologyHopsGarbage(t *testing.T) {
	for name, v := range map[string]any{
		"nil":         nil,
		"string":      "not-a-path",
		"empty-list":  []any{},
		"odd-scalars": []any{"192.168.1.1", 42},
	} {
		if got := topologyHops("192.168.1.55", v); len(got) != 0 {
			t.Fatalf("%s: expected no hops, got %v", name, hopList(got))
		}
	}
}

// A missing target ip only affects the tgt flag, not hop collection.
func TestTopologyHopsMissingTarget(t *testing.T) {
	path := jsonPath(t, `[{"ip":"192.168.1.1"},{"ip":"192.168.1.55"}]`)
	got := topologyHops("", path)
	if !sameIPs(hopList(got), []string{"192.168.1.1", "192.168.1.55"}) {
		t.Fatalf("hops = %v", hopList(got))
	}
	for _, h := range got {
		if h.tgt {
			t.Fatalf("no hop should be flagged target when targetIP is empty: %+v", h)
		}
	}
}

// v1.5.6: the stored trace path must keep TTL, hostname and RTT, whether
// the payload arrives in-memory (int ttl) or JSON round-tripped (float64).
func TestTopologyHopsCarriesHopDetail(t *testing.T) {
	inMemory := []map[string]any{
		{"ip": "192.168.1.1", "ttl": 1, "rtt_ms": 1.2},
		{"ip": "192.168.1.55", "ttl": 2, "hostname": "nas", "rtt_ms": 4.5},
	}
	got := topologyHops("192.168.1.55", inMemory)
	if len(got) != 2 || got[0].ttl != 1 || got[1].ttl != 2 {
		t.Fatalf("ttl parse: %+v", got)
	}
	if got[1].hostname != "nas" || got[1].rtt != 4.5 || got[0].rtt != 1.2 {
		t.Fatalf("hostname/rtt parse: %+v", got)
	}

	roundTripped := jsonPath(t, `[{"ip":"10.0.0.1","ttl":1,"rtt_ms":2.5},{"ttl":2},{"ip":"10.1.2.3","ttl":3}]`)
	got = topologyHops("10.1.2.3", roundTripped)
	if len(got) != 2 || got[0].ttl != 1 || got[1].ttl != 3 {
		t.Fatalf("json ttl parse: %+v", got)
	}
	if got[0].rtt != 2.5 {
		t.Fatalf("json rtt parse: %+v", got)
	}
}
