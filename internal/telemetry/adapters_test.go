package telemetry

import (
	"os"
	"testing"
)

// Fixture-driven adapter tests (spec §108): normalization, timestamps,
// IP parsing, unknown/missing fields — using synthetic files in testdata.
func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/feeds/" + name)
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	return b
}

func TestNormalizeSuricataEVE(t *testing.T) {
	in := Ingestor{BatchSize: 100}
	events, err := in.Normalize(SubjectEvent{TenantID: "org", SiteID: "site", Source: "suricata", Raw: load(t, "suricata_eve_sample.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("want 5 events, got %d", len(events))
	}
	types := map[string]int{}
	for _, e := range events {
		types[e.EventType]++
		if e.SchemaVersion != "1" {
			t.Fatalf("schema version not set")
		}
		if e.EventID == "" {
			t.Fatal("event id missing")
		}
	}
	for _, want := range []string{"alert", "dns", "http", "tls", "flow"} {
		if types[want] != 1 {
			t.Fatalf("want exactly one %s, got %d (%v)", want, types[want], types)
		}
	}
	if events[0].RuleID != "2027865" || events[0].Severity != "high" {
		t.Fatalf("alert mapping wrong: %+v", events[0])
	}
	if events[1].Hostname != "updates.demo.internal" {
		t.Fatalf("dns rrname not normalized: %+v", events[1])
	}
}

func TestNormalizeZeek(t *testing.T) {
	in := Ingestor{BatchSize: 100}
	for _, f := range []string{"zeek_conn_sample.jsonl", "zeek_dns_sample.jsonl"} {
		events, err := in.Normalize(SubjectEvent{TenantID: "org", Source: "zeek", Raw: load(t, f)})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) == 0 {
			t.Fatalf("%s: no events", f)
		}
		for _, e := range events {
			if e.Source != "zeek" || e.Timestamp.IsZero() {
				t.Fatalf("zeek normalization incomplete: %+v", e)
			}
		}
	}
}

func TestNormalizeSnort(t *testing.T) {
	in := Ingestor{BatchSize: 100}
	events, err := in.Normalize(SubjectEvent{TenantID: "org", Source: "snort", Raw: load(t, "snort_alert_sample.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 snort alerts, got %d", len(events))
	}
	if events[0].RuleName != "Attempted Telnet connection (demo)" {
		t.Fatalf("snort message not mapped: %+v", events[0])
	}
}

func TestOversizedPayloadRejected(t *testing.T) {
	in := Ingestor{}
	big := make([]byte, 9<<20)
	if _, err := in.HTTPIngestSize(big); err == nil {
		t.Fatal("oversized payload must be rejected")
	}
}

func TestUnknownSourceRejected(t *testing.T) {
	in := Ingestor{}
	if _, err := in.Normalize(SubjectEvent{Source: "not-a-sensor", Raw: []byte(`{}`)}); err == nil {
		t.Fatal("unknown sensor source must be rejected")
	}
}
