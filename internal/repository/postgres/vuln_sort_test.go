package postgres

import (
	"strings"
	"testing"
	"time"
)

// The ORDER BY whitelist is security-relevant: user input must only ever
// select between fixed literals, never reach SQL.
func TestVulnOrderClause(t *testing.T) {
	cases := []struct {
		sort, order string
		wantSub     string
	}{
		{"published_at", "desc", "v.published_at DESC NULLS LAST"},
		{"published_at", "asc", "v.published_at ASC NULLS LAST"},
		{"published_at", "", "v.published_at DESC NULLS LAST"}, // default direction per key
		{"updated_at", "asc", "v.updated_at ASC NULLS LAST"},
		{"cve_id", "asc", "v.cve_id ASC"},
		{"cve_id", "desc", "v.cve_id DESC"},
		{"cve_id", "", "v.cve_id ASC"}, // "by name" reads A→Z by default
		{"cvss_score", "desc", "cvss_score DESC"},
		{"known_exploited", "asc", "known_exploited ASC"},
	}
	for _, c := range cases {
		got := vulnOrderClause(c.sort, c.order)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("vulnOrderClause(%q, %q) = %q, want substring %q", c.sort, c.order, got, c.wantSub)
		}
	}
	// Unknown sort keys and injection attempts fall back to the default
	// relevance order — nothing user-controlled may appear in the clause.
	for _, bad := range []string{"", "DROP TABLE vulnerabilities", "published_at; --", "cvss_v3", "(SELECT 1)"} {
		got := vulnOrderClause(bad, "asc; DROP TABLE vulnerabilities")
		if got != "known_exploited DESC, cvss_score DESC" {
			t.Errorf("vulnOrderClause(%q, <inject>) = %q, want default clause", bad, got)
		}
	}
}

func TestParsePublishedBound(t *testing.T) {
	// Date-only values parse as that calendar day UTC.
	t1, ok := parsePublishedBound("2026-08-01", false)
	if !ok || t1 != time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) {
		t.Errorf("after date = %v ok=%v", t1, ok)
	}
	// The "before" bound includes the whole day it names (23:59:59).
	t2, ok := parsePublishedBound("2026-08-31", true)
	if !ok || t2 != time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC) {
		t.Errorf("before date = %v ok=%v", t2, ok)
	}
	// RFC3339 passes through verbatim.
	t3, ok := parsePublishedBound("2026-08-15T09:30:00Z", false)
	if !ok || t3.Hour() != 9 {
		t.Errorf("rfc3339 = %v ok=%v", t3, ok)
	}
	// Empty and invalid are "unset", never errors.
	if _, ok := parsePublishedBound("", false); ok {
		t.Error("empty must be unset")
	}
	if _, ok := parsePublishedBound("not-a-date", false); ok {
		t.Error("garbage must be unset")
	}
}
