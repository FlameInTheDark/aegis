package feeds

import (
	"testing"
	"time"
)

// NVD returns zone-less ISO timestamps ("2023-10-11T19:15:09.947"). RFC3339
// alone silently nulled every published_at/updated_at in the corpus.
func TestParseNVDTime(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2023-10-11T19:15:09.947", true},  // NVD zone-less with millis
		{"2023-10-11T19:15:09", true},      // NVD zone-less without millis
		{"2023-10-11T19:15:09.947Z", true}, // RFC3339
		{"2023-10-11T19:15:09+00:00", true},
		{"", false},
		{"not-a-time", false},
	}
	for _, tc := range cases {
		got := parseNVDTime(tc.in)
		if (got != nil) != tc.want {
			t.Errorf("parseNVDTime(%q) = %v, want presence=%v", tc.in, got, tc.want)
		}
	}
}

// The incremental window must query-escape the '+' in "+00:00" — a raw '+'
// in a query string parses as a space and NVD rejects the request. The
// window is empty (full pull) when no previous sync position exists.
func TestNVDWindow(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	q := nvdWindow(time.Time{}, now)
	if len(q) != 0 {
		t.Errorf("zero lastSync must produce a full pull, got %v", q)
	}

	last := now.Add(-6 * time.Hour)
	q = nvdWindow(last, now)
	start := q.Get("lastModStartDate")
	end := q.Get("lastModEndDate")
	if start == "" || end == "" {
		t.Fatalf("incremental window missing: %v", q)
	}
	if encoded := q.Encode(); !contains(encoded, "lastModStartDate=") || containsStr(encoded, "+") {
		t.Errorf("'+' must be percent-encoded in the query: %s", encoded)
	}
	// The overlap pushes the start back 2h from the sync position.
	wantStart := last.UTC().Add(-2 * time.Hour).Format("2006-01-02T15:04:05.000-07:00")
	if start != wantStart {
		t.Errorf("lastModStartDate = %q, want %q", start, wantStart)
	}
	wantEnd := now.UTC().Add(time.Minute).Format("2006-01-02T15:04:05.000-07:00")
	if end != wantEnd {
		t.Errorf("lastModEndDate = %q, want %q", end, wantEnd)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func containsStr(s, sub string) bool { return indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
