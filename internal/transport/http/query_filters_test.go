package httpx

import (
	"testing"

	"github.com/google/uuid"
)

// The changes listing 500'd when the console's "All sites" option sent the
// scope sentinel verbatim (GET /changes?site_id=all): the raw string went
// into a uuid equality and PostgreSQL rejected the cast. These tests pin
// the shared contract for every list endpoint that takes an optional UUID
// filter: empty and "all" mean unfiltered, a real UUID passes through, and
// anything else is a 400 — never a 500 from the database layer.
func TestUUIDFilterParam(t *testing.T) {
	id := "7b0d4bd5-0a33-4f8e-9d21-4a6b1f2ce9a4"
	cases := []struct {
		raw    string
		want   string
		wantNo bool // want a 400 error instead of a value
	}{
		{raw: "", want: ""},
		{raw: "all", want: ""},
		{raw: id, want: id},
		{raw: "ALL", wantNo: true},
		{raw: "garbage", wantNo: true},
		// 32-hex without dashes: uuid.Validate accepts it and PostgreSQL's
		// uuid input parses it, so it passes through instead of erroring.
		{raw: "7b0d4bd50a334f8e9d214a6b1f2ce9a4", want: "7b0d4bd50a334f8e9d214a6b1f2ce9a4"},
		{raw: id + "x", wantNo: true},
	}
	for _, tc := range cases {
		got, err := uuidFilterParam(tc.raw)
		if tc.wantNo {
			if err == nil {
				t.Fatalf("uuidFilterParam(%q) = %q, want a 400", tc.raw, got)
			}
			he, ok := err.(*HTTPError)
			if !ok {
				t.Fatalf("uuidFilterParam(%q) error = %T, want *HTTPError", tc.raw, err)
			}
			if he.Status != 400 {
				t.Fatalf("uuidFilterParam(%q) status = %d, want 400", tc.raw, he.Status)
			}
			continue
		}
		if err != nil {
			t.Fatalf("uuidFilterParam(%q) = error %v, want %q", tc.raw, err, tc.want)
		}
		if got != tc.want {
			t.Fatalf("uuidFilterParam(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if got != "" {
			if _, err := uuid.Parse(got); err != nil {
				t.Fatalf("uuidFilterParam(%q) returned %q which is not a UUID", tc.raw, got)
			}
		}
	}
}
