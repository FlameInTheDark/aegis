package httpx

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Unit tests for the v1.13.0 handler-layer validation helpers (asset-group
// request shaping and detection-match triage states). The full CRUD flows
// are covered by the e2e suite against a live Postgres; these pin the
// request-level contract that must not drift.

func TestSanitizeGroupKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"  Emerald ", "emerald"},
		{"INDIGO", "indigo"},
		{"boxes", "boxes"},
		{string(make([]byte, 0)), ""},
	}
	for _, c := range cases {
		if got := sanitizeGroupKey(c.in); got != c.want {
			t.Errorf("sanitizeGroupKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := make([]byte, 40)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeGroupKey(string(long)); len(got) != 32 {
		t.Errorf("long key not capped: len=%d", len(got))
	}
}

func TestGroupKinds(t *testing.T) {
	for _, k := range []domain.AssetGroupKind{domain.GroupKindLocation, domain.GroupKindFunction, domain.GroupKindOwner, domain.GroupKindCustom} {
		if !groupKinds[k] {
			t.Errorf("groupKinds missing %q", k)
		}
	}
	if groupKinds[domain.AssetGroupKind("galaxy")] {
		t.Error("unknown kind must not validate")
	}
}

func TestValidMatchStatus(t *testing.T) {
	for _, s := range []string{"new", "investigating", "contained", "closed"} {
		if !domain.ValidMatchStatus(s) {
			t.Errorf("ValidMatchStatus(%q) = false", s)
		}
	}
	for _, s := range []string{"", "open", "NEW", "deleted"} {
		if domain.ValidMatchStatus(s) {
			t.Errorf("ValidMatchStatus(%q) = true, want false", s)
		}
	}
}
