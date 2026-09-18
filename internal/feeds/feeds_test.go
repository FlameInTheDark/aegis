package feeds

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestNVDState(t *testing.T) {
	tests := map[string]domain.CVEState{
		"Analyzed":            domain.CVEStatePublished,
		"Modified":            domain.CVEStatePublished,
		"Undergoing Analysis": domain.CVEStatePublished,
		"Rejected":            domain.CVEStateRejected,
	}
	for status, want := range tests {
		if got := nvdState(status); got != want {
			t.Errorf("nvdState(%q) = %q, want %q", status, got, want)
		}
	}
}
