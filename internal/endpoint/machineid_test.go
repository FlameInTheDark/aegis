package endpoint

import (
	"strings"
	"testing"
)

func TestDiscoverMachineIDEnvOverrideWins(t *testing.T) {
	t.Setenv("AEGIS_MACHINE_ID", "explicit-id-42")
	if got := discoverMachineID(); got != "explicit-id-42" {
		t.Fatalf("env override ignored: got %q", got)
	}
}

func TestMachineIDNeverEmpty(t *testing.T) {
	// Whatever the platform (files missing, reg/ioreg absent), the
	// enrollment request must carry a non-empty machine_id — the field was
	// silently empty until v1.23.4.
	if got := machineID(); strings.TrimSpace(got) == "" {
		t.Fatal("machineID() returned empty")
	}
}

func TestDiscoverMachineIDFallbackIsDeterministic(t *testing.T) {
	t.Setenv("AEGIS_MACHINE_ID", "")
	a := discoverMachineID()
	b := discoverMachineID()
	if a == "" || a != b {
		t.Fatalf("fallback must be deterministic and non-empty: %q vs %q", a, b)
	}
}
