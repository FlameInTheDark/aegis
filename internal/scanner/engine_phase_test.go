package scanner

import (
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// One global 30s budget aborted nmap -O (which runs its own port scan first)
// before any probe round completed — the reported "no OS data in the app".
func TestPhaseTimeouts(t *testing.T) {
	// Auto mode (TimeoutSecs 0): per-phase defaults apply.
	cfg := &domain.ScanConfig{TimeoutSecs: 0}
	if got := phaseTimeout(cfg, 5*time.Minute); got != 5*time.Minute {
		t.Errorf("OS phase default = %s, want 5m", got)
	}
	if got := phaseTimeout(cfg, 90*time.Second); got != 90*time.Second {
		t.Errorf("service phase default = %s, want 90s", got)
	}
	// An explicit config acts as a floor, never as a strangle: 30s must not
	// shorten the 5-minute OS budget...
	cfg = &domain.ScanConfig{TimeoutSecs: 30}
	if got := phaseTimeout(cfg, 5*time.Minute); got != 5*time.Minute {
		t.Errorf("OS phase with 30s config = %s, want 5m", got)
	}
	// ...but a larger explicit value extends the budget.
	cfg = &domain.ScanConfig{TimeoutSecs: 600}
	if got := phaseTimeout(cfg, 5*time.Minute); got != 10*time.Minute {
		t.Errorf("OS phase with 600s config = %s, want 10m", got)
	}
	if got := phaseTimeout(nil, time.Minute); got != time.Minute {
		t.Errorf("nil config = %s, want 1m", got)
	}
}

func TestPortCountFor(t *testing.T) {
	if got := portCountFor([]int{22, 80}, nil); got != 2 {
		t.Errorf("explicit ports = %d, want 2", got)
	}
	if got := portCountFor(nil, &domain.ScanConfig{FullTCPPorts: true}); got != 65535 {
		t.Errorf("full range = %d, want 65535", got)
	}
	if got := portCountFor(nil, &domain.ScanConfig{TopTCPPorts: 1000}); got != 1000 {
		t.Errorf("top ports = %d, want 1000", got)
	}
	if got := portCountFor(nil, nil); got != 100 {
		t.Errorf("default = %d, want 100", got)
	}
}
