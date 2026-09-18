// Package observability exposes /healthz, /readyz, /metrics and optional
// OpenTelemetry tracing for every service (spec §49, §81).
package observability

import (
	"context"
	"sync"
	"time"
)

// DependencyHealth is one named dependency check result.
type DependencyHealth struct {
	Name      string `json:"name"`
	Status    string `json:"status"` // ok | degraded | down
	Detail    string `json:"detail,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
}

// Checker is implemented by storage/messaging layers to report readiness.
type Checker interface {
	CheckHealth(ctx context.Context) DependencyHealth
}

// HealthRegistry aggregates dependency checkers.
type HealthRegistry struct {
	mu   sync.Mutex
	deps []Checker
}

func NewHealthRegistry() *HealthRegistry { return &HealthRegistry{} }

// Register adds a dependency checker.
func (h *HealthRegistry) Register(c Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deps = append(h.deps, c)
}

// Check runs all dependency checks. Critical=true means the service is not
// functional without it (readiness fails); non-critical degrade only.
func (h *HealthRegistry) Check(ctx context.Context, critical map[string]bool) (ready bool, deps []DependencyHealth) {
	h.mu.Lock()
	depsList := append([]Checker{}, h.deps...)
	h.mu.Unlock()
	ready = true
	for _, d := range depsList {
		dh := d.CheckHealth(ctx)
		deps = append(deps, dh)
		if critical[dh.Name] && dh.Status != "ok" {
			ready = false
		}
	}
	return ready, deps
}

// UptimeTracker reports process liveness.
type UptimeTracker struct{ Start time.Time }

func NewUptimeTracker() *UptimeTracker         { return &UptimeTracker{Start: time.Now()} }
func (u *UptimeTracker) Uptime() time.Duration { return time.Since(u.Start) }
