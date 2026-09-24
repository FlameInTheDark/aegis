// HybridRole: one connector process running one or both work functions
// (agent = endpoint collection, scanner = remote scanning). Which functions
// run is decided by the connection settings toggles (`agent.enabled` /
// `scanner.enabled`, defaulting to the connection's kind), optionally
// overridden locally with `aegis-connector start --agent|--scanner`.
// Toggle flips arrive through the normal config hot-reload path and start
// or stop the affected function loop WITHOUT restarting the process.
package connectorapp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

// Function names (mirrored by the hub-side connectors.Functions).
const (
	FnAgent   = "agent"
	FnScanner = "scanner"
)

// legacyFlatKeys maps the pre-1.25 flat settings layout onto the function
// it belongs to, so existing connections keep working without rewriting
// their settings.
var legacyFlatKeys = map[string][]string{
	FnAgent: {"collection_level"},
	FnScanner: {"engine", "nmap_path", "ssh_user", "ssh_password", "ssh_key_path",
		"ssh_timeout_secs", "ssh_insecure", "ssh_pinned_key", "ssh_hosts"},
}

// sectionSettings returns the settings of one function: its dedicated
// section ("agent"/"scanner") when present, else the legacy flat keys —
// a section, when present, wins wholesale (no silent mixing).
func sectionSettings(settings map[string]any, fn string) map[string]any {
	if sec, ok := settings[fn].(map[string]any); ok {
		return sec
	}
	m := map[string]any{}
	for _, k := range legacyFlatKeys[fn] {
		if v, ok := settings[k]; ok {
			m[k] = v
		}
	}
	return m
}

// enabledFunctions computes which functions the connector should run:
// each function defaults to the connection kind's own function and an
// explicit `enabled` toggle in its section overrides the default.
// Malformed sections fall back to the kind default (a bad settings push
// must never silently stop an agent).
func enabledFunctions(kind string, settings map[string]any) []string {
	var fns []string
	for _, fn := range []string{FnAgent, FnScanner} {
		defaultOn := kind == fn
		if sec, ok := settings[fn].(map[string]any); ok {
			if e, ok := sec["enabled"].(bool); ok {
				if e {
					fns = append(fns, fn)
				}
				continue
			}
		}
		if defaultOn {
			fns = append(fns, fn)
		}
	}
	return fns
}

// functionRole builds the single-function role for fn. A package variable
// so tests can substitute fake function loops.
var functionRole = func(fn string, log *slog.Logger, cfg *LocalConfig) (Role, error) {
	switch fn {
	case FnAgent:
		return &AgentRole{log: log, started: time.Now(), cfg: cfg}, nil
	case FnScanner:
		return &ScannerRole{log: log, started: time.Now(), tools: detectScanTools(), cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown function %q", fn)
	}
}

// subRole is one running function loop with its own lifetime.
type subRole struct {
	fn     string
	role   Role
	cancel context.CancelFunc
	done   chan struct{}
}

// HybridRole implements Role for agent- and scanner-kind connections: it
// keeps the enabled function loops running, routes each function its own
// settings section and reports a merged status. With exactly one function
// enabled the status is that function's own map (byte-compatible with the
// single-role releases); with both enabled the children nest under their
// function names.
type HybridRole struct {
	log     *slog.Logger
	started time.Time
	cfg     *LocalConfig
	only    string // "" = follow settings; FnAgent/FnScanner = local CLI override

	mu       sync.Mutex
	settings map[string]any
	running  map[string]*subRole
}

func newHybridRole(kind string, log *slog.Logger, cfg *LocalConfig, only string) *HybridRole {
	if only != FnAgent && only != FnScanner {
		only = ""
	}
	return &HybridRole{
		log:     log,
		started: time.Now(),
		cfg:     cfg,
		only:    only,
		running: map[string]*subRole{},
	}
}

// Kind reports the connection kind (identity anchor on the hub).
func (r *HybridRole) Kind() string { return r.cfg.Kind }

// Capabilities is the union of the currently running functions' caps plus
// the protocol-level ones every connector advertises.
func (r *HybridRole) Capabilities() []string {
	caps := []string{"status_reporting", "config_hot_reload"}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range r.running {
		caps = append(caps, sub.role.Capabilities()...)
	}
	return caps
}

// desired functions, honoring the local CLI override over the settings.
func (r *HybridRole) desired() []string {
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	if r.only != "" {
		return []string{r.only}
	}
	return enabledFunctions(r.cfg.Kind, settings)
}

// ApplyConfig stores the settings revision, routes each function its own
// section and reconciles the running set with the newly desired one
// (toggle flips start/stop function loops live).
func (r *HybridRole) ApplyConfig(ctx context.Context, settings json.RawMessage) error {
	m := map[string]any{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &m); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	r.mu.Lock()
	r.settings = m
	want := r.desiredLocked()
	// Route section settings to every function that is running or about
	// to be; a disabled function's section is still applied if its loop
	// is winding down (harmless) — skipped otherwise.
	for _, fn := range want {
		if sub, ok := r.running[fn]; ok {
			_ = sub.role.ApplyConfig(ctx, sectionJSON(m, fn))
		}
	}
	r.mu.Unlock()
	r.reconcile(ctx)
	return nil
}

// sectionJSON marshals one function's effective settings for the child role.
func sectionJSON(settings map[string]any, fn string) json.RawMessage {
	raw, err := json.Marshal(sectionSettings(settings, fn))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// desiredLocked is desired() for callers holding r.mu.
func (r *HybridRole) desiredLocked() []string {
	if r.only != "" {
		return []string{r.only}
	}
	return enabledFunctions(r.cfg.Kind, r.settings)
}

// reconcile starts missing function loops and stops loops that are no
// longer desired. Safe to call repeatedly; blocks until stopped children
// exit (bounded) so toggle flips never leak goroutines.
func (r *HybridRole) reconcile(ctx context.Context) {
	want := r.desired()

	r.mu.Lock()
	var stops []*subRole
	for fn, sub := range r.running {
		wanted := false
		for _, w := range want {
			if w == fn {
				wanted = true
				break
			}
		}
		if !wanted {
			stops = append(stops, sub)
			delete(r.running, fn)
		}
	}
	var starts []string
	for _, fn := range want {
		if _, ok := r.running[fn]; !ok {
			starts = append(starts, fn)
		}
	}
	r.mu.Unlock()

	for _, sub := range stops {
		sub.cancel()
		select {
		case <-sub.done:
		case <-time.After(10 * time.Second):
			r.log.Warn("function loop did not stop in time", "function", sub.fn)
		}
		r.log.Info("function disabled; loop stopped", "function", sub.fn)
	}
	for _, fn := range starts {
		role, err := functionRole(fn, r.log, r.cfg)
		if err != nil {
			r.log.Error("cannot start function", "function", fn, "err", err)
			continue
		}
		_ = role.ApplyConfig(ctx, sectionJSON(r.snapshot(), fn))
		subCtx, cancel := context.WithCancel(ctx)
		sub := &subRole{fn: fn, role: role, cancel: cancel, done: make(chan struct{})}
		go func() {
			defer close(sub.done)
			if err := role.Run(subCtx, r.log); err != nil {
				r.log.Warn("function loop stopped", "function", fn, "err", err)
			}
		}()
		r.mu.Lock()
		r.running[fn] = sub
		r.mu.Unlock()
		r.log.Info("function enabled; loop started", "function", fn)
	}
}

func (r *HybridRole) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settings
}

// Run blocks until the connector session context is cancelled, keeping the
// desired function loops alive (reconcile on every config application).
func (r *HybridRole) Run(ctx context.Context, _ *slog.Logger) error {
	r.reconcile(ctx)
	<-ctx.Done()
	r.mu.Lock()
	subs := make([]*subRole, 0, len(r.running))
	for _, sub := range r.running {
		subs = append(subs, sub)
	}
	r.running = map[string]*subRole{}
	r.mu.Unlock()
	for _, sub := range subs {
		sub.cancel()
	}
	for _, sub := range subs {
		select {
		case <-sub.done:
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

// Status merges the running functions' statuses. One function reports its
// own map (compatible with single-role releases); both functions nest;
// none reports an idle marker (both toggles off is a legal "heartbeat
// only" configuration).
func (r *HybridRole) Status() map[string]any {
	want := r.desired()
	r.mu.Lock()
	order := make([]*subRole, 0, len(r.running))
	for _, fn := range []string{FnAgent, FnScanner} {
		if sub, ok := r.running[fn]; ok {
			order = append(order, sub)
		}
	}
	r.mu.Unlock()

	base := map[string]any{
		"platform":    runtime.GOOS,
		"arch":        runtime.GOARCH,
		"uptime_secs": int64(time.Since(r.started).Seconds()),
		"functions":   want,
	}
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	if len(order) == 1 {
		st := order[0].role.Status()
		st["functions"] = want
		st["settings"] = settings
		return st
	}
	base["settings"] = settings
	for _, sub := range order {
		base[sub.fn] = sub.role.Status()
	}
	if len(order) == 0 {
		base["role"] = "idle"
	} else {
		base["role"] = "hybrid"
	}
	return base
}
