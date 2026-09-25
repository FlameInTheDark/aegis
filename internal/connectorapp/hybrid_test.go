package connectorapp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// v1.25.0 hybrid guards: one connector process runs one or both work
// functions (agent = endpoint collection, scanner = remote scanning),
// driven by the connection settings toggles with CLI overrides on top.

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// --- enabledFunctions / sectionSettings -----------------------------------

func TestEnabledFunctionsDefaultsFollowKind(t *testing.T) {
	cases := []struct {
		kind string
		want []string
	}{
		{"agent", []string{"agent"}},
		{"scanner", []string{"scanner"}},
		{"collector", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := enabledFunctions(tc.kind, nil)
		if len(got) != len(tc.want) {
			t.Fatalf("kind %q: got %v, want %v", tc.kind, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("kind %q: got %v, want %v", tc.kind, got, tc.want)
			}
		}
	}
}

func TestEnabledFunctionsTogglesOverrideKind(t *testing.T) {
	// agent kind with scanner toggled on -> hybrid
	got := enabledFunctions("agent", map[string]any{
		"scanner": map[string]any{"enabled": true},
	})
	if len(got) != 2 || got[0] != "agent" || got[1] != "scanner" {
		t.Fatalf("agent kind + scanner toggle must run both, got %v", got)
	}
	// agent kind with agent explicitly disabled -> nothing runs
	got = enabledFunctions("agent", map[string]any{
		"agent": map[string]any{"enabled": false},
	})
	if len(got) != 0 {
		t.Fatalf("disabled agent function must stop the loop, got %v", got)
	}
	// scanner kind with scanner disabled but agent on -> swapped
	got = enabledFunctions("scanner", map[string]any{
		"scanner": map[string]any{"enabled": false},
		"agent":   map[string]any{"enabled": true},
	})
	if len(got) != 1 || got[0] != "agent" {
		t.Fatalf("swapped toggles must swap functions, got %v", got)
	}
}

func TestEnabledFunctionsMalformedSectionFallsBackToKind(t *testing.T) {
	// a bad settings push must never silently stop an agent
	got := enabledFunctions("agent", map[string]any{"agent": "not-a-map"})
	if len(got) != 1 || got[0] != "agent" {
		t.Fatalf("malformed section must fall back to the kind default, got %v", got)
	}
}

func TestSectionSettingsSectionWinsOverLegacyFlat(t *testing.T) {
	settings := map[string]any{
		"collection_level": "basic", // legacy flat
		"agent":            map[string]any{"collection_level": "full"},
	}
	got := sectionSettings(settings, "agent")
	if got["collection_level"] != "full" {
		t.Fatalf("section must win wholesale over legacy flat keys, got %v", got)
	}
}

func TestSectionSettingsLegacyFlatFallback(t *testing.T) {
	settings := map[string]any{
		"engine":         "simulated",
		"nmap_path":      "/opt/nmap",
		"ssh_user":       "scan",
		"unknown_key":    "dropped",
		"heartbeat_secs": 30,
	}
	got := sectionSettings(settings, "scanner")
	if got["engine"] != "simulated" || got["nmap_path"] != "/opt/nmap" || got["ssh_user"] != "scan" {
		t.Fatalf("legacy flat keys must map onto the scanner function: %v", got)
	}
	if _, ok := got["unknown_key"]; ok {
		t.Fatal("unknown keys must not leak into function sections")
	}
	if _, ok := got["heartbeat_secs"]; ok {
		t.Fatal("heartbeat_secs is protocol-level, not a function setting")
	}
	// agent section: only collection_level is legacy
	got = sectionSettings(settings, "agent")
	if len(got) != 0 {
		t.Fatalf("no legacy agent keys in these settings, got %v", got)
	}
}

// --- HybridRole ------------------------------------------------------------

// fakeFnRole records ApplyConfig payloads and exposes a controllable Run.
type fakeFnRole struct {
	fn       string
	mu       sync.Mutex
	applied  []map[string]any
	stopFunc context.CancelFunc
	stopped  chan struct{}
}

func (f *fakeFnRole) Kind() string { return f.fn }
func (f *fakeFnRole) Capabilities() []string {
	return []string{"cap_" + f.fn}
}
func (f *fakeFnRole) ApplyConfig(_ context.Context, settings json.RawMessage) error {
	m := map[string]any{}
	_ = json.Unmarshal(settings, &m)
	f.mu.Lock()
	f.applied = append(f.applied, m)
	f.mu.Unlock()
	return nil
}
func (f *fakeFnRole) Run(ctx context.Context, _ *slog.Logger) error {
	<-ctx.Done()
	if f.stopFunc != nil {
		f.stopFunc()
	}
	return nil
}
func (f *fakeFnRole) Status() map[string]any { return map[string]any{"role": f.fn} }

func newFakeFn(t *testing.T, fn string) *fakeFnRole {
	t.Helper()
	f := &fakeFnRole{fn: fn, stopped: make(chan struct{})}
	_, cancel := context.WithCancel(context.Background())
	var once sync.Once
	f.stopFunc = func() {
		once.Do(func() {
			cancel()
			close(f.stopped)
		})
	}
	t.Cleanup(f.stopFunc)
	return f
}

func hybridWithFakes(t *testing.T, cfg *LocalConfig, fakes ...*fakeFnRole) *HybridRole {
	t.Helper()
	r := newHybridRole(cfg.Kind, testLogger(), cfg, "")
	restore := setFunctionRole(func(fn string, _ *slog.Logger, _ *LocalConfig) (Role, error) {
		for _, f := range fakes {
			if f.fn == fn {
				return f, nil
			}
		}
		return nil, nil // caller treats nil carefully; tests only request fakes
	})
	t.Cleanup(restore)
	return r
}

func applyHybrid(t *testing.T, r *HybridRole, settings map[string]any) {
	t.Helper()
	if err := r.ApplyConfig(context.Background(), mustRaw(t, settings)); err != nil {
		t.Fatal(err)
	}
}

func runningFns(r *HybridRole) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.running))
	for _, fn := range []string{FnAgent, FnScanner} {
		if _, ok := r.running[fn]; ok {
			out = append(out, fn)
		}
	}
	return out
}

func TestHybridRoleRunsKindDefaultOnly(t *testing.T) {
	agent := newFakeFn(t, FnAgent)
	scanner := newFakeFn(t, FnScanner)
	r := hybridWithFakes(t, &LocalConfig{Kind: "agent", ConnectorID: "c", Secret: "s"}, agent, scanner)
	go func() { _ = r.Run(context.Background(), testLogger()) }()
	applyHybrid(t, r, map[string]any{})
	defer func() {
		r.mu.Lock()
		subs := r.running
		r.running = map[string]*subRole{}
		r.mu.Unlock()
		for _, s := range subs {
			s.cancel()
		}
	}()

	waitFns(t, r, []string{"agent"})
	if fns := runningFns(r); len(fns) != 1 || fns[0] != "agent" {
		t.Fatalf("agent kind must run only the agent function by default, got %v", fns)
	}
	_ = scanner
}

func TestHybridRoleToggleFlipStartsAndStopsLive(t *testing.T) {
	agent := newFakeFn(t, FnAgent)
	scanner := newFakeFn(t, FnScanner)
	r := hybridWithFakes(t, &LocalConfig{Kind: "agent", ConnectorID: "c", Secret: "s"}, agent, scanner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, testLogger()) }()
	applyHybrid(t, r, map[string]any{})
	waitFns(t, r, []string{"agent"})

	// Toggle scanner ON: starts live, no restart of the agent loop.
	applyHybrid(t, r, map[string]any{"scanner": map[string]any{"enabled": true}})
	waitFns(t, r, []string{"agent", "scanner"})

	// Toggle scanner OFF again: its loop stops, agent keeps running.
	applyHybrid(t, r, map[string]any{"scanner": map[string]any{"enabled": false}})
	waitFns(t, r, []string{"agent"})
	select {
	case <-scanner.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner function loop was not stopped after the toggle flip")
	}
}

func TestHybridRoleRoutesSettingsSections(t *testing.T) {
	agent := newFakeFn(t, FnAgent)
	scanner := newFakeFn(t, FnScanner)
	r := hybridWithFakes(t, &LocalConfig{Kind: "agent", ConnectorID: "c", Secret: "s"}, agent, scanner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, testLogger()) }()
	defer func() {
		r.mu.Lock()
		subs := r.running
		r.running = map[string]*subRole{}
		r.mu.Unlock()
		for _, s := range subs {
			s.cancel()
		}
	}()

	applyHybrid(t, r, map[string]any{
		"agent":   map[string]any{"enabled": true, "collection_level": "full"},
		"scanner": map[string]any{"enabled": true, "engine": "simulated"},
	})
	waitFns(t, r, []string{"agent", "scanner"})

	agent.mu.Lock()
	lastAgent := agent.applied[len(agent.applied)-1]
	agent.mu.Unlock()
	if lastAgent["collection_level"] != "full" {
		t.Fatalf("agent function must receive its section settings, got %v", lastAgent)
	}
	if _, ok := lastAgent["engine"]; ok {
		t.Fatalf("agent function must not receive scanner settings, got %v", lastAgent)
	}
	scanner.mu.Lock()
	lastScanner := scanner.applied[len(scanner.applied)-1]
	scanner.mu.Unlock()
	if lastScanner["engine"] != "simulated" {
		t.Fatalf("scanner function must receive its section settings, got %v", lastScanner)
	}
	if _, ok := lastScanner["collection_level"]; ok {
		t.Fatalf("scanner function must not receive agent settings, got %v", lastScanner)
	}
}

func TestHybridRoleStatusShapes(t *testing.T) {
	agent := newFakeFn(t, FnAgent)
	scanner := newFakeFn(t, FnScanner)
	r := hybridWithFakes(t, &LocalConfig{Kind: "agent", ConnectorID: "c", Secret: "s"}, agent, scanner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, testLogger()) }()
	defer func() {
		r.mu.Lock()
		subs := r.running
		r.running = map[string]*subRole{}
		r.mu.Unlock()
		for _, s := range subs {
			s.cancel()
		}
	}()

	// Single function: byte-compatible single-role shape.
	applyHybrid(t, r, map[string]any{})
	waitFns(t, r, []string{"agent"})
	st := r.Status()
	if st["role"] != "agent" {
		t.Fatalf("single-function status must keep the child role name, got %v", st)
	}
	if fns, ok := st["functions"].([]string); !ok || len(fns) != 1 || fns[0] != "agent" {
		t.Fatalf("status must list enabled functions, got %v", st["functions"])
	}

	// Both functions: nested under function names.
	applyHybrid(t, r, map[string]any{"scanner": map[string]any{"enabled": true}})
	waitFns(t, r, []string{"agent", "scanner"})
	st = r.Status()
	if st["role"] != "hybrid" {
		t.Fatalf("dual-function status must be hybrid, got %v", st)
	}
	nested, ok := st["agent"].(map[string]any)
	if !ok || nested["role"] != "agent" {
		t.Fatalf("agent child status must nest under the agent key, got %v", st["agent"])
	}
	nested, ok = st["scanner"].(map[string]any)
	if !ok || nested["role"] != "scanner" {
		t.Fatalf("scanner child status must nest under the scanner key, got %v", st["scanner"])
	}

	// Both toggles off: idle marker, no fabricated child data.
	applyHybrid(t, r, map[string]any{"agent": map[string]any{"enabled": false}, "scanner": map[string]any{"enabled": false}})
	waitFns(t, r, nil)
	st = r.Status()
	if st["role"] != "idle" {
		t.Fatalf("no-function status must be idle, got %v", st)
	}
}

func TestHybridRoleCLIOverrideBeatsSettings(t *testing.T) {
	agent := newFakeFn(t, FnAgent)
	scanner := newFakeFn(t, FnScanner)
	r := newHybridRole("scanner", testLogger(), &LocalConfig{Kind: "scanner", ConnectorID: "c", Secret: "s"}, FnAgent)
	restore := setFunctionRole(func(fn string, _ *slog.Logger, _ *LocalConfig) (Role, error) {
		if fn == FnAgent {
			return agent, nil
		}
		return scanner, nil
	})
	t.Cleanup(restore)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, testLogger()) }()
	defer func() {
		r.mu.Lock()
		subs := r.running
		r.running = map[string]*subRole{}
		r.mu.Unlock()
		for _, s := range subs {
			s.cancel()
		}
	}()

	// Settings say scanner-only; the CLI override forces agent.
	applyHybrid(t, r, map[string]any{})
	waitFns(t, r, []string{"agent"})
	if fns := runningFns(r); len(fns) != 1 || fns[0] != "agent" {
		t.Fatalf("CLI override must pin the function set, got %v", fns)
	}
}

func waitFns(t *testing.T, r *HybridRole, want []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := runningFns(r)
		if len(got) == len(want) {
			match := true
			for i := range got {
				if got[i] != want[i] {
					match = false
				}
			}
			if match {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("running functions never converged to %v, have %v", want, runningFns(r))
}
