package connectorapp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/scanner"
)

func testRole(settings map[string]any) *ScannerRole {
	return &ScannerRole{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: time.Now(),
		cfg:     &LocalConfig{ConnectorID: "c1", Secret: "s", Server: "127.0.0.1:9090"},
	}
}

// applySettings feeds settings through the real hot-reload path.
func applySettings(t *testing.T, r *ScannerRole, settings map[string]any) {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyConfig(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

func TestResolveEngineSimulated(t *testing.T) {
	r := testRole(nil)
	applySettings(t, r, map[string]any{"engine": "simulated"})
	eng, detail := r.resolveEngine()
	if _, ok := eng.(*scanner.SimulatedEngine); !ok {
		t.Fatalf("want SimulatedEngine, got %T", eng)
	}
	want := "engine=simulated (configured in the connection settings)"
	if detail != want {
		t.Fatalf("detail %q, want %q", detail, want)
	}
}

func TestResolveEngineNmapExplicitPath(t *testing.T) {
	r := testRole(nil)
	applySettings(t, r, map[string]any{"engine": "nmap", "nmap_path": "/opt/custom/nmap"})
	eng, detail := r.resolveEngine()
	ne, ok := eng.(*scanner.NmapEngine)
	if !ok {
		t.Fatalf("want NmapEngine, got %T", eng)
	}
	if ne.BinPath != "/opt/custom/nmap" {
		t.Fatalf("BinPath %q, want /opt/custom/nmap", ne.BinPath)
	}
	if detail != "engine=nmap (/opt/custom/nmap)" {
		t.Fatalf("detail %q", detail)
	}
}

func TestResolveEngineAutoUsesConfiguredPath(t *testing.T) {
	r := testRole(nil)
	applySettings(t, r, map[string]any{"nmap_path": "/opt/custom/nmap"})
	eng, detail := r.resolveEngine()
	ne, ok := eng.(*scanner.NmapEngine)
	if !ok {
		t.Fatalf("want NmapEngine, got %T", eng)
	}
	if ne.BinPath != "/opt/custom/nmap" {
		t.Fatalf("BinPath %q", ne.BinPath)
	}
	if detail != "engine=nmap (/opt/custom/nmap)" {
		t.Fatalf("detail %q", detail)
	}
}

// The remaining fallback cases need a host where nmap genuinely cannot be
// found; skip rather than flake on machines that have it installed.
func nmapAbsent(t *testing.T) {
	t.Helper()
	if p := scanner.DetectNmapPath(); p != "" {
		t.Skipf("nmap present at %s; fallback cases indeterminable", p)
	}
}

func TestResolveEngineNmapFallbackIsSimulated(t *testing.T) {
	nmapAbsent(t)
	r := testRole(nil)
	applySettings(t, r, map[string]any{"engine": "nmap"})
	eng, detail := r.resolveEngine()
	if _, ok := eng.(*scanner.SimulatedEngine); !ok {
		t.Fatalf("want SimulatedEngine, got %T", eng)
	}
	if detail == "" {
		t.Fatal("expected a non-empty engine_detail explaining the fallback")
	}
}

func TestResolveEngineAutoFallbackIsSimulated(t *testing.T) {
	nmapAbsent(t)
	r := testRole(nil)
	applySettings(t, r, map[string]any{})
	eng, detail := r.resolveEngine()
	if _, ok := eng.(*scanner.SimulatedEngine); !ok {
		t.Fatalf("want SimulatedEngine, got %T", eng)
	}
	if detail == "" {
		t.Fatal("expected a non-empty engine_detail explaining the fallback")
	}
}

func TestDetectNmapPathFindsBinaryOnPATH(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "nmap")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got := scanner.DetectNmapPath(); got != bin {
		t.Fatalf("DetectNmapPath()=%q, want %q", got, bin)
	}
}

func TestScannerRoleStatusCarriesEngineDetail(t *testing.T) {
	nmapAbsent(t)
	r := testRole(nil)
	applySettings(t, r, map[string]any{})
	st := r.Status()
	if st["engine_detail"] == "" || st["engine_detail"] == nil {
		t.Fatalf("status missing engine_detail: %v", st)
	}
	if st["version"] != Version {
		t.Fatalf("status version %v, want %q", st["version"], Version)
	}
}

// v1.24.0: the agent kind is a real endpoint role now (no separate agent
// binary). These guards pin the config mapping that feeds internal/endpoint.

func newAgentRole(cfg *LocalConfig, settings map[string]any) *AgentRole {
	r := &AgentRole{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: time.Now(),
		cfg:     cfg,
	}
	raw, _ := json.Marshal(settings)
	_ = r.ApplyConfig(context.Background(), raw)
	return r
}

func TestAgentRoleEndpointConfigMapping(t *testing.T) {
	cfg := &LocalConfig{
		Server: "hub.example.com:9090", TLS: true,
		ConnectorID: "conn-9", Secret: "sec",
		ConfigPath: "/etc/aegis-connector/config.json",
	}
	r := newAgentRole(cfg, map[string]any{"collection_level": "standard"})
	ecfg := r.endpointConfig()
	if ecfg.ServerURL != "https://hub.example.com:9090" {
		t.Fatalf("ServerURL = %q, want https mapping of the connector endpoint", ecfg.ServerURL)
	}
	if ecfg.ConnectorID != "conn-9" || ecfg.ConnectorSecret != "sec" {
		t.Fatalf("connector credentials must flow into the endpoint config: %+v", ecfg)
	}
	if ecfg.CollectionLevel != "standard" {
		t.Fatalf("collection_level from connection settings ignored: %q", ecfg.CollectionLevel)
	}
	if ecfg.StateDir != "/etc/aegis-connector/endpoint" {
		t.Fatalf("device state must live next to the connector config, got %q", ecfg.StateDir)
	}
	if ecfg.CertPath != "/etc/aegis-connector/endpoint/agent.crt" || ecfg.KeyPath != "/etc/aegis-connector/endpoint/agent.key" {
		t.Fatalf("key material paths wrong: %s / %s", ecfg.CertPath, ecfg.KeyPath)
	}
}

func TestAgentRoleStatusAndCapabilities(t *testing.T) {
	cfg := &LocalConfig{Server: "h:9090", ConnectorID: "c", Secret: "s"}
	r := newAgentRole(cfg, nil)
	caps := r.Capabilities()
	for _, want := range []string{"basic_inventory", "software_inventory", "network_inventory", "security_posture"} {
		found := false
		for _, c := range caps {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("capability %q missing from agent role: %v", want, caps)
		}
	}
	st := r.Status()
	if st["role"] != "agent" || st["hostname"] == "" || st["platform"] == "" {
		t.Fatalf("agent status incomplete: %v", st)
	}
	if _, has := st["device_id"]; has {
		t.Fatal("device_id must be absent before the first successful bind")
	}
}

// The agent function's metrics cadence must flow from the settings section
// into the endpoint runtime config; absent keys must leave 0 (the endpoint
// runtime substitutes its defaults — a partial push never disables
// collection) and malformed keys must be ignored.
func TestAgentRoleEndpointConfigCarriesRates(t *testing.T) {
	r := &AgentRole{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: time.Now(),
		cfg:     &LocalConfig{ConnectorID: "c1", Secret: "s", Server: "127.0.0.1:9090"},
	}
	r.ApplyConfig(context.Background(), json.RawMessage(`{"collection_level":"standard","probe_rate_ms":250,"pull_rate_ms":60000}`))
	ecfg := r.endpointConfig()
	if ecfg.ProbeRateMs != 250 || ecfg.PullRateMs != 60000 {
		t.Fatalf("rates not carried: probe=%d pull=%d", ecfg.ProbeRateMs, ecfg.PullRateMs)
	}
	if ecfg.CollectionLevel != "standard" {
		t.Fatalf("collection level changed: %q", ecfg.CollectionLevel)
	}

	// Absent keys -> zeros (defaults are applied by the endpoint runtime).
	r.ApplyConfig(context.Background(), json.RawMessage(`{}`))
	ecfg = r.endpointConfig()
	if ecfg.ProbeRateMs != 0 || ecfg.PullRateMs != 0 {
		t.Fatalf("absent rate keys must yield zeros, got probe=%d pull=%d", ecfg.ProbeRateMs, ecfg.PullRateMs)
	}

	// Malformed keys are ignored, not zero-forcing or panicking.
	r.ApplyConfig(context.Background(), json.RawMessage(`{"probe_rate_ms":"fast","pull_rate_ms":-5}`))
	ecfg = r.endpointConfig()
	if ecfg.ProbeRateMs != 0 || ecfg.PullRateMs != 0 {
		t.Fatalf("malformed rate keys must yield zeros, got probe=%d pull=%d", ecfg.ProbeRateMs, ecfg.PullRateMs)
	}
}

// A settings push with no running endpoint loop must be a no-op (the rates
// apply when the loop starts); with rates unchanged nothing may panic.
func TestAgentRoleApplyConfigWithoutRuntimeIsNoop(t *testing.T) {
	r := &AgentRole{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: time.Now(),
		cfg:     &LocalConfig{ConnectorID: "c1", Secret: "s", Server: "127.0.0.1:9090"},
	}
	if err := r.ApplyConfig(context.Background(), json.RawMessage(`{"probe_rate_ms":100,"pull_rate_ms":1000}`)); err != nil {
		t.Fatalf("ApplyConfig without a running runtime must succeed: %v", err)
	}
}
