package endpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// v1.23.4 guards: enrollment state (agent.json) must be read back so
// `run` works after `enroll`, and defaults must not assume Unix paths.

func TestLoadReadsStateWrittenByEnroll(t *testing.T) {
	dir := t.TempDir()
	state := map[string]any{
		"agent_id":   "agt-123",
		"server_url": "http://hub.internal:8080",
		"cert_path":  filepath.Join(dir, "agent.crt"),
		"key_path":   filepath.Join(dir, "agent.key"),
		"site_hint":  "site-9",
		"state_dir":  dir,
	}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, StateFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEGIS_STATE_DIR", dir)
	// Clear env vars that could leak host state into the test.
	t.Setenv("AEGIS_SERVER_URL", "")
	t.Setenv("AEGIS_ENROLL_TOKEN", "")

	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "agt-123" {
		t.Fatalf("agent_id = %q, want agt-123 (state ignored => run can never work after enroll)", cfg.AgentID)
	}
	if cfg.ServerURL != "http://hub.internal:8080" || cfg.SiteHint != "site-9" {
		t.Fatalf("state merge incomplete: %+v", cfg)
	}
	if cfg.StateDir != dir {
		t.Fatalf("state_dir = %q, want %q", cfg.StateDir, dir)
	}
}

func TestLoadExplicitConfigBeatsState(t *testing.T) {
	dir := t.TempDir()
	writeState := func(name string, v map[string]any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeState(StateFileName, map[string]any{"agent_id": "from-state", "state_dir": dir})
	cfgPath := filepath.Join(dir, "custom.json")
	writeState("custom.json", map[string]any{"agent_id": "from-config"})
	t.Setenv("AEGIS_STATE_DIR", dir)

	cfg, err := Load(cfgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "from-config" {
		t.Fatalf("agent_id = %q, want from-config (explicit config must win)", cfg.AgentID)
	}
}

func TestLoadKeyMaterialDefaultsInsideStateDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEGIS_STATE_DIR", dir)
	t.Setenv("AEGIS_CERT_PATH", "")
	t.Setenv("AEGIS_KEY_PATH", "")

	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertPath != filepath.Join(dir, "agent.crt") || cfg.KeyPath != filepath.Join(dir, "agent.key") {
		t.Fatalf("cert/key must default inside the state dir, got %s / %s (/etc/aegis is a Windows dead end)", cfg.CertPath, cfg.KeyPath)
	}
}

func TestDefaultStateDirPerOS(t *testing.T) {
	getenv := func(k string) string {
		if k == "ProgramData" {
			return `C:\ProgramData`
		}
		return ""
	}
	if got := defaultStateDirFor("windows", getenv, func() string { return `C:\Temp` }); got != filepath.Join(`C:\ProgramData`, "aegis-agent") {
		t.Fatalf("windows default = %q (separators follow the building OS; root must be ProgramData)", got)
	}
	if got := defaultStateDirFor("windows", func(string) string { return "" }, func() string { return `C:\Temp` }); got != filepath.Join(`C:\Temp`, "aegis-agent") {
		t.Fatalf("windows fallback = %q", got)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := defaultStateDirFor(goos, func(string) string { return "" }, nil); got != "/var/lib/aegis-agent" {
			t.Fatalf("%s default = %q, want /var/lib/aegis-agent", goos, got)
		}
	}
}
