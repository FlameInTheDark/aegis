// Package endpoint implements the endpoint agent runtime :
// one small Go binary for Windows/Linux/macOS that collects inventory and
// executes ONLY typed tasks. It never collects credentials, never runs
// arbitrary commands from the server, and buffers offline.
package endpoint

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Config is the agent's local configuration. Identity is owned by the
// connector: the device record binds 1:1 to an agent-kind connector and
// every data-plane call carries the connector credentials as metadata.
type Config struct {
	ServerURL       string   `json:"server_url"` // control plane base URL
	ConnectorID     string   `json:"connector_id,omitempty"`
	ConnectorSecret string   `json:"connector_secret,omitempty"` // never persisted in the device state file
	AgentID         string   `json:"agent_id,omitempty"`
	CertPath        string   `json:"cert_path,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	SiteHint        string   `json:"site_hint,omitempty"`
	Capabilities    []string `json:"capabilities"`
	CollectionLevel string   `json:"collection_level"` // basic|standard|full
	HeartbeatSecs   int      `json:"heartbeat_secs"`
	// Metrics cadence: ProbeRateMs is how often a performance sample is
	// taken from the system; PullRateMs is how often buffered samples are
	// flushed to the hub in ONE batched call. Configurable per connection
	// (agent.probe_rate_ms / agent.pull_rate_ms); defaults below.
	ProbeRateMs  int    `json:"probe_rate_ms"`
	PullRateMs   int    `json:"pull_rate_ms"`
	StateDir     string `json:"state_dir"`
	MaxOfflineMB int    `json:"max_offline_mb"`
}

// StateFileName is the state file `enroll` writes and every later `run`
// reads back. Before v1.23.4 nothing ever read this file, so even a
// successful enrollment could not make `run` work on a fresh shell.
const StateFileName = "agent.json"

// Metrics cadence bounds and defaults. The probe floor of 100ms keeps the
// sampling CPU cost negligible on every platform; an hour is the ceiling
// for both rates (anything slower is a misconfiguration, not telemetry).
// A pull faster than the probe can never carry data and is clamped up.
const (
	DefaultProbeRateMs = 5000
	DefaultPullRateMs  = 30000
	MinRateMs          = 100
	MaxRateMs          = 3600000
)

// normalizeMetricsRates clamps the metrics cadence into the bounds above.
// Zero or negative values fall back to the defaults, so a partial config
// (or a settings push that omits the keys) can never disable collection.
func (c *Config) normalizeMetricsRates() {
	c.ProbeRateMs = clampRateMs(c.ProbeRateMs, DefaultProbeRateMs)
	c.PullRateMs = clampRateMs(c.PullRateMs, DefaultPullRateMs)
	if c.PullRateMs < c.ProbeRateMs {
		c.PullRateMs = c.ProbeRateMs
	}
}

func clampRateMs(v, def int) int {
	switch {
	case v <= 0:
		return def
	case v < MinRateMs:
		return MinRateMs
	case v > MaxRateMs:
		return MaxRateMs
	default:
		return v
	}
}

// Load resolves the agent configuration. Priority (lowest first):
// built-in defaults < AEGIS_* environment < state file (agent.json written
// by a previous enroll) < explicit config file < command-line flags.
// stateDirOverride is the --state-dir flag; when empty the AEGIS_STATE_DIR
// env var applies, then the per-OS default.
func Load(path, stateDirOverride string) (*Config, error) {
	stateDir := stateDirOverride
	if stateDir == "" {
		stateDir = os.Getenv("AEGIS_STATE_DIR")
	}
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	cfg := &Config{
		ServerURL:       envOr("AEGIS_SERVER_URL", "http://localhost:8080"),
		ConnectorID:     os.Getenv("AEGIS_CONNECTOR_ID"),
		ConnectorSecret: os.Getenv("AEGIS_CONNECTOR_SECRET"),
		CollectionLevel: envOr("AEGIS_COLLECTION_LEVEL", "basic"),
		HeartbeatSecs:   30,
		ProbeRateMs:     envIntOr("AEGIS_PROBE_RATE_MS", DefaultProbeRateMs),
		PullRateMs:      envIntOr("AEGIS_PULL_RATE_MS", DefaultPullRateMs),
		StateDir:        stateDir,
		MaxOfflineMB:    16,
		Capabilities:    []string{"basic_inventory", "software_inventory", "network_inventory", "security_posture"},
	}
	// Key material defaults INSIDE the state directory: /etc/aegis was
	// meaningless on Windows (and the user-visible enrollment there died
	// before even reaching the server).
	cfg.CertPath = envOr("AEGIS_CERT_PATH", filepath.Join(stateDir, "agent.crt"))
	cfg.KeyPath = envOr("AEGIS_KEY_PATH", filepath.Join(stateDir, "agent.key"))

	// State from a previous `enroll` (agent_id, server_url, paths).
	_ = readJSON(filepath.Join(stateDir, StateFileName), cfg)
	// Explicit config file wins over state when provided.
	if path != "" {
		_ = readJSON(path, cfg)
	}
	if cfg.HeartbeatSecs < 10 {
		cfg.HeartbeatSecs = 10
	}
	cfg.normalizeMetricsRates()
	return cfg, nil
}

// defaultStateDir picks the per-OS state directory. Windows cannot use
// /var/lib (the v1.23.3 default broke every flag-less run there).
func defaultStateDir() string {
	return defaultStateDirFor(runtime.GOOS, os.Getenv, os.TempDir)
}

// defaultStateDirFor is the testable core of defaultStateDir.
func defaultStateDirFor(goos string, getenv func(string) string, tempDir func() string) string {
	switch goos {
	case "windows":
		if pd := getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "aegis-agent")
		}
		return filepath.Join(tempDir(), "aegis-agent")
	default:
		// Linux and macOS (macOS enrollment runs under sudo per the hub UI).
		return "/var/lib/aegis-agent"
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envIntOr reads an integer environment override; malformed values fall
// back to the default instead of failing the load.
func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Platform returns the runtime platform identifier.
func Platform() string { return runtime.GOOS }

// AgentVersion is the agent binary version, stamped at build time via
// -ldflags "-X github.com/FlameInTheDark/aegis/internal/endpoint.AgentVersion=$(cat VERSION)".
// A plain `go build` leaves "dev".
var AgentVersion = "dev"

// Validate checks the config for obviously unsafe values.
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	if len(c.ServerURL) > 512 {
		return fmt.Errorf("server_url too long")
	}
	if c.StateDir == "" {
		return fmt.Errorf("state_dir is required")
	}
	if c.KeyPath == "" {
		return fmt.Errorf("key_path is required (private key is persisted locally)")
	}
	return nil
}
