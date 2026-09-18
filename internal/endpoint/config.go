// Package endpoint implements the endpoint agent runtime (spec §16-§20):
// one small Go binary for Windows/Linux/macOS that collects inventory and
// executes ONLY typed tasks. It never collects credentials, never runs
// arbitrary commands from the server, and buffers offline (§124).
package endpoint

import (
	"fmt"
	"os"
	"runtime"
)

// Config is the agent's local configuration.
type Config struct {
	ServerURL       string   `json:"server_url"` // control plane base URL
	EnrollToken     string   `json:"enroll_token,omitempty"`
	AgentID         string   `json:"agent_id,omitempty"`
	CertPath        string   `json:"cert_path,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	SiteHint        string   `json:"site_hint,omitempty"`
	Capabilities    []string `json:"capabilities"`
	CollectionLevel string   `json:"collection_level"` // basic|standard|full
	HeartbeatSecs   int      `json:"heartbeat_secs"`
	StateDir        string   `json:"state_dir"`
	MaxOfflineMB    int      `json:"max_offline_mb"`
}

// Load reads agent config from a JSON file with env fallbacks.
func Load(path string) (*Config, error) {
	cfg := &Config{
		ServerURL:       envOr("AEGIS_SERVER_URL", "http://localhost:8080"),
		EnrollToken:     os.Getenv("AEGIS_ENROLL_TOKEN"),
		CertPath:        envOr("AEGIS_CERT_PATH", "/etc/aegis/agent.crt"),
		KeyPath:         envOr("AEGIS_KEY_PATH", "/etc/aegis/agent.key"),
		CollectionLevel: envOr("AEGIS_COLLECTION_LEVEL", "basic"),
		HeartbeatSecs:   30,
		StateDir:        envOr("AEGIS_STATE_DIR", "/var/lib/aegis-agent"),
		MaxOfflineMB:    16,
		Capabilities:    []string{"basic_inventory", "software_inventory", "network_inventory", "security_posture"},
	}
	if path != "" {
		_ = readJSON(path, cfg)
	}
	if cfg.HeartbeatSecs < 10 {
		cfg.HeartbeatSecs = 10
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Platform returns the runtime platform identifier.
func Platform() string { return runtime.GOOS }

// AgentVersion is the agent binary version (bumped by CI).
const AgentVersion = "1.0.0"

// Validate checks the config for obviously unsafe values (§82).
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	if len(c.ServerURL) > 512 {
		return fmt.Errorf("server_url too long")
	}
	return nil
}
