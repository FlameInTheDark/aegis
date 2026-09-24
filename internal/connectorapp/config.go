// Package connectorapp implements the aegis-connector binary's runtime:
// the local credential file, the gRPC client for aegis.connector.v1, the
// persistent work loop (config reload on connect, watch-stream hot reload,
// heartbeats with drift recovery) and the per-kind role logic that runs on
// top of the distributed configuration.
package connectorapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Version is the connector binary version (overridden via ldflags).
var Version = "dev"

// LocalConfig is the credential file persisted after a successful
// enrollment (the "config file for continued connection" of the protocol).
// It contains the long-lived connector secret and is chmod 0600.
type LocalConfig struct {
	Server        string `json:"server"`         // gRPC endpoint host:port
	TLS           bool   `json:"tls"`            // use TLS for the gRPC connection
	ConnectorID   string `json:"connector_id"`   // assigned by the backend
	Secret        string `json:"secret"`         // long-lived credential (aegis_conn_s_...)
	Kind          string `json:"kind"`           // agent | scanner | collector
	Name          string `json:"name"`           // connector name from the UI
	GrpcEndpoint  string `json:"grpc_endpoint"`  // canonical endpoint info from the allow message
	ConfigVersion int64  `json:"config_version"` // last applied configuration version
	HeartbeatSecs int    `json:"heartbeat_secs"` // heartbeat interval from the backend

	// ConfigPath is the file this config was loaded from / saved to. Not
	// persisted; used by roles to locate adjacent state (endpoint device
	// state lives in <dir>/endpoint).
	ConfigPath string `json:"-"`
}

// ErrNoConfig is returned when a command needs saved credentials but none
// exist yet.
var ErrNoConfig = errors.New("no connector config found; run `aegis-connector --connect <host:port>/<token>` first")

// DefaultPath resolves the config file location: explicit flag > env var >
// /etc/aegis-connector/config.json for root, ~/.aegis-connector/config.json
// otherwise.
func DefaultPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("AEGIS_CONNECTOR_CONFIG"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "aegis-connector", "config.json")
		}
	}
	if os.Geteuid() == 0 {
		return "/etc/aegis-connector/config.json"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "aegis-connector.json"
	}
	return filepath.Join(home, ".aegis-connector", "config.json")
}

// Load reads the local credential file.
func Load(path string) (*LocalConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoConfig
		}
		return nil, err
	}
	cfg := &LocalConfig{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("invalid connector config at %s: %w", path, err)
	}
	if cfg.Server == "" || cfg.ConnectorID == "" || cfg.Secret == "" {
		return nil, fmt.Errorf("connector config at %s is incomplete (need server, connector_id, secret)", path)
	}
	cfg.ConfigPath = path
	return cfg, nil
}

// Save atomically persists the credential file with restrictive mode:
// the directory is 0700 and the file 0600 because it carries the secret.
func Save(path string, cfg *LocalConfig) error {
	cfg.ConfigPath = path
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Remove deletes the credential file (reset command).
func Remove(path string) error {
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
