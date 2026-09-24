package connectorapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"github.com/FlameInTheDark/aegis/internal/endpoint"
	"github.com/FlameInTheDark/aegis/internal/scanexec"
	"github.com/FlameInTheDark/aegis/internal/scanner"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/FlameInTheDark/aegis/internal/transport/agentclient"
	"google.golang.org/grpc/credentials"
	"strconv"
)

// Role is the per-kind logic that runs on top of the shared connection
// protocol. Every kind enrolls, authenticates, receives configuration and
// heartbeats identically; a role only defines what the component DOES:
// which capabilities it advertises, how it applies configuration and what
// status it reports back.
type Role interface {
	// Kind is the connector kind this role implements.
	Kind() string
	// Capabilities are advertised at enrollment.
	Capabilities() []string
	// ApplyConfig applies a new configuration revision (hot reload; no
	// restart required). Called on the initial snapshot too.
	ApplyConfig(ctx context.Context, settings json.RawMessage) error
	// Run is the role work loop; it blocks until ctx is cancelled.
	Run(ctx context.Context, log *slog.Logger) error
	// Status is the role status snapshot reported with every heartbeat.
	Status() map[string]any
}

// NewRole builds the role logic for a connector kind. Agent- and
// scanner-kind connections get the hybrid container: it runs one or both
// work functions per the connection settings toggles (or the local CLI
// override) and hot-applies toggle flips. Unknown kinds fall back to the
// generic collector role so future kinds keep working with older binaries
// (the server-side record defines the semantics). cfg carries the
// connection material (endpoint + credentials) for roles that open their
// own data-plane connections on top of the shared protocol — today the
// scanner role's hub stream.
func NewRole(kind string, log *slog.Logger, cfg *LocalConfig, only string) Role {
	switch kind {
	case "agent", "scanner":
		return newHybridRole(kind, log, cfg, only)
	default:
		return &CollectorRole{log: log, started: time.Now()}
	}
}

// AgentRole is the endpoint-device role. Since v1.24.0 it is the ONLY way
// an endpoint enrolls: this role runs on an agent-kind connector and does
// the whole endpoint job on top of the shared connection protocol —
// device binding (CSR -> certificate via BindDevice), inventory collection
// and typed task execution through internal/endpoint, authenticated with
// the connector credentials. There is no separate agent binary anymore.
type AgentRole struct {
	log     *slog.Logger
	started time.Time
	cfg     *LocalConfig

	mu       sync.Mutex
	settings map[string]any
	agentID  string // device id once bound
	lastErr  string
	rt       *endpoint.Runtime // running endpoint loop, for hot rate reload
}

func (r *AgentRole) Kind() string { return "agent" }

func (r *AgentRole) Capabilities() []string {
	return []string{
		"basic_inventory", "software_inventory", "network_inventory",
		"security_posture", "status_reporting", "config_hot_reload",
	}
}

func (r *AgentRole) ApplyConfig(_ context.Context, settings json.RawMessage) error {
	m := map[string]any{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &m); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	r.mu.Lock()
	r.settings = m
	rt := r.rt
	r.mu.Unlock()
	// Hot-apply the metrics cadence to a running endpoint loop: probe
	// and pull rates take effect within one loop iteration, no restart.
	// The collection level still applies on the next (re)connect because
	// the collector capabilities are fixed per runtime instance.
	if rt != nil {
		rt.SetMetricsRates(agentRateSetting(m, "probe_rate_ms"), agentRateSetting(m, "pull_rate_ms"))
	}
	return nil
}

// agentRateSetting reads a millisecond rate from the agent settings
// section. Absent or malformed keys yield 0 — the endpoint runtime
// substitutes its defaults, so a partial settings push can never zero the
// cadence.
func agentRateSetting(settings map[string]any, key string) int {
	if v, ok := settings[key]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			return n
		}
	}
	return 0
}

// endpointConfig builds the endpoint runtime configuration from the
// connector credentials: same endpoint, same secret, device state next to
// the connector config file.
func (r *AgentRole) endpointConfig() *endpoint.Config {
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	level := "basic"
	if v, ok := settings["collection_level"].(string); ok && v != "" {
		level = v
	}
	server := r.cfg.Server
	if r.cfg.TLS {
		server = "https://" + server
	} else {
		server = "http://" + server
	}
	stateDir := endpointStateDir(r.cfg.ConfigPath)
	return &endpoint.Config{
		ServerURL:       server,
		ConnectorID:     r.cfg.ConnectorID,
		ConnectorSecret: r.cfg.Secret,
		CollectionLevel: level,
		HeartbeatSecs:   30,
		ProbeRateMs:     agentRateSetting(settings, "probe_rate_ms"),
		PullRateMs:      agentRateSetting(settings, "pull_rate_ms"),
		StateDir:        stateDir,
		CertPath:        filepath.Join(stateDir, "agent.crt"),
		KeyPath:         filepath.Join(stateDir, "agent.key"),
		MaxOfflineMB:    16,
		Capabilities:    r.Capabilities(),
	}
}

// Run drives the endpoint runtime for as long as the connector session
// lives. Transient data-plane failures (hub restarts, network blips) are
// retried with backoff — the connector session heartbeat reports role
// status throughout; only a cancelled context ends the loop.
func (r *AgentRole) Run(ctx context.Context, log *slog.Logger) error {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		ecfg := r.endpointConfig()
		client, err := agentclient.New(ecfg)
		if err != nil {
			err = fmt.Errorf("endpoint client: %w", err)
		} else {
			rt := &endpoint.Runtime{
				Cfg:       ecfg,
				Client:    client,
				Collector: &endpoint.Collector{Cfg: ecfg, Log: log},
				Log:       log,
			}
			r.mu.Lock()
			r.rt = rt
			r.mu.Unlock()
			err = rt.Run(ctx)
			r.mu.Lock()
			r.rt = nil
			r.agentID = ecfg.AgentID
			r.mu.Unlock()
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
		}
		if err != nil {
			r.mu.Lock()
			r.lastErr = err.Error()
			r.mu.Unlock()
			log.Warn("endpoint loop failed; retrying", "err", err, "backoff", backoff.String())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (r *AgentRole) Status() map[string]any {
	host, _ := os.Hostname()
	r.mu.Lock()
	settings := r.settings
	agentID := r.agentID
	lastErr := r.lastErr
	r.mu.Unlock()
	status := map[string]any{
		"role":        "agent",
		"hostname":    host,
		"platform":    runtime.GOOS,
		"arch":        runtime.GOARCH,
		"num_cpu":     runtime.NumCPU(),
		"go_version":  runtime.Version(),
		"uptime_secs": int64(time.Since(r.started).Seconds()),
		"settings":    settings,
	}
	if agentID != "" {
		status["device_id"] = agentID
	}
	if lastErr != "" {
		status["last_error"] = lastErr
	}
	return status
}

// endpointStateDir keeps the device state (agent.json, key material) next
// to the connector config file.
func endpointStateDir(configPath string) string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), "endpoint")
	}
	return filepath.Join(".", "aegis-connector-endpoint")
}

// ScannerRole is the remote-scanner role. On top of the shared connection
// protocol (enroll, config watch, heartbeat) it opens the scanner-hub
// Jobs stream with its connector credentials and executes dispatched scans
// through the same pipeline the embedded scanner and hub agents use
// (internal/scanexec). The scan engine and SSH collector are driven by the
// connection configuration and hot-reload without a restart.
type ScannerRole struct {
	log     *slog.Logger
	started time.Time
	tools   []string
	cfg     *LocalConfig

	mu           sync.Mutex
	settings     map[string]any
	exec         *scanexec.Executor
	engineDetail string // human-readable engine resolution for the heartbeat status
}

func (r *ScannerRole) Kind() string { return "scanner" }

func (r *ScannerRole) Capabilities() []string {
	caps := []string{"status_reporting", "config_hot_reload"}
	caps = append(caps, r.tools...)
	return caps
}

func (r *ScannerRole) ApplyConfig(_ context.Context, settings json.RawMessage) error {
	m := map[string]any{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &m); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	r.mu.Lock()
	r.settings = m
	exec := r.exec
	r.mu.Unlock()
	// Resolve the engine (and its explanation) on every config change so the
	// heartbeat status always explains the current engine state; a missing
	// nmap binary is logged loudly here too.
	eng, detail := r.resolveEngine()
	r.mu.Lock()
	r.engineDetail = detail
	r.mu.Unlock()
	// Live executor present (role running): apply engine/SSH hot reload.
	if exec != nil {
		exec.SetEngine(eng)
		exec.SetSSH(r.sshSettings())
	}
	return nil
}

// resolveEngine picks the scan engine from the `engine` config key and
// returns it with a human-readable explanation for the heartbeat status:
// "auto" (default) uses nmap when present and simulates otherwise —
// LOUDLY, so a degraded scanner can never pass unnoticed; "nmap"/
// "simulated" force one explicitly.
func (r *ScannerRole) resolveEngine() (scanner.Engine, string) {
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	mode := stringSetting(settings, "engine", "auto")
	// An explicitly configured nmap executable wins over PATH detection, so
	// operators can point the scanner at a specific binary (versioned,
	// non-PATH installs). Hot reload re-evaluates this on every push.
	nmapPath := stringSetting(settings, "nmap_path", "")
	if nmapPath == "" {
		nmapPath = detectNmapPath()
	}
	switch mode {
	case "simulated":
		return &scanner.SimulatedEngine{}, "engine=simulated (configured in the connection settings)"
	case "nmap":
		if nmapPath != "" {
			return &scanner.NmapEngine{BinPath: nmapPath}, "engine=nmap (" + nmapPath + ")"
		}
		r.log.Warn("engine=nmap requested but no nmap binary found; falling back to the SIMULATED engine — results are synthetic demo data, not real scans")
		return &scanner.SimulatedEngine{}, "engine=nmap was requested but no nmap binary was found on this host — producing SIMULATED results"
	default: // auto
		if nmapPath != "" {
			return &scanner.NmapEngine{BinPath: nmapPath}, "engine=nmap (" + nmapPath + ")"
		}
		r.log.Warn("no nmap binary found on this host; scans will produce SIMULATED synthetic results, not real scans — install nmap (or set nmap_path in the connection config) to scan for real")
		return &scanner.SimulatedEngine{}, "no nmap binary found on this host — producing SIMULATED results (install nmap or set nmap_path in the connection config)"
	}
}

// sshSettings maps the `ssh_*` config keys onto the agent-less SSH
// collector: ssh_hosts (list of "user@host[:port]" or "host[:port]"),
// ssh_user (default for hosts without a user prefix), ssh_password,
// ssh_key_path, ssh_insecure.
func (r *ScannerRole) sshSettings() scanexec.SSHSettings {
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	defaults := scanexec.SSHSettings{
		User:      stringSetting(settings, "ssh_user", ""),
		Password:  stringSetting(settings, "ssh_password", ""),
		KeyPath:   stringSetting(settings, "ssh_key_path", ""),
		Timeout:   10 * time.Second,
		Insecure:  boolSetting(settings, "ssh_insecure", false),
		PinnedKey: stringSetting(settings, "ssh_pinned_key", ""),
	}
	if v, ok := settings["ssh_timeout_secs"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			defaults.Timeout = time.Duration(n) * time.Second
		}
	}
	if list, ok := settings["ssh_hosts"].([]any); ok {
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if h, ok := parseSSHHostSpec(s, defaults.User); ok {
				defaults.Hosts = append(defaults.Hosts, h)
			}
		}
	}
	return defaults
}

// parseSSHHostSpec parses "user@host[:port]" / "host[:port]".
func parseSSHHostSpec(spec, defaultUser string) (scanning.SSHHostConfig, bool) {
	spec = strings.TrimSpace(spec)
	spec = strings.TrimPrefix(spec, "ssh://")
	if spec == "" {
		return scanning.SSHHostConfig{}, false
	}
	user := defaultUser
	if at := strings.Index(spec, "@"); at >= 0 {
		user = spec[:at]
		spec = spec[at+1:]
	}
	if user == "" {
		user = "root"
	}
	host, port := spec, 22
	if i := strings.LastIndex(spec, ":"); i >= 0 && !strings.Contains(spec[i+1:], "]") {
		if n, err := strconv.Atoi(spec[i+1:]); err == nil && n > 0 && n < 65536 {
			host, port = spec[:i], n
		}
	}
	if host == "" {
		return scanning.SSHHostConfig{}, false
	}
	return scanning.SSHHostConfig{Host: host, Port: port, User: user}, true
}

func (r *ScannerRole) Run(ctx context.Context, _ *slog.Logger) error {
	eng, engDetail := r.resolveEngine()
	r.mu.Lock()
	r.engineDetail = engDetail
	r.mu.Unlock()
	exec := &scanexec.Executor{
		Engine: eng,
		Log:    r.log,
		Limits: scanner.DefaultLimits(),
		SSH:    r.sshSettings(),
	}
	r.mu.Lock()
	r.exec = exec
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.exec = nil
		r.mu.Unlock()
	}()

	// TLS for the hub stream follows the connector endpoint grammar: the
	// saved connection records whether the server speaks TLS.
	var transport credentials.TransportCredentials
	if r.cfg != nil && r.cfg.TLS {
		transport = credentials.NewTLS(&tls.Config{}) // system roots; SNI from the endpoint host
	}
	auth := scanexec.HubAuth{ConnectorID: r.cfg.ConnectorID, ConnectorSecret: r.cfg.Secret}
	name := r.cfg.Name
	if name == "" {
		name = "connector-scanner"
	}
	return scanexec.RunAgent(ctx, exec, scanexec.AgentOptions{
		HubAddr:      r.cfg.Server,
		Auth:         auth,
		Transport:    transport,
		Name:         name,
		Version:      Version + "/" + exec.Engine.Name(),
		Capabilities: r.Capabilities(),
	})
}

func (r *ScannerRole) Status() map[string]any {
	r.mu.Lock()
	settings := r.settings
	exec := r.exec
	detail := r.engineDetail
	r.mu.Unlock()
	engine := ""
	if exec != nil && exec.Engine != nil {
		engine = exec.Engine.Name()
	}
	return map[string]any{
		"role":          "scanner",
		"platform":      runtime.GOOS,
		"arch":          runtime.GOARCH,
		"tools":         r.tools,
		"engine":        engine,
		"engine_detail": detail,
		"version":       Version,
		"hub":           r.cfg != nil,
		"uptime_secs":   int64(time.Since(r.started).Seconds()),
		"settings":      settings,
	}
}

// detectNmapPath delegates to the shared detector (PATH first, then the
// common install locations on Linux/macOS/Windows).
func detectNmapPath() string { return scanner.DetectNmapPath() }

func stringSetting(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func boolSetting(m map[string]any, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

// detectScanTools reports which scanning binaries are on PATH.
func detectScanTools() []string {
	known := []string{"nmap", "zgrab2", "masscan", "nuclei", "tracepath"}
	var found []string
	for _, t := range known {
		if p, err := exec.LookPath(t); err == nil && p != "" {
			found = append(found, t)
		}
	}
	sort.Strings(found)
	return found
}

// CollectorRole is the external-collector role: a generic component that
// forwards data into the platform through its own channel and uses the
// connector plane for identity, configuration and liveness.
type CollectorRole struct {
	log     *slog.Logger
	started time.Time

	mu       sync.Mutex
	settings map[string]any
}

func (r *CollectorRole) Kind() string { return "collector" }

func (r *CollectorRole) Capabilities() []string {
	return []string{"status_reporting", "config_hot_reload"}
}

func (r *CollectorRole) ApplyConfig(_ context.Context, settings json.RawMessage) error {
	m := map[string]any{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &m); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	r.mu.Lock()
	r.settings = m
	r.mu.Unlock()
	return nil
}

func (r *CollectorRole) Run(ctx context.Context, _ *slog.Logger) error {
	<-ctx.Done()
	return nil
}

func (r *CollectorRole) Status() map[string]any {
	r.mu.Lock()
	settings := r.settings
	r.mu.Unlock()
	return map[string]any{
		"role":        "collector",
		"platform":    runtime.GOOS,
		"arch":        runtime.GOARCH,
		"uptime_secs": int64(time.Since(r.started).Seconds()),
		"settings":    settings,
	}
}

// settingsString renders settings compactly for logs.
func settingsString(settings json.RawMessage) string {
	s := strings.TrimSpace(string(settings))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
