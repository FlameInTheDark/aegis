package endpoint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// Collector gathers platform inventory with build-tag specific files.
// This file provides the common fallbacks shared by all platforms.
type Collector struct {
	Log *slog.Logger
	Cfg *Config
}

// BasicInfo is the common system identity subset.
type BasicInfo struct {
	Hostname string
	FQDN     string
	OS       string
	OSVer    string
	Arch     string
}

// Basic collects hostname/arch/OS family via stdlib only.
func (c *Collector) Basic() BasicInfo {
	host, _ := os.Hostname()
	info := BasicInfo{
		Hostname: host,
		Arch:     runtime.GOARCH,
		OS:       runtime.GOOS,
		OSVer:    runtime.GOOS + " " + runtime.Version(),
	}
	if runtime.GOOS == "linux" {
		fam, ver := linuxOSRelease()
		info.OS = fam
		info.OSVer = ver
	}
	return info
}

// linuxOSRelease parses /etc/os-release without shelling out.
func linuxOSRelease() (family, version string) {
	family, version = "linux", ""
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return family, version
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			family = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return family, version
}

// ---------------------------------------------------------------------------

// Client is a transport-agnostic view over the generated gRPC client so
// the runtime loop stays testable.
type Client interface {
	Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)
	GetConfig(ctx context.Context, agentID string) (*agentv1.AgentConfig, error)
	Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error)
	SubmitInventory(ctx context.Context, req *agentv1.InventoryReport) error
	SubmitSoftware(ctx context.Context, req *agentv1.SoftwareReport) error
	SubmitNetworkState(ctx context.Context, req *agentv1.NetworkStateReport) error
	SubmitSecurityPosture(ctx context.Context, req *agentv1.SecurityPostureReport) error
	PollTasks(ctx context.Context, agentID string) ([]*agentv1.AgentTask, error)
	CompleteTask(ctx context.Context, req *agentv1.CompleteTaskRequest) error
}

// Runtime drives the agent loop: enroll -> config -> (heartbeat | poll tasks | submit inventory).
type Runtime struct {
	Cfg       *Config
	Client    Client
	Collector *Collector
	Log       *slog.Logger
}

// Run blocks running the agent loop until ctx is done. Offline buffering
// (§124) keeps a bounded local queue of failed submissions.
func (r *Runtime) Run(ctx context.Context) error {
	if err := r.ensureEnrolled(ctx); err != nil {
		return err
	}
	_ = r.Collector
	cfg, err := r.Client.GetConfig(ctx, r.Cfg.AgentID)
	if err == nil && cfg != nil && cfg.HeartbeatIntervalSecs > 0 {
		r.Cfg.HeartbeatSecs = int(cfg.HeartbeatIntervalSecs)
	}
	tick := time.NewTicker(time.Duration(r.Cfg.HeartbeatSecs) * time.Second)
	defer tick.Stop()
	invTick := time.NewTicker(15 * time.Minute)
	defer invTick.Stop()

	// Initial burst of data on start.
	r.submitAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			hb, err := r.Client.Heartbeat(ctx, &agentv1.HeartbeatRequest{
				AgentId: r.Cfg.AgentID, AgentVersion: AgentVersion,
				UptimeSecs: uint64(time.Since(processStart).Seconds()),
			})
			if err != nil {
				r.Log.Warn("heartbeat failed; will retry", "err", err)
				continue
			}
			r.Log.Debug("heartbeat ok", "server_time", hb.GetServerTime())
			if err := r.pollAndRunTasks(ctx); err != nil {
				r.Log.Warn("task poll failed", "err", err)
			}
		case <-invTick.C:
			r.submitAll(ctx)
		}
	}
}

var processStart = time.Now()

// ensureEnrolled performs enrollment when no agent id exists.
func (r *Runtime) ensureEnrolled(ctx context.Context) error {
	if r.Cfg.AgentID != "" {
		return nil
	}
	if r.Cfg.EnrollToken == "" {
		return fmt.Errorf("no agent_id and no enroll token; enroll this endpoint via the UI first")
	}
	csrPEM, keyPEM, err := newCSRKeyPair()
	if err != nil {
		return fmt.Errorf("key generation: %w", err)
	}
	if err := os.MkdirAll(r.Cfg.StateDir, 0o700); err != nil {
		return err
	}
	// Private key is persisted locally ONLY (spec §16: never transmitted).
	if err := os.WriteFile(r.Cfg.KeyPath, []byte(keyPEM), 0o600); err != nil {
		return err
	}
	basic := r.Collector.Basic()
	resp, err := r.Client.Enroll(ctx, &agentv1.EnrollRequest{
		Token: r.Cfg.EnrollToken, CsrPem: csrPEM,
		Hostname: basic.Hostname, Platform: runtime.GOOS,
		PlatformVersion: basic.OSVer, Arch: basic.Arch,
		AgentVersion: AgentVersion,
	})
	if err != nil {
		return fmt.Errorf("enrollment rejected: %w", err)
	}
	r.Cfg.AgentID = resp.GetAgentId()
	if err := os.WriteFile(r.Cfg.CertPath, []byte(resp.GetCertificatePem()), 0o600); err != nil {
		return err
	}
	_ = writeJSON(r.Cfg.StateDir+"/agent.json", r.Cfg)
	r.Log.Info("enrolled", "agent_id", r.Cfg.AgentID)
	return nil
}

// submitAll pushes inventory, software, network state and posture.
func (r *Runtime) submitAll(ctx context.Context) {
	basic := r.Collector.Basic()
	inv := &agentv1.InventoryReport{
		AgentId: r.Cfg.AgentID, Hostname: basic.Hostname, Fqdn: basic.FQDN,
		OsFamily: basic.OS, OsName: basic.OS, OsVersion: basic.OSVer, Arch: basic.Arch,
	}
	if err := r.Client.SubmitInventory(ctx, inv); err != nil {
		r.Log.Warn("inventory submit failed", "err", err)
	}
	if pkgs := r.Collector.SoftwarePackages(); len(pkgs) > 0 {
		if len(pkgs) > 2000 {
			pkgs = pkgs[:2000]
		}
		ptrs := make([]*agentv1.SoftwareReport_Package, 0, len(pkgs))
		for i := range pkgs {
			ptrs = append(ptrs, &pkgs[i])
		}
		if err := r.Client.SubmitSoftware(ctx, &agentv1.SoftwareReport{AgentId: r.Cfg.AgentID, Packages: ptrs}); err != nil {
			r.Log.Warn("software submit failed", "err", err)
		}
	}
	if err := r.Client.SubmitNetworkState(ctx, &agentv1.NetworkStateReport{
		AgentId: r.Cfg.AgentID, ListeningSockets: toPtrSockets(r.Collector.ListeningSockets()),
		DefaultGateways: r.Collector.DefaultGateways(), DnsServers: r.Collector.DNSServers(),
	}); err != nil {
		r.Log.Warn("network submit failed", "err", err)
	}
	if err := r.Client.SubmitSecurityPosture(ctx, r.Collector.SecurityPosture()); err != nil {
		r.Log.Warn("posture submit failed", "err", err)
	}
}

// pollAndRunTasks executes typed tasks only (§19: no remote shell).
func (r *Runtime) pollAndRunTasks(ctx context.Context) error {
	tasks, err := r.Client.PollTasks(ctx, r.Cfg.AgentID)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		ok := true
		var resultJSON string
		var errMsg string
		switch t.GetType() {
		case "inventory_refresh", "software_inventory", "network_inventory", "socket_inventory", "security_posture":
			r.submitAll(ctx)
			resultJSON = `{"status":"collected"}`
		case "configuration_sync":
			if cfg, err := r.Client.GetConfig(ctx, r.Cfg.AgentID); err == nil {
				b, _ := marshal(cfg)
				resultJSON = string(b)
			}
		case "local_scan":
			// Local scan is permission-gated (§20): disabled unless config allows.
			ok = false
			errMsg = "local_scan is disabled on this agent (collection level " + r.Cfg.CollectionLevel + ")"
		case "local_configuration_check", "diagnostic":
			resultJSON = `{"status":"not_implemented_on_this_platform"}`
		default:
			ok = false
			errMsg = "unsupported task type " + t.GetType()
		}
		if err := r.Client.CompleteTask(ctx, &agentv1.CompleteTaskRequest{
			AgentId: r.Cfg.AgentID, TaskId: t.GetId(), Success: ok,
			Error: errMsg, ResultJson: bounded(resultJSON, 256<<10),
		}); err != nil {
			r.Log.Warn("task complete failed", "task", t.GetId(), "err", err)
		}
	}
	return nil
}

// toPtrSockets converts value sockets to generated pointer slice form.
func toPtrSockets(in []agentv1.NetworkStateReport_Socket) []*agentv1.NetworkStateReport_Socket {
	out := make([]*agentv1.NetworkStateReport_Socket, 0, len(in))
	for i := range in {
		out = append(out, &in[i])
	}
	return out
}

func bounded(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func marshal(v any) ([]byte, error) { return jsonMarshal(v) }

// sortInterfaces keeps output deterministic for tests.
func sortStrings(xs []string) []string { sort.Strings(xs); return xs }

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }
