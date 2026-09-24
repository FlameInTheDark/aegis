package endpoint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// ErrMetricsStorageDisabled is returned by the client when the server
// accepted a metrics sample but has no analytics tier to store it in. The
// runtime logs it once instead of warning on every sample.
var ErrMetricsStorageDisabled = errors.New("metrics storage disabled")

// ErrMetricsBatchUnsupported is returned by the client when the hub
// predates the batch metrics RPC. The runtime falls back to one RPC per
// sample so a newer connector keeps working against an older hub.
var ErrMetricsBatchUnsupported = errors.New("metrics batch unsupported")

// Collector gathers platform inventory with build-tag specific files.
// This file provides the common fallbacks shared by all platforms.
type Collector struct {
	Log *slog.Logger
	Cfg *Config
}

// BasicInfo is the common system identity subset.
type BasicInfo struct {
	Hostname  string
	FQDN      string
	OS        string // family: "windows", the os-release ID, "darwin"
	OSPretty  string // display name: "Windows 11 Pro", "Ubuntu 24.04.1 LTS", "macOS"
	OSVer     string // release: "24H2 (build 26100.2894)", "24.04", "14.5"
	Arch      string
	MachineID string // stable local identifier (best-effort)
}

// Basic collects hostname/arch/OS identity: stdlib facts plus the
// per-platform platformOSInfo hook (/etc/os-release on Linux, the registry
// on Windows, the kernel product version on macOS).
func (c *Collector) Basic() BasicInfo {
	host, _ := os.Hostname()
	fam, name, ver := platformOSInfo()
	if fam == "" {
		fam = runtime.GOOS
	}
	if name == "" {
		name = fam
	}
	return BasicInfo{
		Hostname:  host,
		Arch:      runtime.GOARCH,
		OS:        fam,
		OSPretty:  name,
		OSVer:     ver,
		MachineID: machineID(),
	}
}

// composeWindowsOS builds the displayed Windows edition and release from
// the registry values of HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
// Early Windows 11 builds still report "Windows 10" in ProductName — the
// build number (>= 22000) is authoritative and upgrades the family name.
// DisplayVersion ("24H2") is the marketing release; when it is absent
// (older Windows 10) the plain build number stands in. UBR is the update
// revision appended to the build ("26100.2894").
func composeWindowsOS(product, display, build string, ubr uint64, hasUBR bool) (name, version string) {
	name = strings.TrimSpace(product)
	if rest, ok := strings.CutPrefix(name, "Windows 10"); ok && windows11Build(build) {
		name = "Windows 11" + rest
	}
	if name == "" {
		name = "Windows"
	}
	v := strings.TrimSpace(build)
	if hasUBR && ubr > 0 && v != "" {
		v = fmt.Sprintf("%s.%d", v, ubr)
	}
	switch {
	case display != "" && v != "":
		version = fmt.Sprintf("%s (build %s)", display, v)
	case display != "":
		version = display
	default:
		version = v
	}
	return name, version
}

// windows11Build reports whether a registry build number identifies a
// Windows 11 release (22000 was the first Windows 11 build).
func windows11Build(build string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(build))
	return err == nil && n >= 22000
}

// ---------------------------------------------------------------------------

// Client is a transport-agnostic view over the generated gRPC client so
// the runtime loop stays testable.
type Client interface {
	BindDevice(ctx context.Context, req *BindRequest) (*BindResult, error)
	GetConfig(ctx context.Context, agentID string) (*agentv1.AgentConfig, error)
	Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error)
	SubmitInventory(ctx context.Context, req *agentv1.InventoryReport) error
	SubmitSoftware(ctx context.Context, req *agentv1.SoftwareReport) error
	SubmitNetworkState(ctx context.Context, req *agentv1.NetworkStateReport) error
	SubmitSecurityPosture(ctx context.Context, req *agentv1.SecurityPostureReport) error
	SubmitMetrics(ctx context.Context, req *agentv1.MetricsReport) error
	SubmitMetricsBatch(ctx context.Context, req *agentv1.MetricsBatchReport) error
	PollTasks(ctx context.Context, agentID string) ([]*agentv1.AgentTask, error)
	CompleteTask(ctx context.Context, req *agentv1.CompleteTaskRequest) error
	// Target is the resolved hub address; the primary-address picker uses
	// it as the routing destination for the management-connection probe.
	Target() string
}

// BindRequest carries the device identity facts for ConnectorService.BindDevice.
type BindRequest struct {
	CSR         string // PEM-encoded CSR (public key only)
	Hostname    string
	Platform    string
	PlatformVer string
	Arch        string
	Version     string
	MachineID   string
}

// BindResult is the device identity issued by the server.
type BindResult struct {
	AgentID        string
	CertificatePEM string
	SiteID         string
	HeartbeatSecs  int
}

// Runtime drives the agent loop: enroll -> config -> (heartbeat | poll tasks | submit inventory).
type Runtime struct {
	Cfg       *Config
	Client    Client
	Collector *Collector
	Log       *slog.Logger

	// previous network counter snapshot for throughput rates; only touched
	// from the Run goroutine.
	prevNet   map[string]*agentv1.IfaceMetrics
	prevNetAt time.Time
	netWarned bool // "metrics storage not configured" logged once

	// Metrics samples taken at the probe rate, flushed at the pull rate.
	// metricsBuf is only touched from the Run goroutine; the rates are
	// hot-reloadable and therefore mutex-guarded.
	metricsBuf []*agentv1.MetricsReport

	ratesMu      sync.Mutex
	probeRateMs  int
	pullRateMs   int
	ratesChanged chan struct{} // lazily created by SetMetricsRates
}

// maxMetricsBatch bounds one flush: at the fastest probe and slowest pull
// the buffer is cut off well before the batched RPC grows unwieldy. The
// pull cadence stays the pacing signal — this only guards pathological
// rate combinations and failed-flush accumulation.
const maxMetricsBatch = 1200

// Run blocks running the agent loop until ctx is done. Offline buffering
// keeps a bounded local queue of failed submissions.
func (r *Runtime) Run(ctx context.Context) error {
	if err := r.ensureBound(ctx); err != nil {
		return err
	}
	_ = r.Collector
	cfg, err := r.Client.GetConfig(ctx, r.Cfg.AgentID)
	if err == nil && cfg != nil && cfg.HeartbeatIntervalSecs > 0 {
		r.Cfg.HeartbeatSecs = int(cfg.HeartbeatIntervalSecs)
	}
	r.Cfg.normalizeMetricsRates()
	r.storeRates(r.Cfg.ProbeRateMs, r.Cfg.PullRateMs)
	tick := time.NewTicker(time.Duration(r.Cfg.HeartbeatSecs) * time.Second)
	defer tick.Stop()
	invTick := time.NewTicker(15 * time.Minute)
	defer invTick.Stop()
	probeTick := time.NewTicker(r.probeDur())
	defer probeTick.Stop()
	pullTick := time.NewTicker(r.pullDur())
	defer pullTick.Stop()
	// The first CPU reading measures "since the last call" — seed the
	// baseline now so the first tick already carries a real utilization.
	r.Collector.PrimeCPUSampling()

	// Initial burst of data on start.
	r.submitAll(ctx)
	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush so a graceful stop does not
			// silently discard the samples collected since the
			// last pull.
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			r.flushMetrics(flushCtx)
			cancel()
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
		case <-r.rateSignal():
			// Settings push changed the cadence: re-arm both
			// tickers. A stale tick from the old period may still
			// fire once — harmless (one extra sample or flush).
			probeD, pullD := r.probeDur(), r.pullDur()
			probeTick.Reset(probeD)
			pullTick.Reset(pullD)
			r.Log.Debug("metrics cadence updated", "probe_rate_ms", probeD.Milliseconds(), "pull_rate_ms", pullD.Milliseconds())
		case <-probeTick.C:
			r.collectMetricsSample()
			if len(r.metricsBuf) >= maxMetricsBatch {
				r.flushMetrics(ctx)
			}
		case <-pullTick.C:
			r.flushMetrics(ctx)
		case <-invTick.C:
			r.submitAll(ctx)
		}
	}
}

var processStart = time.Now()

// EnsureBound runs ONLY the device binding and returns; the connector's
// endpoint role uses this on startup before handing over to Run.
func (r *Runtime) EnsureBound(ctx context.Context) error {
	return r.ensureBound(ctx)
}

// ensureBound binds this endpoint to its connector when no device identity
// exists yet. The CSR is generated locally; the private key never leaves.
func (r *Runtime) ensureBound(ctx context.Context) error {
	if r.Cfg.AgentID != "" {
		return nil
	}
	if r.Cfg.ConnectorID == "" || r.Cfg.ConnectorSecret == "" {
		return fmt.Errorf("no device identity and no connection credentials; enroll with: aegis-connector --connect <host>:<port>/<token>")
	}
	csrPEM, keyPEM, err := newCSRKeyPair()
	if err != nil {
		return fmt.Errorf("key generation: %w", err)
	}
	if err := os.MkdirAll(r.Cfg.StateDir, 0o700); err != nil {
		return err
	}
	// Private key is persisted locally ONLY (: never transmitted).
	if err := os.WriteFile(r.Cfg.KeyPath, []byte(keyPEM), 0o600); err != nil {
		return err
	}
	basic := r.Collector.Basic()
	resp, err := r.Client.BindDevice(ctx, &BindRequest{
		CSR:      csrPEM,
		Hostname: basic.Hostname, Platform: runtime.GOOS,
		PlatformVer: basic.OSVer, Arch: basic.Arch,
		Version:   AgentVersion,
		MachineID: basic.MachineID,
	})
	if err != nil {
		return fmt.Errorf("device bind rejected: %w", err)
	}
	r.Cfg.AgentID = resp.AgentID
	if resp.HeartbeatSecs > 0 {
		r.Cfg.HeartbeatSecs = resp.HeartbeatSecs
	}
	if err := os.WriteFile(r.Cfg.CertPath, []byte(resp.CertificatePEM), 0o600); err != nil {
		return err
	}
	// Persist device state WITHOUT the connector secret: credentials live
	// only in the connector's own 0600 config file.
	stateCopy := *r.Cfg
	stateCopy.ConnectorSecret = ""
	if err := writeJSON(filepath.Join(r.Cfg.StateDir, StateFileName), &stateCopy); err != nil {
		r.Log.Warn("state persist failed (device is bound but will not remember it)", "err", err)
	}
	r.Log.Info("device bound", "agent_id", r.Cfg.AgentID, "site", resp.SiteID, "state_dir", r.Cfg.StateDir)
	return nil
}

// submitAll pushes inventory, software, network state and posture.
func (r *Runtime) submitAll(ctx context.Context) {
	basic := r.Collector.Basic()
	inv := &agentv1.InventoryReport{
		AgentId: r.Cfg.AgentID, Hostname: basic.Hostname, Fqdn: basic.FQDN,
		OsFamily: basic.OS, OsName: basic.OSPretty, OsVersion: basic.OSVer, Arch: basic.Arch,
		Kernel: r.Collector.KernelVersion(), UptimeSecs: r.Collector.UptimeSecs(),
	}
	if model, cores := r.Collector.CPUInfo(); model != "" || cores > 0 {
		inv.CpuModel, inv.CpuCores = model, cores
	}
	if total, _, _ := r.Collector.MemoryInfo(); total > 0 {
		inv.MemoryTotal = total
	}
	inv.Interfaces = r.Collector.NetInterfaces()
	inv.PrimaryIp = PickPrimaryIP(r.Client.Target(), inv.Interfaces)
	inv.Disks = r.Collector.DiskUsage()
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

// collectMetricsSample takes one performance sample (CPU, memory, load,
// uptime, per-NIC counters) and buffers it; flushMetrics sends the whole
// buffer at the pull rate. Throughput rates are computed against the
// previous SAMPLE (not the previous pull), so a fast probe yields the same
// rates a slow probe did — just at a finer resolution.
func (r *Runtime) collectMetricsSample() {
	now := time.Now()
	cpuPct := r.Collector.CPUPercentSinceLast()
	total, used, avail := r.Collector.MemoryInfo()
	l1, l5, l15 := r.Collector.LoadAverages()
	cur := r.Collector.NetCounters()

	rep := &agentv1.MetricsReport{
		AgentId:         r.Cfg.AgentID,
		CollectedAtUnix: now.Unix(),
		CpuPercent:      cpuPct,
		MemoryTotal:     total,
		MemoryUsed:      used,
		MemoryAvailable: avail,
		Load1:           l1, Load5: l5, Load15: l15,
		UptimeSecs: r.Collector.UptimeSecs(),
	}
	if r.prevNet != nil {
		rep.Interfaces = ifaceRates(r.prevNet, cur, now.Sub(r.prevNetAt))
	}
	r.prevNet, r.prevNetAt = cur, now
	r.metricsBuf = append(r.metricsBuf, rep)
}

// flushMetrics sends every buffered sample to the hub in ONE batched call,
// so a fast probe rate does not turn into one RPC per sample. An older hub
// without the batch RPC falls back to per-sample submissions; a hub without
// the analytics tier acknowledges-and-drops (logged once); any other
// failure keeps the samples for the next pull, bounded by maxMetricsBatch.
func (r *Runtime) flushMetrics(ctx context.Context) {
	if len(r.metricsBuf) == 0 {
		return
	}
	batch := r.metricsBuf
	r.metricsBuf = nil
	err := r.Client.SubmitMetricsBatch(ctx, &agentv1.MetricsBatchReport{
		AgentId: r.Cfg.AgentID,
		Samples: batch,
	})
	switch {
	case err == nil:
		return
	case errors.Is(err, ErrMetricsBatchUnsupported):
		// Hub predates the batch RPC: degrade to one RPC per sample.
		for _, rep := range batch {
			r.submitOneMetric(ctx, rep)
		}
	case errors.Is(err, ErrMetricsStorageDisabled):
		if !r.netWarned {
			r.netWarned = true
			r.Log.Info("metrics storage not configured on the server; performance samples are dropped")
		}
	default:
		r.Log.Warn("metrics batch submit failed; samples kept for the next pull", "samples", len(batch), "err", err)
		// Re-buffer with the failed batch in front; drop the OLDEST
		// overflow so persistent failures cannot grow it unbounded.
		r.metricsBuf = append(batch, r.metricsBuf...)
		if len(r.metricsBuf) > maxMetricsBatch {
			r.metricsBuf = r.metricsBuf[len(r.metricsBuf)-maxMetricsBatch:]
		}
	}
}

// submitOneMetric pushes a single sample (the per-RPC fallback path).
func (r *Runtime) submitOneMetric(ctx context.Context, rep *agentv1.MetricsReport) {
	if err := r.Client.SubmitMetrics(ctx, rep); err != nil {
		if errors.Is(err, ErrMetricsStorageDisabled) {
			if !r.netWarned {
				r.netWarned = true
				r.Log.Info("metrics storage not configured on the server; performance samples are dropped")
			}
			return
		}
		r.Log.Warn("metrics submit failed", "err", err)
	}
}

// SetMetricsRates hot-applies a new metrics cadence from the connection
// settings push (no restart needed). Values are normalized exactly like
// the config load; the running loop re-arms its tickers when it sees the
// change signal. Safe to call before Run (the loop picks the rates up at
// start) and concurrently from the config-watch goroutine.
func (r *Runtime) SetMetricsRates(probeMs, pullMs int) {
	tmp := Config{ProbeRateMs: probeMs, PullRateMs: pullMs}
	tmp.normalizeMetricsRates()
	r.ratesMu.Lock()
	changed := tmp.ProbeRateMs != r.probeRateMs || tmp.PullRateMs != r.pullRateMs
	if changed {
		r.probeRateMs, r.pullRateMs = tmp.ProbeRateMs, tmp.PullRateMs
	}
	if r.ratesChanged == nil {
		r.ratesChanged = make(chan struct{}, 1)
	}
	ch := r.ratesChanged
	r.ratesMu.Unlock()
	if changed {
		select {
		case ch <- struct{}{}:
		default: // a signal is already pending — one re-arm suffices
		}
	}
}

// storeRates seeds the initial cadence (Run startup, same goroutine as the
// loop); no signal is sent because the tickers are created right after.
func (r *Runtime) storeRates(probeMs, pullMs int) {
	r.ratesMu.Lock()
	r.probeRateMs, r.pullRateMs = probeMs, pullMs
	r.ratesMu.Unlock()
}

func (r *Runtime) probeDur() time.Duration {
	r.ratesMu.Lock()
	defer r.ratesMu.Unlock()
	return time.Duration(r.probeRateMs) * time.Millisecond
}

func (r *Runtime) pullDur() time.Duration {
	r.ratesMu.Lock()
	defer r.ratesMu.Unlock()
	return time.Duration(r.pullRateMs) * time.Millisecond
}

// rateSignal returns the change-signal channel (nil until SetMetricsRates
// creates it; a nil channel in a select simply never fires).
func (r *Runtime) rateSignal() <-chan struct{} {
	r.ratesMu.Lock()
	defer r.ratesMu.Unlock()
	return r.ratesChanged
}

// pollAndRunTasks executes typed tasks only (: no remote shell).
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
			// Local scan is permission-gated: disabled unless config allows.
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
