// Package scanexec holds the scan-execution pipeline shared by every
// scanning binary: the embedded compose scanner (cmd/scanner, direct DB),
// the token-enrolled hub agent (cmd/scanner -mode=agent) and the unified
// aegis-connector scanner role (cmd/connector, connector-secret auth).
// The pipeline is transport-agnostic: an Orch adapter decides where
// observations and state updates flow.
package scanexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/scanner"
	"github.com/FlameInTheDark/aegis/internal/scanning"
)

// ErrScanCancelled is returned by RunScan when the kill switch fires or
// the scan transitions to cancelling: callers map it to the CANCELLED
// scan state instead of FAILED, and the in-flight nmap process is killed
// via the run context (exec.CommandContext).
var ErrScanCancelled = errors.New("scan cancelled")

// JobLogSink receives structured job log and state events. Implemented by
// the Orch adapter families: localOrch broadcasts over NATS (embedded
// mode), RemoteOrch streams them inside hub reports (agent/connector
// mode). A nil sink disables job logging entirely.
type JobLogSink interface {
	EmitJobLog(ctx context.Context, e *domain.JobLogEvent)
	EmitState(ctx context.Context, e *domain.ScanStateEvent)
}

// EngineHooker is implemented by engines that can tee raw diagnostics
// (argv, stderr lines) while running; scanexec installs per-scan emitters
// through it.
type EngineHooker interface {
	SetOutputHooks(onCommand func(argv []string), onStderr func(line string))
}

// jobLogger stamps every emission with the scan/org/scanner/task context
// so instrumentation call sites stay one-liners. TaskID changes as the
// pipeline creates tasks; emissions are fire-and-forget (a logging
// failure must never fail a scan).
type jobLogger struct {
	sink      JobLogSink
	scanID    string
	orgID     string
	scannerID string
	mu        sync.Mutex
	taskID    string
}

func (l *jobLogger) setTask(id string) {
	l.mu.Lock()
	l.taskID = id
	l.mu.Unlock()
}

func (l *jobLogger) emit(ctx context.Context, level, source, msg string, fields map[string]any) {
	if l == nil || l.sink == nil {
		return
	}
	l.mu.Lock()
	taskID := l.taskID
	l.mu.Unlock()
	l.sink.EmitJobLog(ctx, &domain.JobLogEvent{
		ScanID: l.scanID, TaskID: taskID, ScannerID: l.scannerID, OrgID: l.orgID,
		Ts: time.Now().UTC(), Level: level, Source: source, Msg: msg, Fields: fields,
	})
}

func (l *jobLogger) debug(ctx context.Context, source, msg string, fields map[string]any) {
	l.emit(ctx, domain.LevelDebug, source, msg, fields)
}

func (l *jobLogger) info(ctx context.Context, source, msg string, fields map[string]any) {
	l.emit(ctx, domain.LevelInfo, source, msg, fields)
}

func (l *jobLogger) warn(ctx context.Context, source, msg string, fields map[string]any) {
	l.emit(ctx, domain.LevelWarn, source, msg, fields)
}

func (l *jobLogger) err(ctx context.Context, source, msg string, fields map[string]any) {
	l.emit(ctx, domain.LevelError, source, msg, fields)
}

// state emits a lifecycle/progress event alongside the DB state write.
func (l *jobLogger) state(ctx context.Context, state domain.ScanState, phase string, progress float64, stats *domain.ScanStats) {
	if l == nil || l.sink == nil {
		return
	}
	l.mu.Lock()
	taskID := l.taskID
	l.mu.Unlock()
	p := progress
	l.sink.EmitState(ctx, &domain.ScanStateEvent{
		ScanID: l.scanID, OrgID: l.orgID, State: string(state), Phase: phase,
		Progress: &p, Stats: stats, Ts: time.Now().UTC(), ScannerID: l.scannerID,
	})
	_ = taskID
}

// Orch is the orchestrator surface the scan executor needs. Two adapter
// families implement it: direct-DB adapters (embedded mode, via
// scanning.Orchestrator) and remote adapters (hub agent / connector mode:
// everything flows to the hub over gRPC, so a remote scanner never touches
// Postgres/NATS).
type Orch interface {
	RecordObservation(ctx context.Context, obs *domain.Observation) error
	ResolveProfile(ctx context.Context, orgID string, p domain.ScanProfile) (*domain.ProfileDefinition, error)
	Scope(ctx context.Context, scanID string) (*domain.ScanScope, error)
	ScanByID(ctx context.Context, orgID, scanID string) (*domain.Scan, error)
	QueueScans(ctx context.Context) ([]domain.Scan, error)
	UpdateScanState(ctx context.Context, scanID string, state domain.ScanState, phase string, progress float64) error
	UpdateScanStats(ctx context.Context, scanID string, stats domain.ScanStats) error
	SetScanError(ctx context.Context, scanID, msg string) error
	CreateTask(ctx context.Context, t *domain.ScanTask) error
	UpdateTaskState(ctx context.Context, taskID string, state domain.TaskState, msg string) error
	PublishScanResult(ctx context.Context, scanID string, state domain.ScanState) error
}

// SSHSettings parameterizes the agent-less ssh_inventory collector
// (cmd/scanner reads them from AEGIS_SSH_SCAN_*; the connector role from
// its connection configuration).
type SSHSettings struct {
	Hosts    []scanning.SSHHostConfig
	User     string
	Password string
	KeyPath  string
	Timeout  time.Duration
	Insecure bool
	// PinnedKey pins the SSH host key for the scanner-level fallback
	// host list (authorized_keys format). Per-scan hosts carry their own.
	PinnedKey string
}

// Executor runs the phased scan pipeline: discover -> ports ->
// fingerprint -> OS -> topology trace, plus the agent-less SSH inventory
// phase. One scan at a time (the embedded scanner and the hub agents all
// serialize); TryClaim/Release guard that invariant.
type Executor struct {
	Engine scanner.Engine
	Orch   Orch
	Log    *slog.Logger
	Limits scanner.Limits
	// SiteID filters the embedded claim loop (only scans queued for this
	// site); hub-pushed jobs bypass the filter — the hub already routed
	// them to this scanner.
	SiteID string
	SSH    SSHSettings

	mu     sync.Mutex
	active bool
	// pendingEngine/pendingSSH hold configuration hot-reload swaps that
	// arrived mid-scan; Release applies them before the next scan.
	pendingEngine scanner.Engine
	pendingSSH    *SSHSettings

	// Sink receives structured job log / state events for streaming to
	// browsers (nil disables job logging).
	Sink JobLogSink
	// scanTasks maps a running scan to its primary task id so cancel
	// paths outside RunScan update the real task row instead of a
	// synthetic composite id (composite ids broke uuid columns).
	scanTasks map[string]string
}

// TryClaim marks the executor busy; false means a scan is already running.
func (e *Executor) TryClaim() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active {
		return false
	}
	e.active = true
	return true
}

// Release clears the busy mark and applies any configuration swap that
// was deferred while a scan was in flight.
func (e *Executor) Release() {
	e.mu.Lock()
	e.active = false
	if e.pendingEngine != nil {
		e.Engine = e.pendingEngine
		e.pendingEngine = nil
	}
	if e.pendingSSH != nil {
		e.SSH = *e.pendingSSH
		e.pendingSSH = nil
	}
	e.mu.Unlock()
}

// SetEngine hot-swaps the scan engine (configuration reload). Mid-scan
// swaps are deferred to Release so a running scan sees one engine for its
// whole lifetime.
func (e *Executor) SetEngine(eng scanner.Engine) {
	if eng == nil {
		return
	}
	e.mu.Lock()
	if e.active {
		e.pendingEngine = eng
	} else {
		e.Engine = eng
	}
	e.mu.Unlock()
}

// SetSSH hot-swaps the SSH collector settings (configuration reload);
// deferred while a scan is in flight, like SetEngine.
func (e *Executor) SetSSH(s SSHSettings) {
	e.mu.Lock()
	if e.active {
		p := s
		e.pendingSSH = &p
	} else {
		e.SSH = s
	}
	e.mu.Unlock()
}

// registerTask remembers the primary task id of a running scan.
func (e *Executor) registerTask(scanID, taskID string) {
	e.mu.Lock()
	if e.scanTasks == nil {
		e.scanTasks = map[string]string{}
	}
	e.scanTasks[scanID] = taskID
	e.mu.Unlock()
}

// taskForScan returns the primary task id of a running scan ("" unknown).
func (e *Executor) taskForScan(scanID string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scanTasks[scanID]
}

// forgetScan drops the scan's task registration after completion.
func (e *Executor) forgetScan(scanID string) {
	e.mu.Lock()
	delete(e.scanTasks, scanID)
	e.mu.Unlock()
}

// ClaimAndRun processes queued scans for this executor's site (embedded
// mode; hub/connector agents are pushed their scans instead).
func (e *Executor) ClaimAndRun(ctx context.Context, scannerID string) error {
	if !e.TryClaim() {
		return nil
	}
	defer e.Release()

	scans, err := e.Orch.QueueScans(ctx)
	if err != nil {
		return err
	}
	for i := range scans {
		scan := scans[i]
		if e.SiteID != "" && scan.SiteID != e.SiteID {
			continue
		}
		if err := e.RunScan(ctx, &scan, scannerID); err != nil {
			fjl := &jobLogger{sink: e.Sink, scanID: scan.ID, orgID: scan.OrganizationID, scannerID: scannerID}
			if errors.Is(err, ErrScanCancelled) || ctx.Err() != nil {
				e.Log.Info("scan cancelled", "scan", scan.ID)
				fjl.warn(ctx, domain.SourceExec, "scan cancelled", nil)
				_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanCancelled, "cancelled", scan.Progress)
				if tid := e.taskForScan(scan.ID); tid != "" {
					_ = e.Orch.UpdateTaskState(ctx, tid, domain.TaskCancelled, "cancelled")
				}
				continue
			}
			e.Log.Error("scan failed", "scan", scan.ID, "err", err)
			fjl.err(ctx, domain.SourceExec, "scan failed: "+err.Error(), nil)
			fjl.state(ctx, domain.ScanFailed, "failed", scan.Progress, nil)
			_ = e.Orch.SetScanError(ctx, scan.ID, err.Error())
			_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanFailed, "failed", scan.Progress)
			// Failure rides the same result subject: the server notifies
			// subscribers (correlation skips non-completed states).
			_ = e.Orch.PublishScanResult(ctx, scan.ID, domain.ScanFailed)
		}
	}
	return nil
}

// RunSSHInventory executes the agent-less SSH collection pipeline:
// distro detection + package
// enumeration on each configured host, observations fed to the standard
// inventory + correlation path.
func (e *Executor) RunSSHInventory(ctx context.Context, scan *domain.Scan, scannerID string) error {
	// Target resolution: the per-scan SSH host list (ScanConfig.SSHHosts,
	// set from the scan dialog / API with per-host credentials) wins. When
	// the scan carries none, the scanner falls back to its own SSH
	// collector configuration (connector settings or AEGIS_SSH_SCAN_HOSTS).
	type sshTarget struct {
		host   scanning.SSHHostConfig
		client *scanning.SSHClient
	}
	var targets []sshTarget
	if scan.Config != nil && len(scan.Config.SSHHosts) > 0 {
		for _, h := range scan.Config.SSHHosts {
			port := h.Port
			if port == 0 {
				port = 22
			}
			targets = append(targets, sshTarget{
				host: scanning.SSHHostConfig{Host: h.Host, Port: port, User: h.Username},
				client: &scanning.SSHClient{
					User:            h.Username,
					Password:        h.Password,
					KeyPEM:          []byte(h.KeyPEM),
					Timeout:         e.SSH.Timeout,
					InsecureHostKey: e.SSH.Insecure || scan.Config.SSHInsecureHostKey,
					HostKeyPinned:   h.PinnedKey,
				},
			})
		}
	} else {
		if len(e.SSH.Hosts) == 0 {
			return fmt.Errorf("ssh_inventory profile requested but no SSH hosts configured")
		}
		keyPEM, err := e.resolveSSHKey()
		if err != nil {
			return err
		}
		client := &scanning.SSHClient{
			User:            e.SSH.User,
			Password:        e.SSH.Password,
			KeyPEM:          keyPEM,
			KeyPath:         e.SSH.KeyPath,
			Timeout:         e.SSH.Timeout,
			InsecureHostKey: e.SSH.Insecure,
			HostKeyPinned:   e.SSH.PinnedKey,
		}
		for _, h := range e.SSH.Hosts {
			targets = append(targets, sshTarget{host: h, client: client})
		}
	}
	_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "ssh-collection", 5)
	taskID := ids.New()
	e.registerTask(scan.ID, taskID)
	defer e.forgetScan(scan.ID)
	_ = e.Orch.CreateTask(ctx, &domain.ScanTask{ID: taskID, ScanID: scan.ID, Type: domain.TaskDiscoverHosts, State: domain.TaskRunning, ScannerID: scannerID, Attempt: 1})

	started := time.Now()
	jl := &jobLogger{sink: e.Sink, scanID: scan.ID, orgID: scan.OrganizationID, scannerID: scannerID}
	jl.setTask(taskID)
	jl.state(ctx, domain.ScanRunning, "ssh-collection", 5, nil)
	jl.info(ctx, domain.SourceExec, "SSH inventory collection started", map[string]any{
		"hosts": len(targets),
	})

	stats := domain.ScanStats{Targets: len(targets)}
	for i, t := range targets {
		jl.debug(ctx, domain.SourceSSH, "connecting", map[string]any{
			"host": t.host.Host, "port": t.host.Port, "user": t.host.User,
		})
		if ctx.Err() != nil {
			return ErrScanCancelled
		}
		collector := &scanning.SSHCollector{Runner: t.client, Log: e.Log, Timeout: e.SSH.Timeout}
		res := collector.Collect(ctx, t.host)
		switch {
		case res.OSOK || len(res.Packages) > 0:
			stats.Reachable++
			summary := domain.SSHHostSummary{
				Host: t.host.Host, Port: t.host.Port, User: t.host.User,
				OSFamily: res.OSFamily, OSName: res.OSName, OSVersion: res.OSVersion, OSOK: res.OSOK,
				PackageCount: len(res.Packages), Commands: res.Commands, DurationMS: res.DurationMS,
			}
			stats.SSHHosts = append(stats.SSHHosts, summary)
			recordCollectionLog(ctx, e, scan, taskID, summary)
			jl.info(ctx, domain.SourceSSH, "host collected", map[string]any{
				"host": t.host.Host, "user": t.host.User,
				"os_family": res.OSFamily, "os_name": res.OSName, "os_version": res.OSVersion,
				"os_detected": res.OSOK, "packages": len(res.Packages),
				"commands": len(res.Commands), "duration_ms": res.DurationMS,
			})
			if len(res.Packages) > 0 {
				jl.debug(ctx, domain.SourceSSH, "package sample", map[string]any{
					"host":  t.host.Host,
					"first": packageSample(res.Packages, 10),
				})
			}
			obs := &domain.Observation{
				ScanID: scan.ID, TaskID: taskID, SiteID: scan.SiteID,
				OrganizationID: scan.OrganizationID, Target: t.host.Host,
				ObservationType: "host_up", Timestamp: time.Now().UTC(),
				Source: domain.Source("ssh_scan"), Confidence: 0.9,
				Normalized: map[string]any{"ip": t.host.Host},
			}
			if res.OSOK {
				obs.Normalized["os_family"] = res.OSFamily
				obs.Normalized["os_name"] = res.OSName
				obs.Normalized["os_version"] = res.OSVersion
			}
			if err := e.Orch.RecordObservation(ctx, obs); err != nil {
				e.Log.Warn("ssh host_up observation failed", "host", t.host.Host, "err", err)
			}
			for _, pkg := range res.Packages {
				err := e.Orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, TaskID: taskID, SiteID: scan.SiteID,
					OrganizationID: scan.OrganizationID, Target: t.host.Host,
					ObservationType: "software", Timestamp: time.Now().UTC(),
					Source: domain.Source("ssh_scan"), Confidence: 0.9,
					Normalized: map[string]any{
						"name": pkg.Name, "version": pkg.Version,
						"ecosystem": ecosystemFor(res.OSFamily), "pkg_source": "ssh_scan",
					},
				})
				if err != nil {
					e.Log.Warn("ssh software observation failed", "host", t.host.Host, "pkg", pkg.Name, "err", err)
					continue
				}
				stats.PackagesCollected++
			}
		default:
			stats.Unreachable++
			summary := domain.SSHHostSummary{
				Host: t.host.Host, Port: t.host.Port, User: t.host.User,
				Commands: res.Commands, DurationMS: res.DurationMS, Error: res.Err,
			}
			stats.SSHHosts = append(stats.SSHHosts, summary)
			recordCollectionLog(ctx, e, scan, taskID, summary)
			jl.warn(ctx, domain.SourceSSH, "host unreachable", map[string]any{
				"host": t.host.Host, "port": t.host.Port, "user": t.host.User,
				"error": res.Err, "duration_ms": res.DurationMS,
			})
			_ = e.Orch.RecordObservation(ctx, &domain.Observation{
				ScanID: scan.ID, TaskID: taskID, SiteID: scan.SiteID,
				OrganizationID: scan.OrganizationID, Target: t.host.Host,
				ObservationType: "host_down", Timestamp: time.Now().UTC(),
				Source: domain.Source("ssh_scan"), Confidence: 0.5,
				Error: res.Err,
			})
			if res.Err != "" {
				e.Log.Warn("ssh host unreachable", "host", t.host.Host, "err", res.Err)
			}
		}
		_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "ssh-collection", 5+float64(i+1)/float64(len(targets))*90)
		jl.state(ctx, domain.ScanRunning, "ssh-collection", 5+float64(i+1)/float64(len(targets))*90, &stats)
	}
	_ = e.Orch.UpdateScanStats(ctx, scan.ID, stats)
	_ = e.Orch.UpdateTaskState(ctx, taskID, domain.TaskSucceeded, "succeeded")
	_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanCompleted, "completed", 100)
	_ = e.Orch.PublishScanResult(ctx, scan.ID, domain.ScanCompleted)
	jl.state(ctx, domain.ScanCompleted, "completed", 100, &stats)
	jl.info(ctx, domain.SourceExec, "SSH inventory collection completed", map[string]any{
		"reachable": stats.Reachable, "unreachable": stats.Unreachable,
		"packages": stats.PackagesCollected, "duration_ms": time.Since(started).Milliseconds(),
	})
	return nil
}

// packageSample renders the first N packages for a debug log line.
func packageSample(pkgs []scanning.SSHPackage, n int) []string {
	out := make([]string, 0, n)
	for i, p := range pkgs {
		if i >= n {
			break
		}
		out = append(out, p.Name+" "+p.Version)
	}
	return out
}

// recordCollectionLog persists the per-host SSH collection record
// (command log, OS fingerprint, package count, error) as a
// ssh_collection observation: the audit trail behind "what exactly was
// scanned over SSH", queryable from scan_observations forever.
func recordCollectionLog(ctx context.Context, e *Executor, scan *domain.Scan, taskID string, summary domain.SSHHostSummary) {
	norm := map[string]any{}
	if b, err := json.Marshal(summary); err == nil {
		_ = json.Unmarshal(b, &norm)
	}
	_ = e.Orch.RecordObservation(ctx, &domain.Observation{
		ScanID: scan.ID, TaskID: taskID, SiteID: scan.SiteID,
		OrganizationID: scan.OrganizationID, Target: summary.Host,
		ObservationType: "ssh_collection", Timestamp: time.Now().UTC(),
		Source: domain.Source("ssh_scan"), Confidence: 0.9,
		Normalized: norm,
	})
}

// resolveSSHKey loads and pre-validates the configured private key once,
// before any host is dialed. An unusable key must not silently kill every
// host connection: when password auth is also configured, the broken or
// unreadable key is dropped with a loud warning (password takes over);
// when the key is the only credential, the scan fails fast with one
// actionable error instead of N identical per-host failures.
func (e *Executor) resolveSSHKey() ([]byte, error) {
	if e.SSH.KeyPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(e.SSH.KeyPath) // #nosec G304 -- admin-configured path
	if err != nil {
		if e.SSH.Password == "" {
			return nil, fmt.Errorf("ssh key: %w", err)
		}
		if e.Log != nil {
			e.Log.Warn("configured ssh key cannot be read; password auth will be used",
				"path", e.SSH.KeyPath, "err", err)
		}
		return nil, nil
	}
	if _, perr := ssh.ParsePrivateKey(data); perr != nil {
		if e.SSH.Password == "" {
			return nil, scanning.DescribeKeyError(e.SSH.KeyPath, perr)
		}
		if e.Log != nil {
			e.Log.Warn("configured ssh key is not a usable private key; password auth will be used",
				"path", e.SSH.KeyPath, "err", perr)
		}
		return nil, nil
	}
	return data, nil
}

// ecosystemFor maps a canonical distro family onto the software-inventory
// ecosystem its packages are recorded under.
func ecosystemFor(family string) string {
	switch family {
	case fingerprinting.DistroDebian, fingerprinting.DistroUbuntu:
		return fingerprinting.PkgEcoDebian
	case fingerprinting.DistroAlpine:
		return fingerprinting.PkgEcoAlpine
	default:
		return fingerprinting.PkgEcoRPM
	}
}
