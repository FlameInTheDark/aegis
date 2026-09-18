package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/ids"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/hub"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Orch is the orchestrator surface the scan executor needs. Two adapters
// implement it: localOrch (embedded mode: direct DB via scanning.Orchestrator)
// and remoteOrch (agent mode: everything flows to the hub over gRPC, so a
// remote scanner never touches Postgres/NATS).
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

// ---------------------------------------------------------------------------
// Local adapter (embedded/compose scanner)

type localOrch struct{ o *scanning.Orchestrator }

func (l localOrch) RecordObservation(ctx context.Context, obs *domain.Observation) error {
	return l.o.RecordObservation(ctx, obs)
}

func (l localOrch) ResolveProfile(ctx context.Context, orgID string, p domain.ScanProfile) (*domain.ProfileDefinition, error) {
	return l.o.ResolveProfile(ctx, orgID, p)
}

func (l localOrch) Scope(ctx context.Context, scanID string) (*domain.ScanScope, error) {
	return l.o.Scans.Scope(ctx, scanID)
}

func (l localOrch) ScanByID(ctx context.Context, orgID, scanID string) (*domain.Scan, error) {
	return l.o.Scans.ByID(ctx, orgID, scanID)
}

func (l localOrch) QueueScans(ctx context.Context) ([]domain.Scan, error) {
	scans, _, err := l.o.Scans.List(ctx, pg.ScanListFilter{OrgID: "", State: string(domain.ScanQueued), Limit: 5})
	return scans, err
}

func (l localOrch) UpdateScanState(ctx context.Context, scanID string, state domain.ScanState, phase string, progress float64) error {
	return l.o.Scans.UpdateState(ctx, scanID, state, phase, progress)
}

func (l localOrch) UpdateScanStats(ctx context.Context, scanID string, stats domain.ScanStats) error {
	return l.o.Scans.UpdateStats(ctx, scanID, stats)
}

func (l localOrch) SetScanError(ctx context.Context, scanID, msg string) error {
	return l.o.Scans.SetError(ctx, scanID, msg)
}

func (l localOrch) CreateTask(ctx context.Context, t *domain.ScanTask) error {
	return l.o.Tasks.Create(ctx, t)
}

func (l localOrch) UpdateTaskState(ctx context.Context, taskID string, state domain.TaskState, msg string) error {
	return l.o.Tasks.UpdateState(ctx, taskID, state, msg)
}

func (l localOrch) PublishScanResult(ctx context.Context, scanID string, state domain.ScanState) error {
	if l.o.Bus == nil {
		return nil
	}
	evt, _ := json.Marshal(map[string]any{"scan_id": scanID, "state": string(state)})
	return l.o.Bus.Publish(ctx, scanning.SubjectScanResult, evt)
}

// ---------------------------------------------------------------------------
// Remote adapter (agent mode: gRPC to the hub)

type remoteOrch struct {
	conn      *grpc.ClientConn
	token     string
	scannerID string
	log       *slog.Logger
	scopes    map[string][]string // scan_id -> targets (from the job envelope)
}

const hubBase = "/" + hub.ServiceName + "/"

func (r *remoteOrch) ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-scanner-token", r.token)
}

func (r *remoteOrch) invoke(ctx context.Context, method string, req, out any) error {
	return r.conn.Invoke(r.ctx(ctx), hubBase+method, req, out)
}

type ack struct {
	OK bool `json:"ok"`
}

func (r *remoteOrch) report(ctx context.Context, rep *hub.Report) {
	rep.ScannerID = r.scannerID
	var a ack
	if err := r.invoke(ctx, "Report", rep, &a); err != nil {
		r.log.Warn("agent: report failed", "scan", rep.ScanID, "err", err)
	}
}

func (r *remoteOrch) RecordObservation(ctx context.Context, obs *domain.Observation) error {
	if obs.ID == "" {
		obs.ID = ids.New()
	}
	r.report(ctx, &hub.Report{ScanID: obs.ScanID, Observations: []domain.Observation{*obs}})
	return nil
}

func (r *remoteOrch) ResolveProfile(_ context.Context, _ string, p domain.ScanProfile) (*domain.ProfileDefinition, error) {
	// Custom preset args already ride inside the scan config from the hub
	// envelope; built-ins resolve statically inside runScan.
	if def, ok := domain.Profiles[p]; ok {
		return &def, nil
	}
	return nil, fmt.Errorf("unknown profile %q", p)
}

func (r *remoteOrch) Scope(_ context.Context, scanID string) (*domain.ScanScope, error) {
	cidrs := r.scopes[scanID]
	if cidrs == nil {
		cidrs = []string{}
	}
	return &domain.ScanScope{ScanID: scanID, CIDRs: cidrs}, nil
}

func (r *remoteOrch) ScanByID(ctx context.Context, _ string, scanID string) (*domain.Scan, error) {
	var view hub.ScanView
	if err := r.invoke(ctx, "GetScan", hub.GetScanReq{ScanID: scanID}, &view); err != nil {
		return nil, err
	}
	return &domain.Scan{ID: scanID, KillSwitch: view.KillSwitch, State: domain.ScanState(view.State)}, nil
}

func (r *remoteOrch) QueueScans(context.Context) ([]domain.Scan, error) {
	return nil, nil // agent mode: jobs are pushed by the hub
}

func (r *remoteOrch) UpdateScanState(ctx context.Context, scanID string, state domain.ScanState, phase string, progress float64) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanState: string(state), Phase: phase, Progress: &progress})
	return nil
}

func (r *remoteOrch) UpdateScanStats(ctx context.Context, scanID string, stats domain.ScanStats) error {
	r.report(ctx, &hub.Report{ScanID: scanID, Stats: &stats})
	return nil
}

func (r *remoteOrch) SetScanError(ctx context.Context, scanID, msg string) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanError: msg})
	return nil
}

func (r *remoteOrch) CreateTask(ctx context.Context, t *domain.ScanTask) error {
	r.report(ctx, &hub.Report{ScanID: t.ScanID, TaskID: t.ID, TaskState: string(domain.TaskRunning)})
	return nil
}

func (r *remoteOrch) UpdateTaskState(ctx context.Context, taskID string, state domain.TaskState, msg string) error {
	r.report(ctx, &hub.Report{TaskID: taskID, TaskState: string(state), ScanError: msg})
	return nil
}

func (r *remoteOrch) PublishScanResult(ctx context.Context, scanID string, state domain.ScanState) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanState: string(state)})
	return nil
}

// runAgent connects to the hub and executes pushed scans with the same
// executor pipeline the embedded scanner uses.
func runAgent(ctx context.Context, e *executor, hubAddr, token string) error {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient(hubAddr, opts...)
	if err != nil {
		return fmt.Errorf("agent dial %s: %w", hubAddr, err)
	}
	defer conn.Close()
	ro := &remoteOrch{conn: conn, token: token, log: e.log, scopes: map[string][]string{}}
	e.orch = ro

	// Register: enrolls this process against the enrollment token.
	var reg hub.RegisterResp
	regReq := hub.RegisterReq{
		Name: e.cfg.Scanner.ScannerName, Token: token,
		Version: scannerVersion + "/" + e.engine.Name(), Capabilities: e.cfg.Scanner.Capabilities,
	}
	if err := ro.invoke(ctx, "Register", regReq, &reg); err != nil {
		return fmt.Errorf("agent register: %w", err)
	}
	ro.scannerID = reg.ScannerID
	e.log.Info("agent registered with hub", "scanner", reg.ScannerID, "hub", hubAddr)

	// Heartbeat keeps the scanners row live while idle.
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				var a ack
				_ = ro.invoke(ctx, "Heartbeat", hub.JobsReq{}, &a)
			}
		}
	}()

	// Jobs stream; reconnect with backoff so the agent survives hub restarts.
	backoff := 3 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		streamCtx, cancel := context.WithCancel(ctx)
		err := e.jobsLoop(streamCtx, ro)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		e.log.Warn("agent jobs stream ended; reconnecting", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

// jobsLoop opens the server-stream and runs envelopes sequentially (the
// embedded scanner also runs one scan at a time).
func (e *executor) jobsLoop(ctx context.Context, ro *remoteOrch) error {
	sd := &grpc.StreamDesc{StreamName: "Jobs", ServerStreams: true}
	cs, err := ro.conn.NewStream(ro.ctx(ctx), sd, hubBase+"Jobs")
	if err != nil {
		return err
	}
	if err := cs.SendMsg(&hub.JobsReq{}); err != nil {
		return err
	}
	if err := cs.CloseSend(); err != nil {
		return err
	}
	for {
		env := &hub.Envelope{}
		if err := cs.RecvMsg(env); err != nil {
			return err
		}
		if env.Envelope == "ping" || env.ScanID == "" {
			continue
		}
		e.mu.Lock()
		if e.active {
			e.mu.Unlock()
			e.log.Warn("agent busy; scan stays queued for replay", "scan", env.ScanID)
			continue
		}
		e.active = true
		e.mu.Unlock()
		var scan domain.Scan
		if err := json.Unmarshal(env.Scan, &scan); err != nil {
			e.log.Error("agent: bad scan envelope", "scan", env.ScanID, "err", err)
			continue
		}
		ro.scopes[scan.ID] = env.CIDRs
		e.log.Info("agent executing scan", "scan", scan.ID, "profile", string(scan.Profile), "targets", len(env.CIDRs))
		if err := e.runScan(ctx, &scan, ro.scannerID); err != nil {
			if errors.Is(err, errScanCancelled) || ctx.Err() != nil {
				_ = ro.UpdateScanState(ctx, scan.ID, domain.ScanCancelled, "cancelled", 0)
				_ = ro.UpdateTaskState(ctx, scan.ID+"-discover", domain.TaskCancelled, "cancelled")
			} else {
				e.log.Error("agent scan failed", "scan", scan.ID, "err", err)
				_ = ro.SetScanError(ctx, scan.ID, err.Error())
				_ = ro.UpdateScanState(ctx, scan.ID, domain.ScanFailed, "failed", 0)
			}
		}
		ro.scopes[scan.ID] = nil
		e.mu.Lock()
		e.active = false
		e.mu.Unlock()
	}
}
