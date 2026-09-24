package scanexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/hub"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// HubAuth selects the credential kind presented to the scanner hub:
// the legacy enrollment token, or the unified connector credentials
// (a connector of kind=scanner). Exactly one path is populated.
type HubAuth struct {
	ScannerToken    string
	ConnectorID     string
	ConnectorSecret string
}

func (a HubAuth) ctx(ctx context.Context) context.Context {
	if a.ScannerToken != "" {
		return metadata.AppendToOutgoingContext(ctx, "x-scanner-token", a.ScannerToken)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "x-aegis-connector-id", a.ConnectorID)
	return metadata.AppendToOutgoingContext(ctx, "x-aegis-connector-secret", a.ConnectorSecret)
}

// RemoteOrch is the hub-adapter: every orchestrator call flows to the hub
// over gRPC (JSON codec), so a remote scanner never touches Postgres/NATS.
type RemoteOrch struct {
	conn      *grpc.ClientConn
	auth      HubAuth
	scannerID string
	log       *slog.Logger
	scopes    map[string][]string // scan_id -> targets (from the job envelope)
	// Job log batcher: engine stderr and phase events queue here and
	// flush as Report.Logs (one unary report per batch, 300ms).
	logCh   chan *domain.JobLogEvent
	logStop chan struct{}
	logDone chan struct{}
}

const hubBase = "/" + hub.ServiceName + "/"

// NewRemoteOrch dials the hub. transport may be nil (plaintext — the
// compose/demo default) or a TLS credentials set built by the caller
// binary (which owns the root pool and the tls:// address grammar).
func NewRemoteOrch(hubAddr string, auth HubAuth, transport credentials.TransportCredentials, log *slog.Logger) (*RemoteOrch, error) {
	if transport == nil {
		transport = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(hubAddr, []grpc.DialOption{grpc.WithTransportCredentials(transport)}...)
	if err != nil {
		return nil, fmt.Errorf("hub dial %s: %w", hubAddr, err)
	}
	ro := &RemoteOrch{conn: conn, auth: auth, log: log, scopes: map[string][]string{},
		logCh:   make(chan *domain.JobLogEvent, 512),
		logStop: make(chan struct{}),
		logDone: make(chan struct{}),
	}
	go ro.flushJobLogs()
	return ro, nil
}

// Close flushes pending job log events and releases the gRPC connection.
func (r *RemoteOrch) Close() {
	close(r.logStop)
	<-r.logDone
	r.conn.Close()
}

// flushJobLogs batches queued events into hub reports.
func (r *RemoteOrch) flushJobLogs() {
	defer close(r.logDone)
	batch := make([]domain.JobLogEvent, 0, 32)
	send := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r.report(ctx, &hub.Report{ScanID: batch[0].ScanID, Logs: batch})
		batch = make([]domain.JobLogEvent, 0, 32)
	}
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case e := <-r.logCh:
			batch = append(batch, *e)
			if len(batch) >= 32 {
				send()
			}
		case <-t.C:
			send()
		case <-r.logStop:
			for {
				select {
				case e := <-r.logCh:
					batch = append(batch, *e)
				default:
					send()
					return
				}
			}
		}
	}
}

// ScannerID returns the identity assigned by Register.
func (r *RemoteOrch) ScannerID() string { return r.scannerID }

func (r *RemoteOrch) ctx(ctx context.Context) context.Context { return r.auth.ctx(ctx) }

func (r *RemoteOrch) invoke(ctx context.Context, method string, req, out any) error {
	// The hub speaks its registered JSON codec (hub.jsonCodec); without the
	// explicit content subtype gRPC defaults to proto marshaling and every
	// call fails with "message is hub.X, want proto.Message".
	return r.conn.Invoke(r.ctx(ctx), hubBase+method, req, out, grpc.CallContentSubtype("json"))
}

type ack struct {
	OK bool `json:"ok"`
}

func (r *RemoteOrch) report(ctx context.Context, rep *hub.Report) {
	rep.ScannerID = r.scannerID
	var a ack
	if err := r.invoke(ctx, "Report", rep, &a); err != nil {
		r.log.Warn("hub: report failed", "scan", rep.ScanID, "err", err)
	}
}

// EmitJobLog queues one structured job log event for the hub.
func (r *RemoteOrch) EmitJobLog(_ context.Context, e *domain.JobLogEvent) {
	if e == nil || e.ScanID == "" {
		return
	}
	e.Normalize()
	select {
	case r.logCh <- e:
	default:
		// Channel full: drop instead of blocking the scan pipeline.
	}
}

// EmitState is a no-op for the hub path: the executor reports every
// lifecycle transition through Orch.UpdateScanState, and the hub
// broadcasts those to WebSocket subscribers on apply.
func (r *RemoteOrch) EmitState(context.Context, *domain.ScanStateEvent) {}

func (r *RemoteOrch) RecordObservation(ctx context.Context, obs *domain.Observation) error {
	if obs.ID == "" {
		obs.ID = ids.New()
	}
	r.report(ctx, &hub.Report{ScanID: obs.ScanID, Observations: []domain.Observation{*obs}})
	return nil
}

func (r *RemoteOrch) ResolveProfile(_ context.Context, _ string, p domain.ScanProfile) (*domain.ProfileDefinition, error) {
	// Custom preset args already ride inside the scan config from the hub
	// envelope; built-ins resolve statically inside RunScan.
	if def, ok := domain.Profiles[p]; ok {
		return &def, nil
	}
	return nil, fmt.Errorf("unknown profile %q", p)
}

func (r *RemoteOrch) Scope(_ context.Context, scanID string) (*domain.ScanScope, error) {
	cidrs := r.scopes[scanID]
	if cidrs == nil {
		cidrs = []string{}
	}
	return &domain.ScanScope{ScanID: scanID, CIDRs: cidrs}, nil
}

func (r *RemoteOrch) ScanByID(ctx context.Context, _ string, scanID string) (*domain.Scan, error) {
	var view hub.ScanView
	if err := r.invoke(ctx, "GetScan", hub.GetScanReq{ScanID: scanID}, &view); err != nil {
		return nil, err
	}
	return &domain.Scan{ID: scanID, KillSwitch: view.KillSwitch, State: domain.ScanState(view.State)}, nil
}

func (r *RemoteOrch) QueueScans(context.Context) ([]domain.Scan, error) {
	return nil, nil // hub mode: jobs are pushed by the hub
}

func (r *RemoteOrch) UpdateScanState(ctx context.Context, scanID string, state domain.ScanState, phase string, progress float64) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanState: string(state), Phase: phase, Progress: &progress})
	return nil
}

func (r *RemoteOrch) UpdateScanStats(ctx context.Context, scanID string, stats domain.ScanStats) error {
	r.report(ctx, &hub.Report{ScanID: scanID, Stats: &stats})
	return nil
}

func (r *RemoteOrch) SetScanError(ctx context.Context, scanID, msg string) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanError: msg})
	return nil
}

func (r *RemoteOrch) CreateTask(ctx context.Context, t *domain.ScanTask) error {
	r.report(ctx, &hub.Report{ScanID: t.ScanID, TaskID: t.ID, TaskState: string(domain.TaskRunning)})
	return nil
}

func (r *RemoteOrch) UpdateTaskState(ctx context.Context, taskID string, state domain.TaskState, msg string) error {
	r.report(ctx, &hub.Report{TaskID: taskID, TaskState: string(state), ScanError: msg})
	return nil
}

func (r *RemoteOrch) PublishScanResult(ctx context.Context, scanID string, state domain.ScanState) error {
	r.report(ctx, &hub.Report{ScanID: scanID, ScanState: string(state)})
	return nil
}

// AgentOptions parameterizes RunAgent.
type AgentOptions struct {
	HubAddr string
	Auth    HubAuth
	// Transport is optional (nil = plaintext, the compose/demo default);
	// binaries that speak tls:// endpoints pass their credentials set here.
	Transport    credentials.TransportCredentials
	Name         string
	Version      string
	Capabilities []string
}

// RunAgent connects to the hub, registers and executes pushed scans with
// the shared executor pipeline; it reconnects with backoff so the agent
// survives hub restarts, and keeps liveness fresh with hub heartbeats.
func RunAgent(ctx context.Context, e *Executor, opts AgentOptions) error {
	ro, err := NewRemoteOrch(opts.HubAddr, opts.Auth, opts.Transport, e.Log)
	if err != nil {
		return err
	}
	defer ro.Close()
	e.Orch = ro
	e.Sink = ro

	// Register: enrolls this process against the token (legacy agents) or
	// the connector credentials in the metadata (connector scanners).
	var reg hub.RegisterResp
	regReq := hub.RegisterReq{
		Name: opts.Name, Version: opts.Version, Capabilities: opts.Capabilities,
	}
	if opts.Auth.ScannerToken != "" {
		regReq.Token = opts.Auth.ScannerToken
	}
	if err := ro.invoke(ctx, "Register", regReq, &reg); err != nil {
		return fmt.Errorf("hub register: %w", err)
	}
	ro.scannerID = reg.ScannerID
	e.Log.Info("registered with hub", "scanner", reg.ScannerID, "hub", opts.HubAddr)

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
		err := e.JobsLoop(streamCtx, ro)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		e.Log.Warn("hub jobs stream ended; reconnecting", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

// JobsLoop opens the server-stream and runs envelopes sequentially (the
// embedded scanner also runs one scan at a time).
func (e *Executor) JobsLoop(ctx context.Context, ro *RemoteOrch) error {
	sd := &grpc.StreamDesc{StreamName: "Jobs", ServerStreams: true}
	cs, err := ro.conn.NewStream(ro.ctx(ctx), sd, hubBase+"Jobs", grpc.CallContentSubtype("json"))
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
		if !e.TryClaim() {
			e.Log.Warn("executor busy; scan stays queued for replay", "scan", env.ScanID)
			continue
		}
		var scan domain.Scan
		if err := json.Unmarshal(env.Scan, &scan); err != nil {
			e.Log.Error("bad scan envelope", "scan", env.ScanID, "err", err)
			e.Release()
			continue
		}
		ro.scopes[scan.ID] = env.CIDRs
		e.Log.Info("executing scan", "scan", scan.ID, "profile", string(scan.Profile), "targets", len(env.CIDRs))
		if err := e.RunScan(ctx, &scan, ro.scannerID); err != nil {
			fjl := &jobLogger{sink: e.Sink, scanID: scan.ID, orgID: scan.OrganizationID, scannerID: ro.scannerID}
			if errors.Is(err, ErrScanCancelled) || ctx.Err() != nil {
				fjl.warn(ctx, domain.SourceExec, "scan cancelled", nil)
				_ = ro.UpdateScanState(ctx, scan.ID, domain.ScanCancelled, "cancelled", 0)
				if tid := e.taskForScan(scan.ID); tid != "" {
					_ = ro.UpdateTaskState(ctx, tid, domain.TaskCancelled, "cancelled")
				}
			} else {
				e.Log.Error("scan failed", "scan", scan.ID, "err", err)
				fjl.err(ctx, domain.SourceExec, "scan failed: "+err.Error(), nil)
				fjl.state(ctx, domain.ScanFailed, "failed", 0, nil)
				_ = ro.SetScanError(ctx, scan.ID, err.Error())
				_ = ro.UpdateScanState(ctx, scan.ID, domain.ScanFailed, "failed", 0)
				_ = ro.PublishScanResult(ctx, scan.ID, domain.ScanFailed)
			}
		}
		ro.scopes[scan.ID] = nil
		e.Release()
	}
}
