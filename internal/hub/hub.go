// Package hub implements the gRPC scanner hub (spec §5.3/§69): remote
// scanners installed on physical hosts dial the server over gRPC and run
// scans exactly like the compose-embedded scanner, without needing direct
// Postgres/NATS access.
//
// Wire format: gRPC (HTTP/2 multiplexed streams) with a JSON codec — the
// only clients are Aegis scanner binaries, so a proto toolchain is skipped
// deliberately; the transport semantics (unary + server-streaming RPCs,
// per-call token auth) are the contract.
//
// Protocol (service "aegis.scanner.v1.Hub"):
//
//	Register(scanner_name, token, version, capabilities) -> scanner_id
//	  Enrolls the dialing scanner; token is the enrollment secret issued
//	  by POST /api/v1/scanners/enroll (stored hashed).
//	Jobs(stream) <- Envelope
//	  Server-stream: queued scans for this scanner's site are pushed as
//	  full scan context (the agent has NO database access); a ping every
//	  25s keeps the stream and liveness observable.
//	Report(...) -> Ack
//	  Unary: observations, scan/task state updates, scan-completion events
//	  flow back; the hub applies them through the real orchestrator.
//	GetScan(scan_id) -> ScanView
//	  Kill-switch/state readback so cancellation reaches remote probes.
package hub

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const ServiceName = "aegis.scanner.v1.Hub"

// Envelope is one dispatched job: the full scan context (an agent has no DB).
type Envelope struct {
	ScanID   string          `json:"scan_id"`
	Kind     string          `json:"kind"` // task kind (discover)
	Scan     json.RawMessage `json:"scan"` // domain.Scan JSON
	CIDRs    []string        `json:"cidrs"`
	Envelope string          `json:"-"` // "ping" keepalives
}

// Report is the agent -> hub result message. Everything optional; the hub
// applies whatever is present.
type Report struct {
	ScannerID    string               `json:"scanner_id,omitempty"`
	ScanID       string               `json:"scan_id,omitempty"`
	TaskID       string               `json:"task_id,omitempty"`
	Observations []domain.Observation `json:"observations,omitempty"`
	ScanState    string               `json:"scan_state,omitempty"`
	Phase        string               `json:"phase,omitempty"`
	Progress     *float64             `json:"progress,omitempty"`
	Stats        *domain.ScanStats    `json:"stats,omitempty"`
	TaskState    string               `json:"task_state,omitempty"`
	ScanError    string               `json:"scan_error,omitempty"`
}

// ScanView is the kill-switch readback for agent-side cancellation.
type ScanView struct {
	KillSwitch bool   `json:"kill_switch"`
	State      string `json:"state"`
}

// Orch applies reports to the inventory (the server-side orchestrator).
type Orch interface {
	RecordObservation(ctx context.Context, obs *domain.Observation) error
}

// BusPublisher publishes the scan-result event that triggers server-side
// CVE correlation when an agent reports a completed scan.
type BusPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// Hub serves remote scanners.
type Hub struct {
	Scans    *postgres.ScanRepo
	Tasks    *postgres.TaskRepo
	Scanners *postgres.ScannerRepo
	Orch     Orch
	Bus      BusPublisher
	Log      *slog.Logger

	mu      sync.Mutex
	live    map[string]*scanStream
	pending map[string][]*Envelope
}

// New builds a hub.
func New(scans *postgres.ScanRepo, tasks *postgres.TaskRepo, scanners *postgres.ScannerRepo, orch Orch, bus BusPublisher, log *slog.Logger) *Hub {
	return &Hub{Scans: scans, Tasks: tasks, Scanners: scanners, Orch: orch, Bus: bus, Log: log,
		live: map[string]*scanStream{}, pending: map[string][]*Envelope{}}
}

// scanStream is one connected agent.
type scanStream struct {
	id   string
	ch   chan *Envelope
	done chan struct{}
	once sync.Once
}

func (s *scanStream) push(e *Envelope) bool {
	select {
	case s.ch <- e:
		return true
	case <-s.done:
		return false
	default:
		return false // backpressure: never block the dispatcher
	}
}

func (s *scanStream) stop() { s.once.Do(func() { close(s.done) }) }

// Connected reports whether the scanner currently has a live stream.
func (h *Hub) Connected(scannerID string) bool {
	if h == nil || scannerID == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.live[scannerID]
	return ok
}

// Dispatch pushes a scan to a connected agent; scans for offline agents
// stay queued and are pushed when the agent reconnects.
func (h *Hub) Dispatch(scan *domain.Scan, cidrs []string) {
	scanJSON, _ := json.Marshal(scan)
	env := &Envelope{ScanID: scan.ID, Kind: string(domain.TaskDiscoverHosts), Scan: scanJSON, CIDRs: cidrs}
	h.mu.Lock()
	defer h.mu.Unlock()
	if st, ok := h.live[scan.ScannerID]; ok && st.push(env) {
		return
	}
	h.Log.Warn("hub: scanner not connected; scan stays queued for replay", "scanner", scan.ScannerID, "scan", scan.ID)
}

// Register registers the hub service on a grpc server.
func (h *Hub) Register(s *grpc.Server) { s.RegisterService(&hubServiceDesc, h) }

var hubServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*hubServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Register", Handler: mh((*Hub).callRegister)},
		{MethodName: "Report", Handler: mh((*Hub).callReport)},
		{MethodName: "Heartbeat", Handler: mh((*Hub).callHeartbeat)},
		{MethodName: "GetScan", Handler: mh((*Hub).callGetScan)},
	},
	Streams: []grpc.StreamDesc{
		{StreamName: "Jobs", Handler: func(srv any, stream grpc.ServerStream) error { return srv.(*Hub).jobsHandler(srv, stream) }, ServerStreams: true},
	},
}

// mh adapts a hub method to grpc.MethodHandler (raw []byte in/out via the
// JSON codec).
func mh(fn func(h *Hub, ctx context.Context, req []byte) ([]byte, error)) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var in []byte
		_ = dec(&in)
		out, err := fn(srv.(*Hub), ctx, in)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
}

// hubServer is the marker type grpc.ServiceDesc requires.
type hubServer interface{ hubMarker() }

func (h *Hub) hubMarker() {}

// jsonCodec lets request/response structs travel as JSON without proto
// generation; registered globally as "json".
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }
func (jsonCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return json.Marshal(v)
}
func (jsonCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = append((*b)[:0], data...)
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

func init() { encoding.RegisterCodec(jsonCodec{}) }

// auth resolves the scanner from the per-call token.
func (h *Hub) auth(ctx context.Context) (*domain.Scanner, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	toks := md.Get("x-scanner-token")
	if len(toks) == 0 || toks[0] == "" {
		return nil, status.Error(codes.Unauthenticated, "missing scanner token")
	}
	sc, err := h.Scanners.ByTokenHash(ctx, HashToken(toks[0]))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unknown scanner token")
	}
	return sc, nil
}

// HashToken derives the stored form of an enrollment token (SHA-256 hex).
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return fmt.Sprintf("%x", sum)
}

// ---------------------------------------------------------------------------
// RPC implementations

type RegisterReq struct {
	Name         string   `json:"name"`
	Token        string   `json:"token"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type RegisterResp struct {
	ScannerID string `json:"scanner_id"`
}

// JobsReq is the (empty) open-stream request; auth rides in metadata.
type JobsReq struct{}

func (h *Hub) callRegister(ctx context.Context, raw []byte) ([]byte, error) {
	var req RegisterReq
	if err := json.Unmarshal(raw, &req); err != nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token required")
	}
	sc, err := h.Scanners.ByTokenHash(ctx, HashToken(req.Token))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unknown enrollment token")
	}
	if req.Name != "" {
		sc.Name = req.Name
	}
	if req.Version != "" {
		sc.Version = req.Version
	}
	if len(req.Capabilities) > 0 {
		sc.Capabilities = req.Capabilities
	}
	sc.Transport = "grpc"
	sc.Health = "healthy"
	sc.LastSeen = time.Now().UTC()
	if err := h.Scanners.UpdateAgent(ctx, sc); err != nil {
		return nil, status.Error(codes.Internal, "could not update scanner")
	}
	out, _ := json.Marshal(RegisterResp{ScannerID: sc.ID})
	return out, nil
}

func (h *Hub) jobsHandler(srv any, stream grpc.ServerStream) error {
	hn := srv.(*Hub)
	ctx := stream.Context()
	sc, err := hn.auth(ctx)
	if err != nil {
		return err
	}
	st := &scanStream{id: sc.ID, ch: make(chan *Envelope, 16), done: make(chan struct{})}
	hn.mu.Lock()
	if old, ok := hn.live[sc.ID]; ok {
		old.stop()
	}
	hn.live[sc.ID] = st
	queued := hn.pending[sc.ID]
	delete(hn.pending, sc.ID)
	hn.mu.Unlock()
	defer func() {
		hn.mu.Lock()
		if cur, ok := hn.live[sc.ID]; ok && cur == st {
			delete(hn.live, sc.ID)
		}
		var rest []*Envelope
		for {
			select {
			case e := <-st.ch:
				rest = append(rest, e)
				continue
			default:
			}
			break
		}
		if len(rest) > 0 {
			hn.pending[sc.ID] = append(hn.pending[sc.ID], rest...)
		}
		hn.mu.Unlock()
		st.stop()
	}()
	hn.Log.Info("hub: scanner connected", "scanner", sc.ID, "name", sc.Name)

	for _, e := range queued {
		if !st.push(e) {
			return nil
		}
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	seen := time.NewTicker(60 * time.Second)
	defer seen.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-st.done:
			return nil
		case e := <-st.ch:
			if err := stream.SendMsg(e); err != nil {
				return err
			}
		case <-ping.C:
			if err := stream.SendMsg(&Envelope{Envelope: "ping"}); err != nil {
				return err
			}
		case <-seen.C:
			_ = hn.Scanners.Touch(ctx, sc.ID)
		}
	}
}

func (h *Hub) callReport(ctx context.Context, raw []byte) ([]byte, error) {
	sc, err := h.auth(ctx)
	if err != nil {
		return nil, err
	}
	var rep Report
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, status.Error(codes.InvalidArgument, "bad report")
		}
	}
	rep.ScannerID = sc.ID
	if err := h.applyReport(ctx, &rep); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return []byte(`{"ok":true}`), nil
}

func (h *Hub) applyReport(ctx context.Context, rep *Report) error {
	for i := range rep.Observations {
		obs := rep.Observations[i]
		if obs.ScanID == "" {
			continue
		}
		if err := h.Orch.RecordObservation(ctx, &obs); err != nil {
			h.Log.Warn("hub: observation apply failed", "scan", obs.ScanID, "err", err)
		}
	}
	if rep.TaskID != "" && rep.TaskState != "" {
		_ = h.Tasks.UpdateState(ctx, rep.TaskID, domain.TaskState(rep.TaskState), rep.ScanError)
	}
	if rep.ScanID != "" {
		if rep.ScanState != "" {
			progress := 0.0
			if rep.Progress != nil {
				progress = *rep.Progress
			}
			_ = h.Scans.UpdateState(ctx, rep.ScanID, domain.ScanState(rep.ScanState), rep.Phase, progress)
		}
		if rep.Stats != nil {
			_ = h.Scans.UpdateStats(ctx, rep.ScanID, *rep.Stats)
		}
		if rep.ScanError != "" {
			_ = h.Scans.SetError(ctx, rep.ScanID, rep.ScanError)
		}
		// Scan completion reaches the server pipeline the same way the
		// embedded scanner's NATS event does: correlation runs server-side.
		if rep.ScanState == string(domain.ScanCompleted) && h.Bus != nil {
			evt, _ := json.Marshal(map[string]any{"scan_id": rep.ScanID, "state": rep.ScanState})
			if err := h.Bus.Publish(ctx, "security.scan.result.v1", evt); err != nil {
				h.Log.Warn("hub: scan result publish failed", "err", err)
			}
		}
	}
	return nil
}

type GetScanReq struct {
	ScanID string `json:"scan_id"`
}

func (h *Hub) callGetScan(ctx context.Context, raw []byte) ([]byte, error) {
	if _, err := h.auth(ctx); err != nil {
		return nil, err
	}
	var req GetScanReq
	if err := json.Unmarshal(raw, &req); err != nil || req.ScanID == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id required")
	}
	scan, err := h.Scans.ByID(ctx, "", req.ScanID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "scan not found")
	}
	out, _ := json.Marshal(ScanView{KillSwitch: scan.KillSwitch, State: string(scan.State)})
	return out, nil
}

func (h *Hub) callHeartbeat(ctx context.Context, raw []byte) ([]byte, error) {
	sc, err := h.auth(ctx)
	if err != nil {
		return nil, err
	}
	_ = h.Scanners.Touch(ctx, sc.ID)
	return []byte(`{"ok":true}`), nil
}
