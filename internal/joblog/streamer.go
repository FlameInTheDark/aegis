// Streamer glues the NATS broadcast subjects to persistence and the
// browser fan-out. Subscription shapes:
//
//   - scan.log with queue group "aegis-joblog-writer": exactly ONE server
//     replica persists each event (batched writes; seq assignment), then
//     re-publishes the persisted copy — now stamped with its store seq —
//     on the ws-fanout relay subject.
//   - the fanout relay / scan.state / notification WITHOUT a queue group:
//     every replica receives a copy and pushes to its local Hub, whose
//     subs are the browser WebSocket connections.
//
// Persist-then-fan-out matters for logs: the REST history replays rows
// WITH their seq, so live copies must carry the same seq or every browser
// tail drops them as replays. State/notification events have no seq and
// keep the immediate (pre-persist) fan-out.
package joblog

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/platform"
)

// flushInterval and flushLimit bound write batching: events accumulate at
// most this long (or this many) before one Append round-trip.
const (
	flushInterval = 250 * time.Millisecond
	flushLimit    = 128
)

// Streamer consumes broadcast events; run Start once, cancel ctx to stop.
type Streamer struct {
	bus   *platform.Bus
	store *Store
	hub   *Hub
	log   *slog.Logger

	mu   sync.Mutex
	buf  []*domain.JobLogEvent
	stop chan struct{}
}

// NewStreamer wires the dependencies.
func NewStreamer(bus *platform.Bus, store *Store, hub *Hub, log *slog.Logger) *Streamer {
	return &Streamer{bus: bus, store: store, hub: hub, log: log, stop: make(chan struct{})}
}

// Start subscribes and spawns the batched writer. Returns a stop func.
func (s *Streamer) Start(ctx context.Context) func() {
	// Persistence: one writer per deployment.
	_, err := s.bus.BroadcastSub(platform.SubScanLog, "aegis-joblog-writer", func(data []byte) {
		var e domain.JobLogEvent
		if err := json.Unmarshal(data, &e); err != nil {
			s.log.Warn("joblog: malformed event", "err", err)
			return
		}
		if e.ScanID == "" {
			return
		}
		s.enqueue(&e)
	})
	if err != nil {
		s.log.Error("joblog: writer subscribe failed; job logs will not persist", "err", err)
	}

	// Fan-out: every replica, every event. Logs arrive via the relay
	// subject AFTER the writer persisted them (seq stamped); state and
	// notifications stay immediate.
	unsubs := []func(){}
	for subject, kind := range map[string]string{
		platform.SubWSFanout:     KindLog,
		platform.SubScanState:    KindState,
		platform.SubNotification: KindNotification,
	} {
		kind := kind
		stop, err := s.bus.BroadcastSub(subject, "", func(data []byte) { s.fanout(kind, data) })
		if err != nil {
			s.log.Error("joblog: fanout subscribe failed", "subject", subject, "err", err)
			continue
		}
		unsubs = append(unsubs, stop)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				s.flush()
				return
			case <-s.stop:
				s.flush()
				return
			case <-t.C:
				s.flush()
			}
		}
	}()

	return func() {
		close(s.stop)
		<-done
		for _, u := range unsubs {
			u()
		}
	}
}

func (s *Streamer) enqueue(e *domain.JobLogEvent) {
	s.mu.Lock()
	s.buf = append(s.buf, e)
	full := len(s.buf) >= flushLimit
	s.mu.Unlock()
	if full {
		s.flush()
	}
}

func (s *Streamer) flush() {
	s.mu.Lock()
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buf
	s.buf = nil
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.Append(ctx, batch); err != nil {
		// Persistence is best-effort for streaming purposes: dropping a
		// batch must never wedge a scanner. The failure is loud.
		s.log.Error("joblog: persist batch failed", "events", len(batch), "err", err)
		return
	}
	// Re-publish the persisted copies so every replica's Hub (and its
	// WebSocket conns) receives the seq-stamped events; browsers dedupe
	// them against the REST history they loaded on open.
	for _, e := range batch {
		if b, err := json.Marshal(e); err == nil {
			_ = s.bus.Broadcast(platform.SubWSFanout, b)
		}
	}
}

func (s *Streamer) fanout(kind string, data []byte) {
	var orgID, channel string
	switch kind {
	case KindLog:
		var probe struct {
			ScanID string `json:"scan_id"`
			OrgID  string `json:"org_id"`
		}
		if json.Unmarshal(data, &probe) == nil {
			channel, orgID = "scan:"+probe.ScanID, probe.OrgID
		}
	case KindState:
		var probe struct {
			ScanID string `json:"scan_id"`
			OrgID  string `json:"org_id"`
		}
		if json.Unmarshal(data, &probe) == nil {
			channel, orgID = "scan:"+probe.ScanID, probe.OrgID
		}
	case KindNotification:
		var probe struct {
			OrgID string `json:"org_id"`
		}
		if json.Unmarshal(data, &probe) == nil {
			channel, orgID = "notify", probe.OrgID
		}
	}
	if channel == "" {
		return
	}
	s.hub.Publish(&Event{OrgID: orgID, Channel: channel, Kind: kind, Data: json.RawMessage(data)})
}

// PublishLog emits one job log event onto the broadcast subject.
// Fire-and-forget: streaming must never fail a scan.
func PublishLog(ctx context.Context, bus *platform.Bus, e *domain.JobLogEvent) {
	if bus == nil || e == nil || e.ScanID == "" {
		return
	}
	e.Normalize()
	if b, err := json.Marshal(e); err == nil {
		_ = bus.Broadcast(platform.SubScanLog, b)
	}
}

// PublishState emits a scan lifecycle event (progress/phase/state).
func PublishState(ctx context.Context, bus *platform.Bus, e *domain.ScanStateEvent) {
	if bus == nil || e == nil || e.ScanID == "" {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if b, err := json.Marshal(e); err == nil {
		_ = bus.Broadcast(platform.SubScanState, b)
	}
}

// PublishNotification emits a user-facing notification event.
func PublishNotification(ctx context.Context, bus *platform.Bus, e *domain.NotificationEvent) {
	if bus == nil || e == nil || e.OrgID == "" {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if b, err := json.Marshal(e); err == nil {
		_ = bus.Broadcast(platform.SubNotification, b)
	}
}
