// Hub fans realtime events out to connected browser subscribers.
// Thread-safe; one Hub per server process. Events are (channel, kind,
// payload) tuples routed to every subscriber joined to that channel whose
// org matches the event org — tenancy is enforced here so a handler bug
// upstream cannot leak another org's scan activity.
package joblog

import (
	"encoding/json"
	"sync"
	"sync/atomic"
)

// Event kinds pushed to subscribers.
const (
	KindLog          = "log"
	KindState        = "state"
	KindNotification = "notification"
)

// Event is one fan-out unit. Channel keys: "scan:<scan_id>" and "notify".
type Event struct {
	OrgID   string          `json:"-"`
	Channel string          `json:"-"`
	Kind    string          `json:"kind"`
	Data    json.RawMessage `json:"data"`
}

// subBuf bounds per-subscriber buffering (events). A subscriber slower
// than this for long enough is dropped: a wedged browser tab must never
// back-pressure the scanner pipeline.
const subBuf = 512

// Sub is one subscribed connection.
type Sub struct {
	hub      *Hub
	orgID    string
	ch       chan *Event
	channels map[string]struct{}
	closed   atomic.Bool
	dropped  atomic.Bool
	once     sync.Once
	done     chan struct{}
}

// Org returns the tenant this subscriber belongs to.
func (s *Sub) Org() string { return s.orgID }

// C returns the receive channel; closed exactly once when the sub leaves
// the hub (unsubscribe, hub shutdown, or slow-consumer eviction).
func (s *Sub) C() <-chan *Event { return s.ch }

// Join subscribes the connection to channel keys ("scan:<id>", "notify").
// The WebSocket handler validates each channel against the claims BEFORE
// calling Join (scan ownership, org match) — the hub only routes.
func (s *Sub) Join(channels ...string) {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	for _, c := range channels {
		s.channels[c] = struct{}{}
	}
}

// Leave drops channel keys; the sub itself stays until Unsubscribe.
func (s *Sub) Leave(channels ...string) {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	for _, c := range channels {
		delete(s.channels, c)
	}
}

// In reports whether the sub joined the channel.
func (s *Sub) In(channel string) bool {
	s.hub.mu.RLock()
	defer s.hub.mu.RUnlock()
	_, ok := s.channels[channel]
	return ok
}

// Unsubscribe removes the sub from the hub and closes its channel.
func (s *Sub) Unsubscribe() {
	s.hub.remove(s)
}

func (s *Sub) close() {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.done)
		close(s.ch)
	})
}

// Hub routes events to subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[*Sub]struct{}
}

// NewHub builds an empty Hub.
func NewHub() *Hub {
	return &Hub{subs: map[*Sub]struct{}{}}
}

// Subscribe registers a new connection sub scoped to an org.
func (h *Hub) Subscribe(orgID string) *Sub {
	s := &Sub{
		hub:      h,
		orgID:    orgID,
		ch:       make(chan *Event, subBuf),
		channels: map[string]struct{}{},
		done:     make(chan struct{}),
	}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *Hub) remove(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
	s.close()
}

// Publish routes one event to every matching subscriber. Matching = joined
// the channel AND same org. Delivery is best-effort non-blocking: a full
// subscriber buffer marks the sub as dropped and evicts it (the client
// reconnects and replays history via REST, which is exactly the recovery
// story this architecture gives us).
func (h *Hub) Publish(ev *Event) {
	if ev == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subs {
		if s.closed.Load() || s.dropped.Load() {
			continue
		}
		if _, ok := s.channels[ev.Channel]; !ok {
			continue
		}
		// Tenancy: notify is per-org by definition; scan channels carry the
		// event org resolved by the streamer (from the scan row).
		if ev.OrgID != "" && s.orgID != ev.OrgID {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			s.dropped.Store(true)
			go h.remove(s) // async: never under RLock
		}
	}
}

// Subscribers returns the current connection count (metrics/health).
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
