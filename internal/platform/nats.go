// Package platform contains infrastructure adapters shared by all services.
package platform

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/observability"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSSubjects is the versioned subject model.
const (
	SubScanRequested   = "security.scan.requested.v1"
	SubScanTask        = "security.scan.task.v1"
	SubScanResult      = "security.scan.result.v1"
	SubAssetObserved   = "security.asset.observed.v1"
	SubServiceObserved = "security.service.observed.v1"
	SubVulnMatch       = "security.vulnerability.match.v1"
	SubFindingCreated  = "security.finding.created.v1"
	SubFindingUpdated  = "security.finding.updated.v1"
	SubAgentRegistered = "security.agent.registered.v1"
	SubAgentTelemetry  = "security.agent.telemetry.v1"
	SubSensorEvent     = "security.sensor.event.v1"
	SubDetectionMatch  = "security.detection.match.v1"
	SubFeedSync        = "security.feed.sync.v1"

	// Dedicated domain-event stream for the alert-trigger engine. It is
	// deliberately separate from the mixed streams above: existing
	// consumers register without a subject filter and would ACK messages
	// they cannot parse, so alert events must not share their subjects.
	SubAlertEvent = "security.alert.event.v1"

	// Realtime streaming subjects (core NATS, deliberately NOT part of any
	// JetStream stream): job logs and scan state are persisted by the server
	// itself, notifications are ephemeral. Every subscriber receives every
	// message (broadcast), which is exactly what the WS fan-out needs.
	SubScanLog      = "security.scan.log.v1"
	SubScanState    = "security.scan.state.v1"
	SubNotification = "security.notification.v1"
	// Internal fan-out relay: the joblog streamer re-publishes anything a
	// browser subscriber would care about on this subject so every server
	// replica (and its local WebSocket conns) sees the same event stream.
	SubWSFanout = "aegis.internal.ws.fanout.v1"
)

// StreamNames configures JetStream streams.
const (
	StreamScan   = "SECURITY_SCAN"
	StreamEvents = "SECURITY_EVENTS"
	StreamAgents = "SECURITY_AGENTS"
	StreamFeeds  = "SECURITY_FEEDS"
	StreamAlerts = "ALERT_EVENTS"
)

// Bus is the NATS JetStream client wrapper. Delivery is at-least-once;
// consumers must be idempotent.
type Bus struct {
	conn      *nats.Conn
	js        jetstream.JetStream
	consumers []string
	mu        sync.Mutex
}

// ConnectBus establishes a NATS connection and declares streams.
func ConnectBus(ctx context.Context, url string) (*Bus, error) {
	nc, err := nats.Connect(url,
		nats.Name("aegis"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("nats: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}
	b := &Bus{conn: nc, js: js}
	if err := b.declareStreams(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bus) declareStreams(ctx context.Context) error {
	streams := []jetstream.StreamConfig{
		{Name: StreamScan, Subjects: []string{SubScanRequested, SubScanTask, SubScanResult},
			Retention: jetstream.WorkQueuePolicy, MaxAge: 24 * time.Hour},
		{Name: StreamEvents, Subjects: []string{SubAssetObserved, SubServiceObserved,
			SubSensorEvent, SubDetectionMatch, SubAgentTelemetry},
			Retention: jetstream.InterestPolicy},
		{Name: StreamAgents, Subjects: []string{SubAgentRegistered}, Retention: jetstream.LimitsPolicy},
		{Name: StreamFeeds, Subjects: []string{SubFeedSync, SubVulnMatch,
			SubFindingCreated, SubFindingUpdated}, Retention: jetstream.WorkQueuePolicy},
		{Name: StreamAlerts, Subjects: []string{SubAlertEvent},
			Retention: jetstream.InterestPolicy, MaxAge: 24 * time.Hour},
	}
	for _, cfg := range streams {
		if _, err := b.js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("nats: stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// Publish publishes a payload to a subject asynchronously (returns before
// the server ack is received; use PublishSync when the ack is required).
func (b *Bus) Publish(ctx context.Context, subject string, payload []byte) error {
	_, err := b.js.PublishAsync(subject, payload)
	return err
}

// PublishSync publishes synchronously and waits for the JetStream ack.
func (b *Bus) PublishSync(ctx context.Context, subject string, payload []byte) error {
	_, err := b.js.PublishMsg(ctx, &nats.Msg{Subject: subject, Data: payload})
	return err
}

// Broadcast publishes on core NATS (no JetStream, no ack): at-most-once,
// lowest latency, every subscriber gets a copy. This is the right
// delivery for realtime UI streaming where the durable copy lives in
// Postgres (job logs) or in the entity row itself (scan state).
func (b *Bus) Broadcast(subject string, payload []byte) error {
	if b.conn == nil || !b.conn.IsConnected() {
		return nats.ErrConnectionClosed
	}
	return b.conn.Publish(subject, payload)
}

// BroadcastSub subscribes to a core-NATS subject. queueGroup empty means
// every subscriber receives every message (true broadcast); a non-empty
// queue group load-balances one delivery per group (used so exactly one
// server replica persists each job log line while all replicas fan out).
func (b *Bus) BroadcastSub(subject, queueGroup string, handler func(data []byte)) (func(), error) {
	if b.conn == nil {
		return nil, nats.ErrConnectionClosed
	}
	var sub *nats.Subscription
	var err error
	if queueGroup != "" {
		sub, err = b.conn.QueueSubscribe(subject, queueGroup, func(m *nats.Msg) {
			handler(m.Data)
		})
	} else {
		sub, err = b.conn.Subscribe(subject, func(m *nats.Msg) {
			handler(m.Data)
		})
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

// Subscribe creates a durable pull consumer and starts a handler loop.
// The handler must be idempotent (at-least-once delivery).
func (b *Bus) Subscribe(ctx context.Context, stream, durable string, handler func(msg jetstream.Msg) error) error {
	return b.SubscribeFiltered(ctx, stream, durable, "", handler)
}

// SubscribeFiltered creates a durable pull consumer restricted to one
// subject. Explicit filtering matters: unfiltered consumers on multi-
// subject streams receive (and must ACK) messages they cannot parse.
func (b *Bus) SubscribeFiltered(ctx context.Context, stream, durable, filterSubject string, handler func(msg jetstream.Msg) error) error {
	cfg := jetstream.ConsumerConfig{
		Durable:       durable,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxDeliver:    10,
		AckWait:       30 * time.Second,
		MaxAckPending: 256,
	}
	if filterSubject != "" {
		cfg.FilterSubject = filterSubject
	}
	c, err := b.js.CreateOrUpdateConsumer(ctx, stream, cfg)
	if err != nil {
		return fmt.Errorf("nats: consumer %s: %w", durable, err)
	}
	b.mu.Lock()
	b.consumers = append(b.consumers, durable)
	b.mu.Unlock()
	_, err = c.Consume(func(msg jetstream.Msg) {
		if err := handler(msg); err != nil {
			_ = msg.NakWithDelay(5 * time.Second)
			return
		}
		_ = msg.Ack()
	}, jetstream.PullMaxMessages(64))
	if err != nil {
		return fmt.Errorf("nats: consume %s: %w", durable, err)
	}
	return nil
}

// ConsumerLag reports pending messages per durable consumer.
func (b *Bus) ConsumerLag(ctx context.Context) map[string]uint64 {
	out := map[string]uint64{}
	for _, d := range b.consumers {
		c, err := b.js.Consumer(ctx, StreamScan, d)
		if err == nil && c != nil {
			if info, err := c.Info(ctx); err == nil {
				out[d] = info.NumPending
			}
		}
	}
	return out
}

// Conn exposes the raw connection (queue groups, request/reply).
func (b *Bus) Conn() *nats.Conn { return b.conn }

// Health implements observability.Checker.
func (b *Bus) CheckHealth(ctx context.Context) observability.DependencyHealth {
	if b == nil || b.conn == nil {
		return observability.DependencyHealth{Name: "nats", Status: "down"}
	}
	if b.conn.Status() != nats.CONNECTED {
		return observability.DependencyHealth{Name: "nats", Status: "down"}
	}
	return observability.DependencyHealth{Name: "nats", Status: "ok"}
}

// Close drains and closes the connection.
func (b *Bus) Close() {
	if b.conn != nil {
		b.conn.Drain()
	}
}
