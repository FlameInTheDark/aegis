// Package telemetry implements event ingestion: sensor events flow
// NATS -> normalizing adapters -> ClickHouse (analytics) with detection
// evaluation (workers).
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/events"
	"github.com/FlameInTheDark/aegis/internal/platform"
	ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	"github.com/FlameInTheDark/aegis/internal/repository/redis"
	"github.com/nats-io/nats.go/jetstream"
)

// Subjects for telemetry ingestion.
const (
	SubjectSensorEvent = "security.sensor.event.v1"
	SubjectAgentEvent  = "security.agent.telemetry.v1"
)

// Ingestor consumes normalized events from NATS and persists to
// ClickHouse, then runs detections.
type Ingestor struct {
	Bus       *platform.Bus
	CH        *ch.DB
	Engine    *detections.Engine
	Cache     *redisrepo.Client
	Log       *slog.Logger
	BatchSize int
}

// SubjectEvent is the wire payload for an ingestion message.
type SubjectEvent struct {
	TenantID string          `json:"tenant_id"`
	SiteID   string          `json:"site_id,omitempty"`
	SensorID string          `json:"sensor_id,omitempty"`
	Source   string          `json:"source"` // suricata|zeek|snort|agent
	Raw      json.RawMessage `json:"raw"`
}

// Run starts the durable consumer (blocks until ctx is cancelled).
func (in *Ingestor) Run(ctx context.Context) error {
	return in.Bus.Subscribe(ctx, platform.StreamEvents, "telemetry-ingest", func(msg jetstream.Msg) error {
		var se SubjectEvent
		if err := json.Unmarshal(msg.Data(), &se); err != nil {
			in.Log.Error("bad telemetry payload", "err", err)
			return nil // poison messages are dropped, not retried forever
		}
		eventsBatch, err := in.Normalize(se)
		if err != nil {
			in.Log.Warn("normalize failed", "source", se.Source, "err", err)
			return nil
		}
		if len(eventsBatch) == 0 {
			return nil
		}
		if err := in.CH.InsertEvents(ctx, eventsBatch); err != nil {
			in.Log.Error("clickhouse insert failed", "err", err)
			return err // retryable
		}
		if in.Engine != nil {
			if _, err := in.Engine.Ingest(ctx, se.TenantID, eventsBatch); err != nil {
				in.Log.Warn("detection ingest failed", "err", err)
			}
		}
		return nil
	})
}

// Normalize adapts one raw sensor payload into platform events.
func (in *Ingestor) Normalize(se SubjectEvent) ([]domain.Event, error) {
	adapter, err := events.AdapterFor(se.Source)
	if err != nil {
		return nil, err
	}
	// Payload may be a single JSON object or JSONL of records.
	var out []domain.Event
	lines := splitJSONL(se.Raw)
	for _, line := range lines {
		ev, err := adapter.Parse(line, se.TenantID, se.SiteID, se.SensorID)
		if err != nil {
			in.Log.Debug("record rejected", "source", se.Source, "err", err)
			continue // partial failure: keep going
		}
		out = append(out, *ev)
		if in.BatchSize > 0 && len(out) >= in.BatchSize {
			break
		}
	}
	return out, nil
}

// splitJSONL handles both single-object and newline-delimited payloads.
func splitJSONL(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	trimmed := trimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// Array form: split top-level elements.
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err == nil {
			out := make([][]byte, 0, len(arr))
			for _, a := range arr {
				out = append(out, a)
			}
			return out
		}
	}
	var out [][]byte
	start := -1
	depth := 0
	inStr := false
	esc := false
	for i, b := range data {
		if inStr {
			if esc {
				esc = false
			} else if b == '\\' {
				esc = true
			} else if b == '"' {
				inStr = false
			}
			continue
		}
		switch b {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, trimSpace(data[start:i+1]))
				start = -1
			}
		}
	}
	return out
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// PublishEvent marshals and publishes a subject event (API path).
func (in *Ingestor) PublishEvent(ctx context.Context, se SubjectEvent) error {
	payload, err := json.Marshal(se)
	if err != nil {
		return fmt.Errorf("marshal subject event: %w", err)
	}
	return in.Bus.Publish(ctx, SubjectSensorEvent, payload)
}

// HTTPIngest handles the synchronous API ingestion path with size caps
// and dedup (oversized events, duplication, replay).
func (in *Ingestor) HTTPIngest(ctx context.Context, se SubjectEvent) (int, error) {
	if len(se.Raw) > 8<<20 {
		return 0, fmt.Errorf("payload exceeds 8MiB limit")
	}
	evs, err := in.Normalize(se)
	if err != nil {
		return 0, err
	}
	accepted := 0
	batch := make([]domain.Event, 0, len(evs))
	for _, ev := range evs {
		first, err := in.Cache.DedupCheck(ctx, "evt:"+ev.EventID, 10*time.Minute)
		if err == nil && !first {
			continue // duplicate within window
		}
		batch = append(batch, ev)
		accepted++
	}
	// One insert per request, not per event: row-at-a-time inserts make
	// ClickHouse accumulate thousands of tiny parts and eventually reject
	// ingestion with "too many parts".
	if len(batch) > 0 {
		_ = in.CH.InsertEvents(ctx, batch)
	}
	if in.Engine != nil && len(evs) > 0 {
		_, _ = in.Engine.Ingest(ctx, se.TenantID, evs)
	}
	return accepted, nil
}

// HTTPIngestSize validates payload size independently (used by tests and
// the API layer's pre-check, oversized events).
func (in *Ingestor) HTTPIngestSize(raw []byte) (int, error) {
	if len(raw) > 8<<20 {
		return 0, fmt.Errorf("payload exceeds 8MiB limit")
	}
	return len(raw), nil
}
