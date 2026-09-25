package alerting

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Relay moves committed outbox rows to the dedicated alert JetStream
// stream. Publishing is synchronous: published_at is stamped only after
// the broker acknowledges, and a failed publish retries with backoff —
// a NATS outage therefore delays alerts but never loses committed events.
type Relay struct {
	Outbox   *pg.OutboxRepo
	Bus      *platform.Bus
	Log      *slog.Logger
	Interval time.Duration
	Now      func() time.Time
}

// Run blocks until ctx is done.
func (r *Relay) Run(ctx context.Context) {
	if r.Interval <= 0 {
		r.Interval = time.Second
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.RelayOnce(ctx)
			// Retention: acknowledged rows are history; a week is plenty
			// for replay/debug and keeps the table bounded.
			if r.now().Sub(lastPrune) > time.Hour {
				if n, err := r.Outbox.DeletePublishedBefore(ctx, r.now().Add(-7*24*time.Hour)); err == nil && n > 0 {
					r.Log.Info("outbox retention sweep", "removed", n)
				}
				lastPrune = r.now()
			}
		}
	}
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

// RelayOnce claims, publishes and acknowledges one batch.
func (r *Relay) RelayOnce(ctx context.Context) {
	events, err := r.Outbox.ClaimUnpublished(ctx, 100, r.now())
	if err != nil {
		r.Log.Warn("outbox relay claim failed", "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	var published []string
	for _, ev := range events {
		payload, err := json.Marshal(ev)
		if err != nil {
			_ = r.Outbox.MarkFailed(ctx, ev.ID, "marshal: "+err.Error(), r.now().Add(backoff(ev.Attempts)))
			continue
		}
		if err := r.Bus.PublishSync(ctx, platform.SubAlertEvent, payload); err != nil {
			_ = r.Outbox.MarkFailed(ctx, ev.ID, err.Error(), r.now().Add(backoff(ev.Attempts)))
			continue
		}
		published = append(published, ev.ID)
	}
	if len(published) > 0 {
		if err := r.Outbox.MarkPublished(ctx, published, r.now()); err != nil {
			r.Log.Warn("outbox mark published failed", "err", err)
		}
	}
}

// backoff caps relay retries at 10 minutes.
func backoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempts && d < 10*time.Minute; i++ {
		d *= 2
	}
	if d > 10*time.Minute {
		d = 10 * time.Minute
	}
	return d
}
