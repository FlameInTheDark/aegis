// Package retention enforces the operator-configured retention of the
// ClickHouse device_metrics tier. The setting lives in the platform
// settings store (settings:manage API); this service keeps the table TTL
// aligned with it and periodically issues bounded delete mutations so
// storage is actually freed instead of waiting on merge-driven TTL expiry.
package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// SettingStore is the slice of the settings repository the worker needs.
type SettingStore interface {
	Get(ctx context.Context, key string) (json.RawMessage, error)
	Set(ctx context.Context, key string, value json.RawMessage) error
}

// CH is the slice of the ClickHouse repository the worker needs.
type CH interface {
	SetDeviceMetricsTTL(ctx context.Context, days int) error
	PurgeDeviceMetricsBefore(ctx context.Context, days int, wait bool) (time.Time, error)
}

// Setting keys and defaults. metrics.retention_days holds the configured
// retention (number of days, 0 = keep forever); the applied shadow key
// remembers what the table TTL was last synced to, so a restart or a
// no-op value never rewrites DDL.
const (
	KeyRetention        = "metrics.retention_days"
	KeyRetentionApplied = "metrics.retention_days.applied"
	// DefaultRetentionDays matches the device_metrics schema TTL (30 days).
	DefaultRetentionDays = 30
	// MaxRetentionDays bounds the setting — 10 years of device samples is
	// nobody's healthy deployment; larger spans are rejected by the API.
	MaxRetentionDays = 3650
)

// Service runs the retention loop.
type Service struct {
	Settings SettingStore
	CH       CH
	Log      *slog.Logger

	// PollEvery watches the setting; SweepEvery throttles the periodic
	// purge mutation. Both have production defaults; tests shrink them.
	PollEvery  time.Duration
	SweepEvery time.Duration

	notify chan struct{} // poked by the API after a settings change
	mu     sync.Mutex    // serializes sweeps against SweepNow
}

// New builds a service with production cadences.
func New(settings SettingStore, ch CH, log *slog.Logger) *Service {
	return &Service{
		Settings: settings, CH: ch, Log: log,
		PollEvery:  time.Minute,
		SweepEvery: 6 * time.Hour,
		notify:     make(chan struct{}, 1),
	}
}

// EffectiveDays reads the retention setting and normalizes it: a stored
// number clamps to 0..MaxRetentionDays; missing or malformed values fall
// back to DefaultRetentionDays.
func EffectiveDays(ctx context.Context, store SettingStore) (int, error) {
	raw, err := store.Get(ctx, KeyRetention)
	if err != nil {
		return DefaultRetentionDays, err
	}
	if raw == nil {
		return DefaultRetentionDays, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return DefaultRetentionDays, fmt.Errorf("settings %s: malformed value %s", KeyRetention, raw)
	}
	if n < 0 {
		n = 0
	}
	if n > MaxRetentionDays {
		n = MaxRetentionDays
	}
	return n, nil
}

// appliedDays reads the shadow key (missing → schema default 30). The
// shadow is written as a bare JSON number, so parse it leniently.
func (s *Service) appliedDays(ctx context.Context) int {
	raw, err := s.Settings.Get(ctx, KeyRetentionApplied)
	if err != nil || raw == nil {
		return DefaultRetentionDays
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil || n < 0 {
		return DefaultRetentionDays
	}
	return n
}

func (s *Service) markApplied(ctx context.Context, days int) {
	if err := s.Settings.Set(ctx, KeyRetentionApplied, json.RawMessage(strconv.Itoa(days))); err != nil {
		s.Log.Warn("retention: could not record applied TTL", "err", err)
	}
}

// Run drives the loop until ctx is cancelled. Every tick re-reads the
// setting; a change syncs the table TTL immediately and purges right away
// (a reduced retention takes effect now, not at the next sweep). The
// purge mutation itself runs at most every SweepEvery otherwise.
func (s *Service) Run(ctx context.Context) {
	if s.PollEvery <= 0 {
		s.PollEvery = time.Minute
	}
	if s.SweepEvery <= 0 {
		s.SweepEvery = 6 * time.Hour
	}
	ticker := time.NewTicker(s.PollEvery)
	defer ticker.Stop()
	lastSweep := time.Time{}
	for {
		if err := s.tick(ctx, &lastSweep); err != nil {
			s.Log.Warn("retention tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.notify: // settings changed — re-read immediately
		}
	}
}

// tick performs one alignment pass; lastSweep is updated in place.
func (s *Service) tick(ctx context.Context, lastSweep *time.Time) error {
	days, err := EffectiveDays(ctx, s.Settings)
	if err != nil {
		return err
	}
	if days != s.appliedDays(ctx) {
		if err := s.CH.SetDeviceMetricsTTL(ctx, days); err != nil {
			return err
		}
		s.markApplied(ctx, days)
		s.Log.Info("retention: device_metrics TTL synced", "days", days)
		if days > 0 {
			// The operator just tightened (or first-configured) retention —
			// clear everything beyond the new window immediately.
			if _, err := s.CH.PurgeDeviceMetricsBefore(ctx, days, false); err != nil {
				return err
			}
			*lastSweep = time.Now()
		} else {
			*lastSweep = time.Now() // keep-forever: nothing to sweep until it changes
		}
		return nil
	}
	// Steady state: periodic purge keeps storage honest even when TTL
	// removals would otherwise wait for background merges. Zero lastSweep
	// means "never swept" — sweep once on startup when retention is on.
	if days > 0 && (lastSweep.IsZero() || time.Since(*lastSweep) >= s.SweepEvery) {
		s.mu.Lock()
		_, err := s.CH.PurgeDeviceMetricsBefore(ctx, days, false)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		*lastSweep = time.Now()
	}
	return nil
}

// Notify wakes the loop right away (called by the API after PATCH).
func (s *Service) Notify() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// SweepNow runs a synchronous purge at the configured retention and
// returns the cutoff plus a row estimate captured beforehand (when the
// caller provides countBefore). Used by the manual "clean up now" action.
func (s *Service) SweepNow(ctx context.Context, countBefore func(context.Context, time.Time) (uint64, error)) (time.Time, int, uint64, error) {
	days, err := EffectiveDays(ctx, s.Settings)
	if err != nil {
		return time.Time{}, 0, 0, err
	}
	if days <= 0 {
		return time.Time{}, 0, 0, fmt.Errorf("metrics retention is disabled (keep forever) — nothing to clean")
	}
	var estimate uint64
	if countBefore != nil {
		estimateCutoff := time.Now().UTC().Truncate(time.Second).Add(-time.Duration(days) * 24 * time.Hour)
		if estimate, err = countBefore(ctx, estimateCutoff); err != nil {
			return time.Time{}, days, 0, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff, err := s.CH.PurgeDeviceMetricsBefore(ctx, days, true)
	if err != nil {
		return time.Time{}, days, estimate, err
	}
	return cutoff, days, estimate, nil
}
