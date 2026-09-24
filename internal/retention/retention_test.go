package retention

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ---- fakes ---------------------------------------------------------------

type fakeSettings struct {
	mu   sync.Mutex
	data map[string]json.RawMessage
}

func newFakeSettings() *fakeSettings { return &fakeSettings{data: map[string]json.RawMessage{}} }

func (f *fakeSettings) Get(_ context.Context, key string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.data[key]; ok {
		return v, nil
	}
	return nil, nil
}

func (f *fakeSettings) Set(_ context.Context, key string, value json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeSettings) put(key string, v any) {
	raw, _ := json.Marshal(v)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = raw
}

type fakeCH struct {
	mu       sync.Mutex
	ttlCalls []int
	ttlErr   error
	purges   []struct {
		days int
		wait bool
	}
	purgeErr error
	removed  map[int]int // days -> how many purges ran
}

func newFakeCH() *fakeCH { return &fakeCH{removed: map[int]int{}} }

func (f *fakeCH) SetDeviceMetricsTTL(_ context.Context, days int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ttlErr != nil {
		return f.ttlErr
	}
	f.ttlCalls = append(f.ttlCalls, days)
	return nil
}

func (f *fakeCH) PurgeDeviceMetricsBefore(_ context.Context, days int, wait bool) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.purgeErr != nil {
		return time.Time{}, f.purgeErr
	}
	f.purges = append(f.purges, struct {
		days int
		wait bool
	}{days, wait})
	f.removed[days]++
	return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), nil
}

// ---- tests ---------------------------------------------------------------

func TestEffectiveDays(t *testing.T) {
	ctx := context.Background()
	s := newFakeSettings()

	// Missing → default.
	if d, _ := EffectiveDays(ctx, s); d != DefaultRetentionDays {
		t.Errorf("missing setting: days = %d, want %d", d, DefaultRetentionDays)
	}
	// Stored values pass through when in range.
	s.put(KeyRetention, 90)
	if d, _ := EffectiveDays(ctx, s); d != 90 {
		t.Errorf("stored 90: days = %d", d)
	}
	// 0 = keep forever stays 0 (not the default).
	s.put(KeyRetention, 0)
	if d, _ := EffectiveDays(ctx, s); d != 0 {
		t.Errorf("stored 0: days = %d, want 0", d)
	}
	// Out-of-range clamps; malformed falls back to the default.
	s.put(KeyRetention, 99999)
	if d, _ := EffectiveDays(ctx, s); d != MaxRetentionDays {
		t.Errorf("stored 99999: days = %d, want %d", d, MaxRetentionDays)
	}
	s.put(KeyRetention, json.RawMessage(`"soon"`))
	if d, err := EffectiveDays(ctx, s); d != DefaultRetentionDays || err == nil {
		t.Errorf("malformed: days = %d err = %v, want default + error", d, err)
	}
}

func TestTickSyncsTTLOnChangeAndPurges(t *testing.T) {
	ctx := context.Background()
	settings, ch := newFakeSettings(), newFakeCH()
	svc := New(settings, ch, testLogger())
	last := time.Time{}

	// First tick: no configured value → default 30 == applied default → no
	// DDL, but the periodic sweep runs (never swept before).
	if err := svc.tick(ctx, &last); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(ch.ttlCalls) != 0 {
		t.Errorf("unexpected TTL calls: %v", ch.ttlCalls)
	}
	if len(ch.purges) != 1 || ch.purges[0].days != DefaultRetentionDays {
		t.Fatalf("want one startup sweep at %dd, got %+v", DefaultRetentionDays, ch.purges)
	}

	// Change retention to 7 → TTL rewrite + immediate purge, shadow recorded.
	settings.put(KeyRetention, 7)
	if err := svc.tick(ctx, &last); err != nil {
		t.Fatalf("tick after change: %v", err)
	}
	if len(ch.ttlCalls) != 1 || ch.ttlCalls[0] != 7 {
		t.Fatalf("TTL calls: %v, want [7]", ch.ttlCalls)
	}
	if n := ch.removed[7]; n != 1 {
		t.Errorf("want immediate purge at 7d, got %d", n)
	}
	applied, _ := settings.Get(ctx, KeyRetentionApplied)
	if string(applied) != "7" {
		t.Errorf("applied shadow = %s, want 7", applied)
	}

	// Same value again → nothing but the (throttled) sweep; set SweepEvery
	// so the sweep is skipped this time.
	svc.SweepEvery = time.Hour
	if err := svc.tick(ctx, &last); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if len(ch.ttlCalls) != 1 {
		t.Errorf("TTL rewritten without a change: %v", ch.ttlCalls)
	}
	if len(ch.purges) != 2 {
		t.Errorf("sweep not throttled: %v", ch.purges)
	}

	// 0 = keep forever → REMOVE TTL, no purge ever.
	settings.put(KeyRetention, 0)
	if err := svc.tick(ctx, &last); err != nil {
		t.Fatalf("keep-forever tick: %v", err)
	}
	if n := len(ch.ttlCalls); n != 2 || ch.ttlCalls[1] != 0 {
		t.Errorf("keep-forever TTL calls: %v", ch.ttlCalls)
	}
	if len(ch.purges) != 2 {
		t.Errorf("purged while keep-forever: %+v", ch.purges)
	}
}

func TestTickSurvivesCHErrors(t *testing.T) {
	ctx := context.Background()
	settings, ch := newFakeSettings(), newFakeCH()
	ch.ttlErr = errors.New("boom")
	svc := New(settings, ch, testLogger())
	settings.put(KeyRetention, 14)
	last := time.Time{}
	if err := svc.tick(ctx, &last); err == nil {
		t.Fatal("want TTL error surfaced")
	}
	// The failed alignment must not record the shadow — the next tick retries.
	if _, err := settings.Get(ctx, KeyRetentionApplied); err != nil {
		t.Fatalf("settings get: %v", err)
	}
	ch.ttlErr = nil
	if err := svc.tick(ctx, &last); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(ch.ttlCalls) != 1 || ch.ttlCalls[0] != 14 {
		t.Fatalf("retry TTL calls: %v", ch.ttlCalls)
	}
}

func TestSweepNowCountsAndRejectsKeepForever(t *testing.T) {
	ctx := context.Background()
	settings, ch := newFakeSettings(), newFakeCH()
	svc := New(settings, ch, testLogger())

	// Keep forever → explicit rejection (0 must be configured; missing
	// falls back to the default, which is active).
	settings.put(KeyRetention, 0)
	if _, _, _, err := svc.SweepNow(ctx, nil); err == nil {
		t.Fatal("want rejection when retention disabled")
	}

	settings.put(KeyRetention, 5)
	var gotCutoff time.Time
	estimate, countErr := uint64(4242), error(nil)
	cutoff, days, rows, err := svc.SweepNow(ctx, func(_ context.Context, cutoff time.Time) (uint64, error) {
		gotCutoff = cutoff
		return estimate, countErr
	})
	if err != nil {
		t.Fatalf("SweepNow: %v", err)
	}
	if days != 5 || rows != 4242 {
		t.Errorf("days = %d rows = %d, want 5 / 4242", days, rows)
	}
	if want := 5 * 24 * time.Hour; time.Since(gotCutoff) < want-time.Hour || time.Since(gotCutoff) > want+time.Hour {
		t.Errorf("estimate cutoff = %v, want ~5 days ago", gotCutoff)
	}
	if !cutoff.After(gotCutoff) && !cutoff.Equal(gotCutoff) {
		t.Errorf("purge cutoff %v predates estimate cutoff %v", cutoff, gotCutoff)
	}
	if len(ch.purges) != 1 || !ch.purges[0].wait {
		t.Errorf("SweepNow must purge synchronously: %+v", ch.purges)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	settings, ch := newFakeSettings(), newFakeCH()
	svc := New(settings, ch, testLogger())
	svc.PollEvery = 10 * time.Millisecond
	settings.put(KeyRetention, strconv.Itoa(DefaultRetentionDays))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
