package httpx

import (
	"testing"
	"time"

	chx "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
)

func TestMetricsWindowBuckets(t *testing.T) {
	cases := []struct {
		window     string
		wantBucket int
		wantSpan   time.Duration
	}{
		{"1h", 60, time.Hour},
		{"6h", 300, 6 * time.Hour},
		{"24h", 900, 24 * time.Hour},
		{"7d", 3600, 7 * 24 * time.Hour},
	}
	for _, tc := range cases {
		rng, err := resolveMetricsRange(tc.window, "", "", time.Now().UTC())
		if err != nil {
			t.Errorf("window %q: unexpected error %v", tc.window, err)
			continue
		}
		if rng.Bucket != tc.wantBucket {
			t.Errorf("window %q: bucket = %d, want %d", tc.window, rng.Bucket, tc.wantBucket)
		}
		span := rng.To.Sub(rng.From)
		if diff := span - tc.wantSpan; diff > 5*time.Second || diff < -5*time.Second {
			t.Errorf("window %q: span = %v, want ~%v", tc.window, span, tc.wantSpan)
		}
		if !rng.Tail {
			t.Errorf("window %q: want tail mode", tc.window)
		}
	}
}

func TestParseMetricsWindow(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30s", 30 * time.Second, true},
		{"90", 90 * time.Second, true},
		{"5m", 5 * time.Minute, true},
		{"2h", 2 * time.Hour, true},
		{"3d", 3 * 24 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"", 24 * time.Hour, true}, // default
		{"0", 0, false},
		{"-5m", 0, false},
		{"5x", 0, false},
		{"d", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseMetricsWindow(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseMetricsWindow(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPickMetricsBucket(t *testing.T) {
	cases := []struct {
		span   time.Duration
		target int
		want   int
	}{
		// ~240-point target for tails.
		{30 * time.Second, 240, 1},        // 30 pts at 1s
		{5 * time.Minute, 240, 2},         // 300/1>240 → 2s (150 pts)
		{24 * time.Hour, 240, 600},        // 144 pts
		{7 * 24 * time.Hour, 240, 3600},   // ~168 pts
		{30 * 24 * time.Hour, 240, 14400}, // ~180 pts
		// ~360-point target for ranges.
		{24 * time.Hour, 360, 300},
		{366 * 24 * time.Hour, 360, 86400 * 2}, // day ladder exhausted → 2-day buckets
		{366 * 24 * time.Hour, 240, 86400 * 2},
	}
	for _, tc := range cases {
		if got := pickMetricsBucket(tc.span, tc.target); got != tc.want {
			t.Errorf("pickMetricsBucket(%v, %d) = %d, want %d", tc.span, tc.target, got, tc.want)
		}
	}
}

func TestResolveMetricsRange(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	// Range mode: explicit bounds are honored verbatim; bucket auto-picked.
	rng, err := resolveMetricsRange("", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", now)
	if err != nil {
		t.Fatalf("range mode: %v", err)
	}
	if rng.Tail {
		t.Error("range mode must not be tail")
	}
	if rng.Window != "range" {
		t.Errorf("window label = %q, want range", rng.Window)
	}
	if !rng.From.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !rng.To.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("bounds = %v..%v", rng.From, rng.To)
	}
	if rng.Bucket != 300 {
		t.Errorf("1-day range bucket = %d, want 300", rng.Bucket)
	}

	// to defaults to now.
	rng, err = resolveMetricsRange("", "2026-09-24T11:30:00Z", "", now)
	if err != nil {
		t.Fatalf("open-ended range: %v", err)
	}
	if !rng.To.Equal(now) {
		t.Errorf("to = %v, want %v", rng.To, now)
	}

	// Rejections: window+range mixed, inverted bounds, too-short, too-long.
	if _, err := resolveMetricsRange("1h", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", now); err == nil {
		t.Error("window+from must be rejected")
	}
	if _, err := resolveMetricsRange("", "2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z", now); err == nil {
		t.Error("inverted range must be rejected")
	}
	if _, err := resolveMetricsRange("", "2026-09-01T00:00:00Z", "2026-09-01T00:00:05Z", now); err == nil {
		t.Error("sub-minimum range must be rejected")
	}
	if _, err := resolveMetricsRange("", "2020-01-01T00:00:00Z", "2026-09-01T00:00:00Z", now); err == nil {
		t.Error("over-long range must be rejected")
	}

	// Tail mode clamps tiny windows up to the minimum span.
	rng, err = resolveMetricsRange("3s", "", "", now)
	if err != nil {
		t.Fatalf("tiny tail: %v", err)
	}
	if got := rng.To.Sub(rng.From); got != 10*time.Second {
		t.Errorf("tiny tail span = %v, want clamped to 10s", got)
	}
}

func TestGroupIfaceSeries(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	points := []chx.IfaceSeriesPoint{
		// Query orders by name, bucket — eth0 first, then eth1.
		{Name: "eth0", Bucket: base, RxBPS: 1, TxBPS: 2},
		{Name: "eth0", Bucket: base.Add(time.Minute), RxBPS: 3, TxBPS: 4},
		{Name: "eth1", Bucket: base, RxBPS: 5, TxBPS: 6},
	}
	grouped := groupIfaceSeries(points)
	if len(grouped) != 2 {
		t.Fatalf("want 2 series, got %d", len(grouped))
	}
	eth0, eth1 := grouped[0], grouped[1]
	if eth0.Name != "eth0" || len(eth0.Rx) != 2 || eth0.Rx[1] != 3 || eth0.Tx[1] != 4 {
		t.Errorf("eth0 series: %+v", eth0)
	}
	if eth1.Name != "eth1" || len(eth1.Rx) != 1 || eth1.Rx[0] != 5 || eth1.Tx[0] != 6 {
		t.Errorf("eth1 series: %+v", eth1)
	}
}
