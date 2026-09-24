// Retention enforcement for the device metrics tier: storage stats,
// TTL synchronization and manual/periodic purge mutations.

package clickhouse

import (
	"context"
	"fmt"
	"time"
)

// DeviceMetricsStats is a storage snapshot for the settings page.
type DeviceMetricsStats struct {
	Rows   uint64     `json:"rows"`
	Oldest *time.Time `json:"oldest,omitempty"` // nil when the table is empty
	Newest *time.Time `json:"newest,omitempty"`
}

// DeviceMetricsStats reports the stored sample count and the age span of
// the device_metrics table (empty table → zero Rows, nil bounds).
func (d *DB) DeviceMetricsStats(ctx context.Context) (DeviceMetricsStats, error) {
	var s DeviceMetricsStats
	// Empty-table aggregates are NULL; coalesce them to epoch and map
	// the sentinel back to nil so callers never see a fake 1970 bound.
	const epoch = "1970-01-01 00:00:00"
	var oldest, newest string
	err := d.conn.QueryRow(ctx,
		`SELECT count(), ifNull(toString(min(timestamp)), ?), ifNull(toString(max(timestamp)), ?)
                 FROM device_metrics`, epoch, epoch).Scan(&s.Rows, &oldest, &newest)
	if err != nil {
		return s, fmt.Errorf("clickhouse: device metrics stats: %w", err)
	}
	if oldest != epoch {
		if t, err := time.Parse("2006-01-02 15:04:05", oldest); err == nil {
			t = t.UTC()
			s.Oldest = &t
		}
	}
	if newest != epoch {
		if t, err := time.Parse("2006-01-02 15:04:05", newest); err == nil {
			t = t.UTC()
			s.Newest = &t
		}
	}
	return s, nil
}

// SetDeviceMetricsTTL aligns the device_metrics TTL with the configured
// retention: days > 0 modifies the table TTL, days == 0 removes it (keep
// everything). DDL takes no bound parameters — days is an int, never
// user-controlled text.
func (d *DB) SetDeviceMetricsTTL(ctx context.Context, days int) error {
	q := "ALTER TABLE device_metrics REMOVE TTL"
	if days > 0 {
		q = fmt.Sprintf("ALTER TABLE device_metrics MODIFY TTL toDateTime(timestamp) + INTERVAL %d DAY", days)
	}
	if err := d.conn.Exec(ctx, q); err != nil {
		return fmt.Errorf("clickhouse: set device metrics ttl (%d days): %w", days, err)
	}
	return nil
}

// CountDeviceMetricsBefore counts samples older than cutoff — the purge
// estimate the manual cleanup action reports.
func (d *DB) CountDeviceMetricsBefore(ctx context.Context, cutoff time.Time) (uint64, error) {
	var n uint64
	if err := d.conn.QueryRow(ctx,
		`SELECT count() FROM device_metrics WHERE timestamp < ?`, cutoff).Scan(&n); err != nil {
		return 0, fmt.Errorf("clickhouse: count device metrics before %s: %w", cutoff.Format(time.RFC3339), err)
	}
	return n, nil
}

// PurgeDeviceMetricsBefore drops samples older than `days` with a delete
// mutation. With wait=true the call blocks until the mutation completes
// (mutations_sync=1 — used by the manual cleanup trigger); periodic sweeps
// stay asynchronous so a large purge never stalls the worker.
func (d *DB) PurgeDeviceMetricsBefore(ctx context.Context, days int, wait bool) (time.Time, error) {
	if days <= 0 {
		return time.Time{}, fmt.Errorf("clickhouse: purge requires a positive retention, got %d", days)
	}
	cutoff := time.Now().UTC().Truncate(time.Second).Add(-time.Duration(days) * 24 * time.Hour)
	q := fmt.Sprintf("ALTER TABLE device_metrics DELETE WHERE timestamp < toDateTime(%d) SETTINGS mutations_sync = %d",
		cutoff.Unix(), map[bool]int{false: 0, true: 1}[wait])
	if err := d.conn.Exec(ctx, q); err != nil {
		return cutoff, fmt.Errorf("clickhouse: purge device metrics (>%dd): %w", days, err)
	}
	return cutoff, nil
}
