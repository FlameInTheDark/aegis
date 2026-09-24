// Device performance metrics: ingest of endpoint samples and the
// bucketed aggregates the asset performance charts read.

package clickhouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DeviceIfaceSample is one NIC's counters/rates within a metrics sample.
type DeviceIfaceSample struct {
	Name      string  `json:"name"`
	MAC       string  `json:"mac,omitempty"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxPackets uint64  `json:"rx_packets,omitempty"`
	TxPackets uint64  `json:"tx_packets,omitempty"`
	RxBPS     float64 `json:"rx_bps"`
	TxBPS     float64 `json:"tx_bps"`
}

// DeviceMetricSample is one performance sample of a bound device, taken
// over the interval since the endpoint's previous sample.
type DeviceMetricSample struct {
	TenantID     string
	SiteID       string
	AgentID      string
	AssetID      string // zero UUID when the device has no asset link yet
	Timestamp    time.Time
	CPUPercent   float64
	RxBPS        float64 // device-total receive rate
	TxBPS        float64 // device-total transmit rate
	MemTotal     uint64
	MemUsed      uint64
	MemAvailable uint64
	Load1        float64
	Load5        float64
	Load15       float64
	UptimeSecs   uint64
	Interfaces   []DeviceIfaceSample
}

// InsertDeviceMetrics batch-inserts endpoint samples into device_metrics.
func (d *DB) InsertDeviceMetrics(ctx context.Context, samples []DeviceMetricSample) error {
	if len(samples) == 0 {
		return nil
	}
	batch, err := d.conn.PrepareBatch(ctx, "INSERT INTO device_metrics")
	if err != nil {
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	for _, s := range samples {
		ifaces, err := json.Marshal(s.Interfaces)
		if err != nil {
			ifaces = []byte("[]")
		}
		assetID := s.AssetID
		if assetID == "" {
			assetID = "00000000-0000-0000-0000-000000000000"
		}
		if err := batch.Append(
			mustUUID(s.TenantID), mustUUID(s.SiteID), mustUUID(s.AgentID), mustUUID(assetID),
			s.Timestamp, float32(s.CPUPercent), float32(s.RxBPS), float32(s.TxBPS),
			s.MemTotal, s.MemUsed, s.MemAvailable,
			float32(s.Load1), float32(s.Load5), float32(s.Load15),
			s.UptimeSecs, string(ifaces),
		); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("clickhouse: append: %w", err)
		}
	}
	return batch.Send()
}

// DeviceMetricPoint is one bucket of the device metrics series.
type DeviceMetricPoint struct {
	Bucket     time.Time `json:"ts"`
	CPUAvg     float64   `json:"cpu_avg"`
	CPUMax     float64   `json:"cpu_max"`
	MemUsed    float64   `json:"mem_used"`
	MemTotal   float64   `json:"mem_total"`
	RxBPS      float64   `json:"rx_bps"`
	TxBPS      float64   `json:"tx_bps"`
	UptimeSecs float64   `json:"uptime_secs"`
}

// QueryDeviceMetrics returns time-bucketed aggregates for one device.
// bucketSecs selects the chart resolution (60 for an hour, 300 for a day,
// 3600 for a week). The upper bound is inclusive: live tails pass now,
// range queries pass the requested end so a static window stays static.
func (d *DB) QueryDeviceMetrics(ctx context.Context, tenantID, agentID string, from, to time.Time, bucketSecs int) ([]DeviceMetricPoint, error) {
	if bucketSecs <= 0 {
		bucketSecs = 300
	}
	// avg() always returns Float64, but max() keeps the column type — the
	// cpu/rx/tx columns are Float32 and mem/uptime are UInt64, and the
	// driver only scans those into *float32 / *uint64. Cast every
	// aggregate to Float64 so each row scans into float64 fields.
	rows, err := d.conn.Query(ctx,
		`SELECT toStartOfInterval(timestamp, INTERVAL ? second) AS bucket,
                        avg(cpu_percent), toFloat64(max(cpu_percent)), avg(mem_used), toFloat64(max(mem_total)),
                        avg(rx_bps), avg(tx_bps), toFloat64(max(uptime_secs))
                 FROM device_metrics
                 WHERE tenant_id = ? AND agent_id = ? AND timestamp >= ? AND timestamp <= ?
                 GROUP BY bucket ORDER BY bucket`,
		bucketSecs, mustUUID(tenantID), mustUUID(agentID), from, to)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: device metrics query: %w", err)
	}
	defer rows.Close()
	var out []DeviceMetricPoint
	for rows.Next() {
		var p DeviceMetricPoint
		if err := rows.Scan(&p.Bucket, &p.CPUAvg, &p.CPUMax, &p.MemUsed, &p.MemTotal,
			&p.RxBPS, &p.TxBPS, &p.UptimeSecs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// IfaceSeriesPoint is one bucket of one NIC's rate history (the interface
// table sparklines read these).
type IfaceSeriesPoint struct {
	Name   string    `json:"name"`
	Bucket time.Time `json:"ts"`
	RxBPS  float64   `json:"rx_bps"`
	TxBPS  float64   `json:"tx_bps"`
}

// QueryIfaceSeries returns per-NIC receive/transmit rate history. The
// interfaces column stores a JSON array per sample; ARRAY JOIN with
// JSONExtract flattens it into (bucket, nic) rows before aggregation, so
// the series stays tenant/agent scoped without a separate table.
func (d *DB) QueryIfaceSeries(ctx context.Context, tenantID, agentID string, from, to time.Time, bucketSecs int) ([]IfaceSeriesPoint, error) {
	if bucketSecs <= 0 {
		bucketSecs = 900
	}
	rows, err := d.conn.Query(ctx,
		`SELECT toStartOfInterval(timestamp, INTERVAL ? second) AS bucket,
                        JSONExtractString(iface, 'name') AS name,
                        avg(toFloat64(JSONExtractFloat(iface, 'rx_bps'))) AS rx_avg,
                        avg(toFloat64(JSONExtractFloat(iface, 'tx_bps'))) AS tx_avg
                 FROM device_metrics
                 ARRAY JOIN JSONExtractArrayRaw(interfaces) AS iface
                 WHERE tenant_id = ? AND agent_id = ? AND timestamp >= ? AND timestamp <= ?
                 GROUP BY bucket, name
                 ORDER BY name, bucket`,
		bucketSecs, mustUUID(tenantID), mustUUID(agentID), from, to)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: iface series query: %w", err)
	}
	defer rows.Close()
	var out []IfaceSeriesPoint
	for rows.Next() {
		var p IfaceSeriesPoint
		if err := rows.Scan(&p.Bucket, &p.Name, &p.RxBPS, &p.TxBPS); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// IfaceSeries is one NIC's rate history as the API returns it (sparkline
// columns in the asset interface table).
type IfaceSeries struct {
	Name string    `json:"name"`
	MAC  string    `json:"mac,omitempty"`
	Rx   []float64 `json:"rx"`
	Tx   []float64 `json:"tx"`
}

// DeviceLatestSample is the most recent raw sample of a device.
type DeviceLatestSample struct {
	Timestamp  time.Time           `json:"timestamp"`
	CPUPercent float64             `json:"cpu_percent"`
	RxBPS      float64             `json:"rx_bps"`
	TxBPS      float64             `json:"tx_bps"`
	MemTotal   uint64              `json:"mem_total"`
	MemUsed    uint64              `json:"mem_used"`
	UptimeSecs uint64              `json:"uptime_secs"`
	Ifaces     []DeviceIfaceSample `json:"ifaces"`
}

// LatestDeviceSample returns the newest stored sample (for the "current
// load" header and the per-NIC table on the asset page).
func (d *DB) LatestDeviceSample(ctx context.Context, tenantID, agentID string) (*DeviceLatestSample, error) {
	var (
		s      DeviceLatestSample
		ifaces string
	)
	// The float columns are Float32 in the table; widen them in SQL —
	// the driver refuses to scan Float32 into *float64.
	err := d.conn.QueryRow(ctx,
		`SELECT timestamp, toFloat64(cpu_percent), toFloat64(rx_bps), toFloat64(tx_bps), mem_total, mem_used, uptime_secs, interfaces
                 FROM device_metrics
                 WHERE tenant_id = ? AND agent_id = ?
                 ORDER BY timestamp DESC LIMIT 1`,
		mustUUID(tenantID), mustUUID(agentID)).Scan(
		&s.Timestamp, &s.CPUPercent, &s.RxBPS, &s.TxBPS, &s.MemTotal, &s.MemUsed, &s.UptimeSecs, &ifaces)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // no sample stored yet — an empty state, not a failure
		}
		return nil, fmt.Errorf("clickhouse: latest device sample: %w", err)
	}
	s.Ifaces = []DeviceIfaceSample{}
	if ifaces != "" {
		_ = json.Unmarshal([]byte(ifaces), &s.Ifaces)
	}
	return &s, nil
}
