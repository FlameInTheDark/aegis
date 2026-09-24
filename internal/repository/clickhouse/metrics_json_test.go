// API contract of the metrics tier: the asset page reads snake_case keys
// from /assets/:id/metrics (AssetMetricLatest in web/src/data/types.ts).
// A missing json tag here silently blanks the "current load" tiles.

package clickhouse

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeviceLatestSampleJSONKeys(t *testing.T) {
	s := DeviceLatestSample{
		Timestamp:  time.Date(2026, 9, 23, 21, 0, 0, 0, time.UTC),
		CPUPercent: 42.5,
		RxBPS:      1000000,
		TxBPS:      2000000,
		MemTotal:   16 << 30,
		MemUsed:    8 << 30,
		UptimeSecs: 3600,
		Ifaces:     []DeviceIfaceSample{{Name: "eth0", RxBytes: 1, TxBytes: 2, RxBPS: 3, TxBPS: 4}},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"timestamp", "cpu_percent", "rx_bps", "tx_bps", "mem_total", "mem_used", "uptime_secs", "ifaces"} {
		if _, ok := m[key]; !ok {
			t.Errorf("DeviceLatestSample JSON is missing key %q", key)
		}
	}
	iface, ok := m["ifaces"].([]any)
	if !ok || len(iface) != 1 {
		t.Fatalf("ifaces: want 1 element, got %v", m["ifaces"])
	}
	first, ok := iface[0].(map[string]any)
	if !ok {
		t.Fatalf("ifaces[0]: not an object: %v", iface[0])
	}
	for _, key := range []string{"name", "rx_bytes", "tx_bytes", "rx_bps", "tx_bps"} {
		if _, ok := first[key]; !ok {
			t.Errorf("DeviceIfaceSample JSON is missing key %q", key)
		}
	}
}

func TestDeviceMetricPointJSONKeys(t *testing.T) {
	p := DeviceMetricPoint{Bucket: time.Date(2026, 9, 23, 21, 0, 0, 0, time.UTC), CPUAvg: 1, CPUMax: 2}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"ts", "cpu_avg", "cpu_max", "mem_used", "mem_total", "rx_bps", "tx_bps", "uptime_secs"} {
		if _, ok := m[key]; !ok {
			t.Errorf("DeviceMetricPoint JSON is missing key %q", key)
		}
	}
}
