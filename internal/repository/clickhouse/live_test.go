package clickhouse

import (
	"context"
	"io"
	neturl "net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/migrations"
)

// chSchema loads the embedded ClickHouse schema the same way cmd/server does.
func chSchema() func() ([]byte, error) {
	return func() ([]byte, error) {
		f, err := migrations.ClickHouse().Open("001_schema.sql")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(f)
	}
}

// Live end-to-end test against a real ClickHouse (e.g. the compose service or
// a local server). Skipped unless AEGIS_TEST_CH_URL is set, so plain
// `go test ./...` stays hermetic:
//
//	AEGIS_TEST_CH_URL='clickhouse://aegis:aegis-ch-dev@localhost:9000?database=aegis' \
//	  go test ./internal/repository/clickhouse/ -run TestLive -v
//
// The URL MUST carry credentials: the official docker image removes its
// passwordless `default` user when CLICKHOUSE_USER is configured, and host
// connections are otherwise rejected with a generic 516 "Authentication
// failed" (see deploy/compose/docker-compose.yml).
func TestLiveConnectAppliesSchemaAndQueries(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_CH_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_CH_URL not set; skipping live ClickHouse test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := Connect(ctx, url, chSchema())
	if err != nil {
		t.Fatalf("connect+schema: %v", err)
	}
	defer db.Close()

	// Schema applied means the `aegis` database exists; a query against a
	// real table proves the whole path (auth, database, DDL, query).
	tenant := "00000000-0000-7000-8000-000000000000"
	if _, err := db.QueryEvents(ctx, EventFilter{TenantID: tenant}); err != nil {
		t.Fatalf("query security_events after schema: %v", err)
	}

	// Round-trip: batch insert (UUID + IPv6 columns) then read back.
	ev := domain.Event{
		EventID:       "00000000-0000-7000-8000-00000000feed",
		TenantID:      tenant,
		SiteID:        "00000000-0000-7000-8000-00000000site",
		AgentID:       "00000000-0000-7000-8000-00000000age1",
		Timestamp:     time.Now().UTC(),
		EventType:     "alert",
		Source:        "suricata",
		SchemaVersion: "1",
		SrcIP:         "192.168.1.10",
		SrcPort:       51000,
		DstIP:         "10.0.0.5",
		DstPort:       443,
		Protocol:      "tcp",
		Direction:     "outbound",
		Severity:      domain.SeverityHigh,
		Action:        "alert",
		RuleName:      "live-test rule",
		Hostname:      "host-a",
	}
	if err := db.InsertEvents(ctx, []domain.Event{ev}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	got, err := db.QueryEvents(ctx, EventFilter{TenantID: tenant, Limit: 10})
	if err != nil {
		t.Fatalf("query inserted event: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("inserted event not visible in query")
	}
}

// Without credentials the connection must fail loudly (the image's `default`
// user is localhost-only or removed entirely) — never silently degrade.
func TestLiveConnectRejectsAnonymous(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_CH_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_CH_URL not set; skipping live ClickHouse test")
	}
	u, err := urlWithoutUser(url)
	if err != nil {
		t.Fatalf("rewrite url: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := Connect(ctx, u, nil); err == nil {
		t.Fatal("anonymous connect must fail against a credentialed server")
	}
}

// Round-trip for the device performance metrics tier: insert samples
// through the batch writer and read them back through both chart queries.
// Guards the scan-type contract — the table stores Float32/UInt64 columns
// and the driver only widens them when the SQL casts to Float64.
func TestLiveDeviceMetricsRoundTrip(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_CH_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_CH_URL not set; skipping live ClickHouse test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := Connect(ctx, url, chSchema())
	if err != nil {
		t.Fatalf("connect+schema: %v", err)
	}
	defer db.Close()

	const (
		tenant = "00000000-0000-7000-8000-000000000000"
		site   = "00000000-0000-7000-8000-00000000site"
	)
	// Random device/asset ids per run: the table keeps rows (30-day TTL), so
	// fixed ids would collide with leftovers from a previous run.
	agent := uuid.NewString()
	asset := uuid.NewString()
	base := time.Now().UTC().Truncate(time.Minute) // full-minute timestamps land in distinct 60s buckets
	ifaces := []DeviceIfaceSample{
		{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", RxBytes: 1000, TxBytes: 2000, RxBPS: 1000000, TxBPS: 2000000},
	}
	samples := []DeviceMetricSample{
		{TenantID: tenant, SiteID: site, AgentID: agent, AssetID: asset, Timestamp: base.Add(-time.Minute),
			CPUPercent: 42.5, RxBPS: 1000000, TxBPS: 2000000,
			MemTotal: 16 << 30, MemUsed: 8 << 30, MemAvailable: 8 << 30,
			Load1: 1.5, Load5: 1.25, Load15: 0.75, UptimeSecs: 3600, Interfaces: ifaces},
		{TenantID: tenant, SiteID: site, AgentID: agent, AssetID: asset, Timestamp: base,
			CPUPercent: 57.5, RxBPS: 3000000, TxBPS: 4000000,
			MemTotal: 16 << 30, MemUsed: 9 << 30, MemAvailable: 7 << 30,
			Load1: 2.5, Load5: 2.25, Load15: 1.75, UptimeSecs: 3660, Interfaces: ifaces},
	}
	if err := db.InsertDeviceMetrics(ctx, samples); err != nil {
		t.Fatalf("insert samples: %v", err)
	}

	from := base.Add(-2 * time.Minute)
	points, err := db.QueryDeviceMetrics(ctx, tenant, agent, from, base.Add(time.Minute), 60)
	if err != nil {
		t.Fatalf("query device metrics: %v", err) // Float32/UInt64 → *float64 scan mismatch lands here
	}
	if len(points) != 2 {
		t.Fatalf("want 2 buckets, got %d", len(points))
	}
	first, second := points[0], points[1]
	if first.CPUAvg != 42.5 || first.CPUMax != 42.5 {
		t.Errorf("bucket 1 cpu: got avg=%v max=%v, want 42.5/42.5", first.CPUAvg, first.CPUMax)
	}
	if second.CPUAvg != 57.5 || second.CPUMax != 57.5 {
		t.Errorf("bucket 2 cpu: got avg=%v max=%v, want 57.5/57.5", second.CPUAvg, second.CPUMax)
	}
	if first.MemTotal != float64(16<<30) || first.MemUsed != float64(8<<30) {
		t.Errorf("bucket 1 memory: got used=%v total=%v", first.MemUsed, first.MemTotal)
	}
	if second.UptimeSecs != 3660 {
		t.Errorf("bucket 2 uptime: got %v, want 3660", second.UptimeSecs)
	}

	latest, err := db.LatestDeviceSample(ctx, tenant, agent)
	if err != nil {
		t.Fatalf("latest sample: %v", err)
	}
	if latest == nil {
		t.Fatal("latest sample: nil after insert")
	}
	if latest.CPUPercent != 57.5 || latest.RxBPS != 3000000 || latest.TxBPS != 4000000 {
		t.Errorf("latest floats: cpu=%v rx=%v tx=%v, want 57.5/3e6/4e6", latest.CPUPercent, latest.RxBPS, latest.TxBPS)
	}
	if latest.MemTotal != 16<<30 || latest.MemUsed != 9<<30 || latest.UptimeSecs != 3660 {
		t.Errorf("latest counters: total=%d used=%d uptime=%d", latest.MemTotal, latest.MemUsed, latest.UptimeSecs)
	}
	if len(latest.Ifaces) != 1 || latest.Ifaces[0].Name != "eth0" || latest.Ifaces[0].RxBPS != 1000000 {
		t.Errorf("latest interfaces: %+v", latest.Ifaces)
	}

	// Per-NIC series (interface sparklines): the JSON interfaces column is
	// flattened through ARRAY JOIN + JSONExtract; both samples carry eth0.
	ifaceRows, err := db.QueryIfaceSeries(ctx, tenant, agent, from, base.Add(time.Minute), 60)
	if err != nil {
		t.Fatalf("iface series: %v", err)
	}
	if len(ifaceRows) != 2 {
		t.Fatalf("iface series: want 2 rows (2 buckets x eth0), got %d", len(ifaceRows))
	}
	if ifaceRows[0].Name != "eth0" || ifaceRows[0].RxBPS != 1000000 || ifaceRows[0].TxBPS != 2000000 {
		t.Errorf("iface series row 1: %+v", ifaceRows[0])
	}
	if ifaceRows[1].Name != "eth0" || ifaceRows[1].RxBPS != 3000000 || ifaceRows[1].TxBPS != 4000000 {
		t.Errorf("iface series row 2: %+v", ifaceRows[1])
	}
}

func urlWithoutUser(raw string) (string, error) {
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = nil
	return u.String(), nil
}
