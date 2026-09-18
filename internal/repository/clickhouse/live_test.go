package clickhouse

import (
	"context"
	"io"
	neturl "net/url"
	"os"
	"testing"
	"time"

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

func urlWithoutUser(raw string) (string, error) {
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = nil
	return u.String(), nil
}
