package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests against a real PostgreSQL instance.
// Skipped unless AEGIS_TEST_PG_URL is set, e.g.
//
//	AEGIS_TEST_PG_URL=postgres://postgres@127.0.0.1:5433/aegis_it?sslmode=disable go test ./internal/repository/postgres/ -run Integration
func testURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("AEGIS_TEST_PG_URL")
	if u == "" {
		t.Skip("AEGIS_TEST_PG_URL not set; skipping integration test")
	}
	return u
}

func upCount(t *testing.T) int {
	t.Helper()
	files, err := fs.Glob(migrations.Postgres(), "*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("embedded up migrations missing: %v", err)
	}
	return len(files)
}

func currentVersion(t *testing.T, pool *pgxpool.Pool) (uint, bool) {
	t.Helper()
	var v uint
	var dirty bool
	err := pool.QueryRow(context.Background(),
		"SELECT version, dirty FROM schema_migrations").Scan(&v, &dirty)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	return v, dirty
}

func TestIntegrationMigrationsApplyFresh(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	v, dirty := currentVersion(t, pool)
	if dirty {
		t.Fatalf("schema_migrations dirty at version %d", v)
	}
	if want := uint(upCount(t)); v != want {
		t.Fatalf("schema version = %d, want %d", v, want)
	}
}

func TestIntegrationDirtyRecovery(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx := context.Background()

	// Simulate the exact state a failed migration leaves behind: objects of
	// migrations 4..N absent (each failed file rolls back wholesale) and the
	// version row marked dirty at 4.
	n := upCount(t)
	for i := n; i >= 4; i-- {
		matches, err := fs.Glob(migrations.Postgres(), fmt.Sprintf("%04d_*.down.sql", i))
		if err != nil || len(matches) != 1 {
			t.Fatalf("down migration for %04d: %v", i, err)
		}
		sql, err := fs.ReadFile(migrations.Postgres(), matches[0])
		if err != nil {
			t.Fatal(err)
		}
		// Comment lines must go before the ";" split: a semicolon in a
		// comment ("Data-preserving; only the") cut a statement in half
		// and made every recovery run fail with a syntax error.
		var clean strings.Builder
		for _, line := range strings.Split(string(sql), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			clean.WriteString(line)
			clean.WriteString("\n")
		}
		for _, stmt := range strings.Split(clean.String(), ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("down %s: %v", matches[0], err)
			}
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET version = 4, dirty = true"); err != nil {
		t.Fatal(err)
	}

	// Recovery: MigrateUp must clear the dirty state and re-apply 4..N.
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate up after dirty: %v", err)
	}
	v, dirty := currentVersion(t, pool)
	if dirty || v != uint(n) {
		t.Fatalf("after recovery version=%d dirty=%v, want %d clean", v, dirty, n)
	}
}

func TestIntegrationRenamedColumnUpserts(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	ctx := context.Background()
	db, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// detection_rules.refs / detection_rules.window_spec (renamed from the
	// reserved words `references` / `window`) — exercised by rule seeding
	// on every server start.
	orgID := "00000000-0000-7000-8000-000000000001"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug) VALUES ($1::uuid, 'IT Org', 'it-org')
                 ON CONFLICT (id) DO NOTHING`, orgID); err != nil {
		t.Fatal(err)
	}
	rules := NewRuleRepo(db)
	rule := &domain.DetectionRule{
		OrgID: orgID, Title: "Port scan pattern",
		Identifier: "aegis-it-portscan", Status: "stable", References: []string{"https://example.test"},
		Level: "medium", Type: "threshold", Window: "60s", Enabled: true,
	}
	if err := rules.Upsert(ctx, rule); err != nil {
		t.Fatalf("rule upsert: %v", err)
	}
	got, err := rules.ByID(ctx, rule.OrgID, rule.ID)
	if err != nil {
		t.Fatalf("rule by id: %v", err)
	}
	if got.Window != "60s" || len(got.References) != 1 {
		t.Fatalf("round-trip mismatch: window=%q refs=%v", got.Window, got.References)
	}

	// osv_records.refs (renamed from `references`) — exercised by feed-worker.
	vulns := NewVulnRepo(db)
	rec := &domain.OSVRecord{
		ID: "GHSA-it-0001", CVEIDs: []string{"CVE-2026-0001"}, Ecosystem: "Go",
		PackageName: "example.test/pkg", References: []string{"https://example.test/advisory"}, Source: "osv",
	}
	if err := vulns.UpsertOSV(ctx, rec); err != nil {
		t.Fatalf("osv upsert: %v", err)
	}
	recs, err := vulns.OSVForPackage(ctx, "Go", "example.test/pkg")
	if err != nil || len(recs) != 1 {
		t.Fatalf("osv for package: n=%d err=%v", len(recs), err)
	}
}
