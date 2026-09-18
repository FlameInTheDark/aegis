package organizations_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/organizations"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Integration test: the full first-run bootstrap path against a real
// PostgreSQL instance. Regression for the startup failure where the id
// layer emitted ULID strings into UUID primary keys
// ("invalid input syntax for type uuid: 01M2JKXF3AGSYGTC3TDHQMA2BA").
//
// Skipped unless AEGIS_TEST_PG_URL is set.
func TestIntegrationBootstrapCreatesUUIDv7Rows(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_PG_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_PG_URL not set; skipping integration test")
	}
	ctx := context.Background()
	if err := pg.MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	db, err := pg.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Make the test re-runnable: clear any rows from previous runs.
	if _, err := db.Pool.Exec(ctx, "TRUNCATE users, organizations CASCADE"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	svc := &organizations.Service{
		Orgs:        pg.NewOrgRepo(db),
		Users:       pg.NewUserRepo(db),
		Memberships: pg.NewMembershipRepo(db),
		Sites:       pg.NewSiteRepo(db),
		Networks:    pg.NewNetworkRepo(db),
		Log:         slog.New(slog.DiscardHandler),
	}
	hash, err := auth.HashPassword("aegis-it-admin-2026")
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Bootstrap(ctx, "Aegis", "bootstrap-it@aegis.local", "Platform Administrator", hash)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for _, id := range []string{res.Organization.ID, res.User.ID, res.Site.ID} {
		if !ids.Valid(id) {
			t.Fatalf("bootstrap produced non-UUIDv7 id %q", id)
		}
		if _, err := ids.Time(id); err != nil {
			t.Fatalf("id %q has no extractable timestamp: %v", id, err)
		}
	}
	if _, err := svc.Bootstrap(ctx, "Aegis", "bootstrap-it@aegis.local", "dup", hash); err == nil {
		t.Fatal("second bootstrap must be refused (already initialized)")
	}
}
