package postgres

import (
	"context"
	"testing"
)

// A nil DB intentionally proves incomplete scopes are rejected before even
// attempting SQL. This test never opens or touches a database.
func TestReportDetailRejectsIncompleteScope(t *testing.T) {
	repo := NewReportDetailRepo(nil)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		load func() error
	}{
		{"organization", func() error { _, err := repo.Organization(ctx, ""); return err }},
		{"site tenant", func() error { _, err := repo.Site(ctx, "", "site"); return err }},
		{"site id", func() error { _, err := repo.Site(ctx, "org", ""); return err }},
		{"asset tenant", func() error { _, err := repo.Asset(ctx, "", "device"); return err }},
		{"asset id", func() error { _, err := repo.Asset(ctx, "org", ""); return err }},
		{"device children", func() error { _, err := repo.Device(ctx, "", "device"); return err }},
		{"inventory", func() error { _, err := repo.Inventory(ctx, "", "site"); return err }},
		{"networks", func() error { _, err := repo.Networks(ctx, "", "site"); return err }},
		{"scans", func() error { _, err := repo.Scans(ctx, "", "site"); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.load(); err == nil {
				t.Fatal("incomplete scope accepted")
			}
		})
	}
}
