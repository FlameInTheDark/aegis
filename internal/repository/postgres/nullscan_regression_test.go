package postgres

// Regression tests for the pgx NULL-scan bug class and broken count queries
// reported from the demo deployment (< 1.0.10):
//
//   - pgx v5 cannot scan SQL NULL into plain Go string fields
//     ("cannot scan NULL into *string") — every nullable TEXT/UUID/INET
//     column must be COALESCEd in the select list (or scanned into pointers).
//   - appending count(*) to a column list (or a window count on an empty
//     table) made list endpoints 500.
//
// Run with: AEGIS_TEST_PG_URL=postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable \
//   go test ./internal/repository/postgres/ -run TestIntegrationNullScanRegression

import (
	"context"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// setupNullFixture creates a fresh org + site and returns their ids.
func setupNullFixture(t *testing.T, db *DB) (orgID, siteID string) {
	t.Helper()
	org, err := NewOrgRepo(db).Create(context.Background(), "nullscan-org-"+ids.New(), "ns-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "ns-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(context.Background(), site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	return org.ID, site.ID
}

func TestIntegrationNullScanRegression(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	db, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	orgID, siteID := setupNullFixture(t, db)

	// --- audit: seed-style row with NULL actor_id/actor_name/actor_ip/target/site_id
	if _, err := db.Pool.Exec(ctx, `INSERT INTO audit_logs (id, organization_id, actor_id, action, target, result, detail)
		VALUES ($1, $2, NULL, 'scan.created', NULL, 'success', '{"profile":"inventory"}'::jsonb)`, ids.New(), orgID); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}
	entries, _, err := NewAuditRepo(db).List(ctx, orgID, Page{Limit: 10, Page: 1})
	if err != nil {
		t.Fatalf("AuditRepo.List with NULL columns: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("audit list returned no rows")
	}
	// empty table for a different org must not ErrNoRows on the count
	if _, _, err := NewAuditRepo(db).List(ctx, ids.New(), Page{Limit: 10, Page: 1}); err != nil {
		t.Fatalf("AuditRepo.List on empty org: %v", err)
	}

	// --- feeds: EnsureSource leaves last_sync_at/last_error NULL
	if err := NewFeedRepo(db).EnsureSource(ctx, "nvd", "public"); err != nil {
		t.Fatalf("EnsureSource: %v", err)
	}
	feeds, err := NewFeedRepo(db).Sources(ctx)
	if err != nil {
		t.Fatalf("FeedRepo.Sources with NULL last_error: %v", err)
	}
	if len(feeds) == 0 {
		t.Fatal("feed sources empty")
	}

	// --- scans: queued scan with NULL scanner_id/created_by/error/schedule_cron
	if err := NewProfileRepo(db).Sync(ctx, domain.Profiles); err != nil {
		t.Fatalf("profile sync: %v", err)
	}
	scan := &domain.Scan{ID: ids.New(), OrganizationID: orgID, SiteID: siteID,
		Name: "ns-scan", Profile: domain.ProfileInventory, Engine: "nmap", State: domain.ScanQueued}
	scope := &domain.ScanScope{CIDRs: []string{"192.168.99.0/24"}}
	if err := NewScanRepo(db).Create(ctx, scan, scope); err != nil {
		t.Fatalf("scan create: %v", err)
	}
	scans, _, err := NewScanRepo(db).List(ctx, ScanListFilter{OrgID: orgID, Limit: 10, Page: 1})
	if err != nil {
		t.Fatalf("ScanRepo.List with NULL scan columns: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("scan list rows = %d, want 1", len(scans))
	}

	// --- scan_tasks: NULL scanner_id/target/error
	if _, err := db.Pool.Exec(ctx, `INSERT INTO scan_tasks (id, scan_id, type, state)
		VALUES ($1, $2, 'discovery', 'pending')`, ids.New(), scan.ID); err != nil {
		t.Fatalf("seed task row: %v", err)
	}
	if _, err := NewTaskRepo(db).ListForScan(ctx, scan.ID); err != nil {
		t.Fatalf("TaskRepo.ListForScan with NULL task columns: %v", err)
	}

	// --- networks: create with empty gateway -> NULL inet, then list
	net := &domain.Network{ID: ids.New(), SiteID: siteID, OrganizationID: orgID,
		CIDR: "192.168.99.0/24", Name: "ns-net", Exposure: domain.ExposureInternal,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewNetworkRepo(db).Create(ctx, net); err != nil {
		t.Fatalf("network create with empty gateway: %v", err)
	}
	nets, err := NewNetworkRepo(db).ListBySite(ctx, siteID)
	if err != nil {
		t.Fatalf("NetworkRepo.ListBySite with NULL gateway: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("network list rows = %d, want 1", len(nets))
	}

	// --- detection_matches: NULL site_id/asset_id/src_ip
	org := orgID
	if _, err := db.Pool.Exec(ctx, `INSERT INTO detection_rules (id, organization_id, title, identifier, status, description, author, level, type)
		VALUES ($1, $2, 'ns-rule', 'ns-rule-1', 'stable', '', 'aegis', 'medium', 'threshold')`, ids.New(), org); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO detection_matches (id, organization_id, rule_id, rule_title, level, summary, event_ids, count, timestamp)
		VALUES ($1, $2, $3, 'ns-rule', 'medium', 'ns match', ARRAY[]::text[], 1, now())`,
		ids.New(), org, "00000000-0000-4000-8000-000000006001"); err != nil {
		t.Fatalf("seed match: %v", err)
	}
	if _, _, err := NewMatchRepo(db).List(ctx, MatchFilter{OrgID: org, Limit: 10, Page: 1}); err != nil {
		t.Fatalf("MatchRepo.List with NULL match columns: %v", err)
	}

	// --- reports + jobs: NULL site_id/scan_id/min_severity/error
	rep := &domain.ReportDefinition{OrganizationID: org, Name: "ns-report", Type: domain.ReportExecutive,
		Format: domain.ReportPDF, Sections: []string{"summary"}, CreatedAt: time.Now().UTC()}
	if err := NewReportRepo(db).Create(ctx, rep); err != nil {
		t.Fatalf("report create: %v", err)
	}
	if _, err := NewReportRepo(db).List(ctx, org); err != nil {
		t.Fatalf("ReportRepo.List with NULL columns: %v", err)
	}
	if err := NewReportRepo(db).CreateJob(ctx, &domain.ReportJob{ID: ids.New(), Definition: rep.ID, OrgID: org, State: "queued"}); err != nil {
		t.Fatalf("report job create: %v", err)
	}
	if _, err := NewReportRepo(db).ListJobs(ctx, org, 10); err != nil {
		t.Fatalf("ReportRepo.ListJobs with NULL error: %v", err)
	}

	// --- services: row with NULL tls/http
	asset := &domain.Asset{ID: ids.New(), OrganizationID: orgID, SiteID: siteID,
		Hostname: "ns-host", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := NewAssetRepo(db).Insert(ctx, asset); err != nil {
		t.Fatalf("asset insert: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO services (id, asset_id, organization_id, protocol, port, service_name)
		VALUES ($1, $2, $3, 'tcp', 9999, 'ns-svc')`, ids.New(), asset.ID, orgID); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	if _, _, err := NewServiceRepo(db).List(ctx, ServiceFilter{OrgID: orgID, Limit: 10, Page: 1}); err != nil {
		t.Fatalf("ServiceRepo.List with NULL tls/http: %v", err)
	}
}
