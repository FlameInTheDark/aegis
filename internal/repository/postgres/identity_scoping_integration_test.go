package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// The Phase 0 P0 acceptance items touching the Postgres layer (skipped
// without a live database, like the other integration tests):
//   - FindingRepo.Upsert distinguishes a real INSERT from a refresh —
//     "new finding" counts and finding.created events need the difference.
//   - Identifier lookups are organization-scoped in the QUERY: one tenant's
//     hostname/MAC/address must never surface in another tenant's
//     candidate sets, and an empty orgID fails closed.

func TestIntegrationFindingUpsertReportsCreatedVsRefreshed(t *testing.T) { //nolint:dupl // setup mirrors the other integration tests
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

	org, err := NewOrgRepo(db).Create(ctx, "upsert-org-"+ids.New(), "ups-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "upsert-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	now := time.Now().UTC()
	asset := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "upsert-host", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
		FirstSeen: now, LastSeen: now}
	if err := NewAssetRepo(db).Insert(ctx, asset); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	repo := NewFindingRepo(db)
	f := &domain.Finding{
		ID: ids.New(), OrganizationID: org.ID, AssetID: asset.ID,
		CVEID: "CVE-2026-9001", Title: "Upsert outcome probe",
		MatchType: domain.MatchCPERange, Confidence: 0.9, RiskScore: 6.0,
		Severity: domain.SeverityMedium, Status: domain.FindingOpen,
		FirstSeen: now, LastSeen: now,
	}

	created, err := repo.Upsert(ctx, f)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created {
		t.Fatalf("first upsert must report created=true")
	}

	// Refreshing the same conflict key (asset/CVE/service) must report a
	// refresh, not a second creation — "new finding" counts used to be
	// inflated because every refresh reported a creation.
	f.Title = "Upsert outcome probe (refreshed)"
	f.RiskScore = 6.5
	created, err = repo.Upsert(ctx, f)
	if err != nil {
		t.Fatalf("refresh upsert: %v", err)
	}
	if created {
		t.Fatalf("refresh upsert must report created=false")
	}
}

func TestIntegrationIdentifierLookupIsOrganizationScoped(t *testing.T) {
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

	assets := NewAssetRepo(db)
	ident := NewIdentifierRepo(db)
	now := time.Now().UTC()

	// Two tenants, each registering a machine with the SAME hostname.
	var orgs []*domain.Organization
	var perOrg []*domain.Asset
	for i := 0; i < 2; i++ {
		org, err := NewOrgRepo(db).Create(ctx, "scope-org-"+ids.New(), "scp-"+ids.New())
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "scope-site", SiteType: "lab",
			CreatedAt: now, UpdatedAt: now}
		if err := NewSiteRepo(db).Create(ctx, site); err != nil {
			t.Fatalf("create site: %v", err)
		}
		a := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
			Hostname: "shared-host", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
			FirstSeen: now, LastSeen: now}
		if err := assets.Insert(ctx, a); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		if err := ident.Upsert(ctx, a.ID, "hostname", "shared-host", 0.9); err != nil {
			t.Fatalf("upsert identifier: %v", err)
		}
		perOrg = append(perOrg, a)
		orgs = append(orgs, org)
	}

	// A lookup from tenant A must see only tenant A's asset — a global
	// lookup used to leak foreign candidates into matching and merging.
	var orgIDs []string
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}
	holders, err := ident.FindByIdentifier(ctx, orgIDs[0], "hostname", "shared-host")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(holders) != 1 || holders[0] != perOrg[0].ID {
		t.Fatalf("org A holders = %v, want only [%s]", holders, perOrg[0].ID)
	}

	// An empty orgID fails closed — identity resolution without tenancy is
	// a bug, not a lookup mode.
	if holders, err := ident.FindByIdentifier(ctx, "", "hostname", "shared-host"); err != nil || len(holders) != 0 {
		t.Fatalf("empty orgID must fail closed, got %v (err %v)", holders, err)
	}
}
