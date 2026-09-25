package postgres

// Integration test for AssetRepo.Delete — the analyst's "remove this asset"
// path (v1.26.6): deletion is the remedy for false discoveries and departed
// hosts, so it must cascade every dependent row, unbind the endpoint device
// (agents.asset_id is ON DELETE SET NULL) so its next inventory report
// re-provisions a fresh asset, and stay organization-scoped. Rediscovery
// itself is covered by the agent-side rematch tests (internal/agents) and
// ProvisionHost; here we pin the data-layer contract. Proven against real
// Postgres (skipped unless AEGIS_TEST_PG_URL is set).

import (
	"context"
	"testing"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

func TestIntegrationAssetDelete(t *testing.T) {
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

	org, err := NewOrgRepo(db).Create(ctx, "delete-org-"+ids.New(), "del-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "delete-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}

	assets := NewAssetRepo(db)
	now := time.Now().UTC()
	// The victim: a false discovery carrying every kind of dependent row —
	// identifier, interface + address, MAC, service, software, finding,
	// group membership and a bound endpoint device.
	victim := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "ghost-discovery", HasAgent: true, Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now}
	if err := assets.Insert(ctx, victim); err != nil {
		t.Fatalf("victim insert: %v", err)
	}
	// A second asset in the same org that must survive untouched.
	survivor := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "survivor", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
		FirstSeen: now, LastSeen: now}
	if err := assets.Insert(ctx, survivor); err != nil {
		t.Fatalf("survivor insert: %v", err)
	}

	ident := NewIdentifierRepo(db)
	if err := ident.Upsert(ctx, victim.ID, "ip", "10.9.9.9", 0.6); err != nil {
		t.Fatalf("identifier: %v", err)
	}
	ifaces := NewInterfaceRepo(db)
	const nicMAC = "02:aa:bb:cc:dd:ee"
	nic := &domain.Interface{ID: ids.New(), AssetID: victim.ID, MAC: nicMAC, Name: "eth0",
		Status: "up", FirstSeen: now, LastSeen: now}
	if err := ifaces.Upsert(ctx, nic); err != nil {
		t.Fatalf("iface: %v", err)
	}
	if err := ifaces.AddIP(ctx, nic.ID, "10.9.9.9", true); err != nil {
		t.Fatalf("iface ip: %v", err)
	}
	if _, err := db.Exec(ctx, db.Insert("mac_addresses").
		Columns("id", "asset_id", "mac", "vendor").
		Values(ids.New(), victim.ID, nicMAC, "Test Vendor")); err != nil {
		t.Fatalf("mac row: %v", err)
	}

	services := NewServiceRepo(db)
	victimSvc := &domain.Service{ID: ids.New(), AssetID: victim.ID, OrganizationID: org.ID,
		Protocol: "tcp", Port: 8080, ServiceName: "http", State: "open",
		Exposure: domain.ExposureInternal, FirstSeen: now, LastSeen: now}
	if err := services.Upsert(ctx, victimSvc); err != nil {
		t.Fatalf("service: %v", err)
	}
	software := NewSoftwareRepo(db)
	if err := software.Upsert(ctx, &domain.Software{ID: ids.New(), AssetID: victim.ID,
		Name: "ghost-app", Version: "1.0", Ecosystem: "os_linux", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("software: %v", err)
	}
	if _, err := NewFindingRepo(db).Upsert(ctx, &domain.Finding{ID: ids.New(), OrganizationID: org.ID, AssetID: victim.ID,
		ServiceID: &victimSvc.ID, CVEID: "CVE-2026-0001", Title: "Ghost service vulnerable",
		MatchType: domain.MatchServiceVersion, Confidence: 0.8, RiskScore: 7.5,
		Severity: domain.SeverityHigh, Status: domain.FindingOpen, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("finding: %v", err)
	}

	groups := NewGroupRepo(db)
	group := &domain.AssetGroup{ID: ids.New(), OrgID: org.ID, Name: "temp-" + ids.New()[:8],
		Color: "slate", Icon: "boxes", Kind: "custom", CreatedAt: now, UpdatedAt: now}
	if err := groups.Create(ctx, group); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := groups.AddMembers(ctx, org.ID, group.ID, []string{victim.ID}); err != nil {
		t.Fatalf("group membership: %v", err)
	}

	deviceID := ids.New()
	agentRepo := NewAgentRepo(db)
	if err := agentRepo.Enroll(ctx, &domain.Agent{ID: deviceID, OrganizationID: org.ID, SiteID: site.ID,
		AssetID: &victim.ID, Hostname: "ghost-discovery", Platform: "linux", Status: "online",
		LastSeen: now, EnrolledAt: now}); err != nil {
		t.Fatalf("enroll device: %v", err)
	}

	// Organization scoping first: a delete keyed to a foreign organization is
	// a no-op, never a cross-org deletion.
	if err := assets.Delete(ctx, "00000000-0000-0000-0000-000000000000", survivor.ID); err != nil {
		t.Fatalf("foreign-org delete must not error: %v", err)
	}
	if a, err := assets.ByID(ctx, org.ID, survivor.ID); err != nil || a == nil {
		t.Fatalf("survivor must survive a foreign-org delete: %v %+v", err, a)
	}

	// --- the delete
	if err := assets.Delete(ctx, org.ID, victim.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Idempotent: repeating it must not error (the where clause matches nothing).
	if err := assets.Delete(ctx, org.ID, victim.ID); err != nil {
		t.Fatalf("repeat delete must be a no-op, got %v", err)
	}

	if a, err := assets.ByID(ctx, org.ID, victim.ID); err == nil && a != nil {
		t.Fatalf("asset must be gone, got %+v", a)
	}

	// Identifiers cascaded: the address no longer resolves to any asset.
	holders, err := ident.FindByIdentifier(ctx, org.ID, "ip", "10.9.9.9")
	if err != nil {
		t.Fatalf("find identifier: %v", err)
	}
	if len(holders) != 0 {
		t.Fatalf("identifiers must cascade with the asset, holders: %v", holders)
	}

	// Interfaces (and their addresses) and MAC rows cascaded.
	if rows, err := ifaces.ListForAsset(ctx, victim.ID); err != nil || len(rows) != 0 {
		t.Fatalf("interfaces must cascade with the asset: %v %+v", err, rows)
	}
	var macCount int
	if err := db.QueryRow(ctx, db.Select("count(*)").From("mac_addresses").
		Where(squirrel.Eq{"asset_id": victim.ID})).Scan(&macCount); err != nil {
		t.Fatalf("count mac rows: %v", err)
	}
	if macCount != 0 {
		t.Fatalf("mac_addresses rows must cascade with the asset, got %d", macCount)
	}

	// Services, software and findings cascaded.
	if rows, err := services.ListForAsset(ctx, victim.ID); err != nil || len(rows) != 0 {
		t.Fatalf("services must cascade with the asset: %v %+v", err, rows)
	}
	if rows, err := software.ListForAsset(ctx, victim.ID); err != nil || len(rows) != 0 {
		t.Fatalf("software must cascade with the asset: %v %+v", err, rows)
	}
	if rows, err := NewFindingRepo(db).ListForAsset(ctx, victim.ID); err != nil || len(rows) != 0 {
		t.Fatalf("findings must cascade with the asset: %v %+v", err, rows)
	}

	// Group membership cascaded; the group itself survives.
	g, err := groups.ByID(ctx, org.ID, group.ID)
	if err != nil {
		t.Fatalf("group by id: %v", err)
	}
	for _, m := range g.AssetIDs {
		if m == victim.ID {
			t.Fatal("the deleted asset must not remain a group member")
		}
	}

	// The endpoint device survives but is unlinked, so its next inventory
	// report goes through the rematch/provision path and re-creates the asset.
	dev, err := agentRepo.ByID(ctx, org.ID, deviceID)
	if err != nil {
		t.Fatalf("device by id: %v", err)
	}
	if dev.AssetID != nil && *dev.AssetID != "" {
		t.Fatalf("the device must be unlinked after the asset delete, asset_id: %v", *dev.AssetID)
	}

	// The unrelated asset in the same org is untouched.
	if a, err := assets.ByID(ctx, org.ID, survivor.ID); err != nil || a == nil {
		t.Fatalf("survivor must remain after the victim delete: %v %+v", err, a)
	}
}
