package postgres

// Regression tests for the interface/MAC persistence bug (v1.15.0 field
// report: "seems like MAC address is gone, we need this field too").
//
// Root cause: InterfaceRepo.Upsert wrote with ON CONFLICT (asset_id, mac)
// and AddIP with ON CONFLICT (interface_id, ip), but migration 0003 created
// only plain indexes on those column pairs. PostgreSQL rejects every such
// write with 42P10 ("there is no unique or exclusion constraint matching
// the ON CONFLICT specification") and ensureInterface swallowed the error —
// so network_interfaces and ip_addresses stayed empty for the whole
// product: no MAC address, no NIC vendor, no observed addresses anywhere.
//
// Migration 0030 backfills the missing unique indexes. This test pins the
// upsert semantics against real Postgres (skipped unless AEGIS_TEST_PG_URL
// is set — the 42P10 failure class only exists inside Postgres).

import (
	"context"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// TestIntegrationInterfaceUpsertAndIPs exercises the interface lifecycle:
// create → matched update (vendor fill, same row) → duplicate insert
// converges on one row → AddIP idempotent → ListForAsset returns the MAC,
// the vendor and exactly the observed addresses.
func TestIntegrationInterfaceUpsertAndIPs(t *testing.T) {
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

	org, err := NewOrgRepo(db).Create(ctx, "iface-org-"+ids.New(), "ifc-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "ifc-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	asset := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "ifc-host", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := NewAssetRepo(db).Insert(ctx, asset); err != nil {
		t.Fatalf("asset insert: %v", err)
	}

	repo := NewInterfaceRepo(db)
	const mac = "b8:27:eb:11:22:33"

	nic1 := &domain.Interface{ID: ids.New(), AssetID: asset.ID, MAC: mac, Status: "unknown",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := repo.Upsert(ctx, nic1); err != nil {
		t.Fatalf("first Upsert failed (missing unique index → 42P10?): %v", err)
	}
	if err := repo.AddIP(ctx, nic1.ID, "192.168.10.25", true); err != nil {
		t.Fatalf("AddIP failed (missing unique index → 42P10?): %v", err)
	}

	// Second observation of the same NIC: fresh row id, richer vendor —
	// must converge on the first row and fill the empty vendor.
	nic2 := &domain.Interface{ID: ids.New(), AssetID: asset.ID, MAC: mac, Vendor: "Raspberry Pi Foundation",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := repo.Upsert(ctx, nic2); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if nic2.ID != nic1.ID {
		t.Fatalf("upsert created a second row (%s) instead of converging on %s", nic2.ID, nic1.ID)
	}

	// AddIP must be idempotent per (interface, ip).
	if err := repo.AddIP(ctx, nic1.ID, "192.168.10.25", true); err != nil {
		t.Fatalf("duplicate AddIP: %v", err)
	}

	list, err := repo.ListForAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListForAsset: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("interfaces = %d rows, want 1", len(list))
	}
	got := list[0]
	if got.MAC != mac {
		t.Fatalf("mac = %q, want %q", got.MAC, mac)
	}
	if got.Vendor != "Raspberry Pi Foundation" {
		t.Fatalf("vendor = %q, want the nmap OUI string filled by the second upsert", got.Vendor)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].IP != "192.168.10.25" {
		t.Fatalf("addresses = %+v, want exactly [192.168.10.25]", got.Addresses)
	}
}

// TestIntegrationSetPrimaryIPConverges pins the primary-address invariant:
// an interface whose ip rows were flagged by report position (the bug that
// made Windows NICs display a link-local IPv6 — the address that happened
// to enumerate first — instead of the IPv4 the machine is reachable on)
// converges to exactly one primary row per interface when SetPrimaryIP
// re-flags by comparison. ListForAsset must return the primary first.
func TestIntegrationSetPrimaryIPConverges(t *testing.T) {
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

	org, err := NewOrgRepo(db).Create(ctx, "iface-org-"+ids.New(), "spg-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "spg-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	asset := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "spg-host", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := NewAssetRepo(db).Insert(ctx, asset); err != nil {
		t.Fatalf("asset insert: %v", err)
	}

	repo := NewInterfaceRepo(db)
	nic := &domain.Interface{ID: ids.New(), AssetID: asset.ID, MAC: "b8:27:eb:aa:bb:cc", Status: "up",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := repo.Upsert(ctx, nic); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Report order as Windows enumerates it: IPv6 (link-local and global)
	// before the IPv4, with the positional is_primary=true of the legacy
	// AddIP callers leaving two flagged rows.
	if err := repo.AddIP(ctx, nic.ID, "fe80::1", true); err != nil {
		t.Fatalf("AddIP fe80::1: %v", err)
	}
	if err := repo.AddIP(ctx, nic.ID, "2a02:6b8:c0e::1", true); err != nil {
		t.Fatalf("AddIP global v6: %v", err)
	}
	if err := repo.AddIP(ctx, nic.ID, "192.168.1.80", true); err != nil {
		t.Fatalf("AddIP v4: %v", err)
	}
	if err := repo.AddIP(ctx, nic.ID, "192.168.1.80", false); err != nil {
		t.Fatalf("duplicate AddIP: %v", err)
	}

	// A second NIC must be untouched by the first one's re-flagging.
	other := &domain.Interface{ID: ids.New(), AssetID: asset.ID, MAC: "b8:27:eb:dd:ee:ff", Status: "up",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := repo.Upsert(ctx, other); err != nil {
		t.Fatalf("Upsert other: %v", err)
	}
	if err := repo.AddIP(ctx, other.ID, "10.0.0.5", true); err != nil {
		t.Fatalf("AddIP other: %v", err)
	}

	if err := repo.SetPrimaryIP(ctx, nic.ID, "192.168.1.80"); err != nil {
		t.Fatalf("SetPrimaryIP: %v", err)
	}

	list, err := repo.ListForAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListForAsset: %v", err)
	}
	byMAC := map[string]domain.Interface{}
	for _, i := range list {
		byMAC[i.MAC] = i
	}
	got := byMAC["b8:27:eb:aa:bb:cc"]
	var primaries []string
	for _, a := range got.Addresses {
		if a.IsPrimary {
			primaries = append(primaries, a.IP)
		}
	}
	if len(primaries) != 1 || primaries[0] != "192.168.1.80" {
		t.Fatalf("primary rows = %v, want exactly [192.168.1.80]", primaries)
	}
	if got.Addresses[0].IP != "192.168.1.80" || !got.Addresses[0].IsPrimary {
		t.Fatalf("first address = %+v, want the primary 192.168.1.80 first", got.Addresses[0])
	}
	otherGot := byMAC["b8:27:eb:dd:ee:ff"]
	if len(otherGot.Addresses) != 1 || !otherGot.Addresses[0].IsPrimary || otherGot.Addresses[0].IP != "10.0.0.5" {
		t.Fatalf("sibling interface disturbed: %+v", otherGot.Addresses)
	}
}
