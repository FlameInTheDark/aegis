package postgres

// Integration test for MergeAssets — the duplicate-cleanup half of identity
// convergence (v1.26.5): when a device adopts its machine's original asset,
// the abandoned duplicate is folded into it and removed. The move is full of
// unique constraints ((asset_id, mac), (interface_id, ip),
// (asset_id, protocol, port), (asset_id, name, version, ecosystem), the
// NULL-safe findings dedup triple), so the merge is only proven against real
// Postgres (skipped unless AEGIS_TEST_PG_URL is set).

import (
	"context"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

func TestIntegrationAssetMerge(t *testing.T) {
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

	org, err := NewOrgRepo(db).Create(ctx, "merge-org-"+ids.New(), "mrg-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "merge-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}

	assets := NewAssetRepo(db)
	now := time.Now().UTC()
	// The machine's original asset, created by a scan: holds the management
	// address, the NIC (Ethernet MAC), one service and one package.
	target := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "desktop-rufjn45", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
		FirstSeen: now.Add(-14 * 24 * time.Hour), LastSeen: now}
	if err := assets.Insert(ctx, target); err != nil {
		t.Fatalf("target insert: %v", err)
	}
	// The duplicate, created by the endpoint before identity persistence: a
	// hostname husk with its own copy of the interface, an extra NIC, a
	// colliding service, packages, identifiers and a bound device.
	orphan := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
		Hostname: "DESKTOP-RUFJN45", HasAgent: true, Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
		FirstSeen: now.Add(-1 * time.Hour), LastSeen: now}
	if err := assets.Insert(ctx, orphan); err != nil {
		t.Fatalf("orphan insert: %v", err)
	}

	ident := NewIdentifierRepo(db)
	if err := ident.Upsert(ctx, target.ID, "ip", "192.168.1.80", 0.6); err != nil {
		t.Fatalf("seed target ip: %v", err)
	}
	if err := ident.Upsert(ctx, orphan.ID, "hostname", "desktop-rufjn45", 0.9); err != nil {
		t.Fatalf("seed orphan hostname: %v", err)
	}
	if err := ident.Upsert(ctx, orphan.ID, "ip", "192.168.1.80", 0.6); err != nil {
		t.Fatalf("seed orphan ip: %v", err)
	}
	if err := ident.Upsert(ctx, orphan.ID, "ip", "10.8.0.2", 0.5); err != nil {
		t.Fatalf("seed orphan vpn ip: %v", err)
	}

	ifaces := NewInterfaceRepo(db)
	const ethernet = "aa:bb:cc:dd:ee:ff"
	const usb = "02:11:22:33:44:55"
	targetNIC := &domain.Interface{ID: ids.New(), AssetID: target.ID, MAC: ethernet, Name: "Ethernet",
		Status: "up", FirstSeen: now.Add(-14 * 24 * time.Hour), LastSeen: now}
	if err := ifaces.Upsert(ctx, targetNIC); err != nil {
		t.Fatalf("target iface: %v", err)
	}
	if err := ifaces.AddIP(ctx, targetNIC.ID, "192.168.1.80", false); err != nil {
		t.Fatalf("target iface ip: %v", err)
	}
	orphanNIC := &domain.Interface{ID: ids.New(), AssetID: orphan.ID, MAC: ethernet, Name: "Ethernet",
		Status: "up", FirstSeen: now.Add(-1 * time.Hour), LastSeen: now}
	if err := ifaces.Upsert(ctx, orphanNIC); err != nil {
		t.Fatalf("orphan iface: %v", err)
	}
	// An address the target's Ethernet NIC does not hold yet: the merge must
	// donate it to the target's NIC.
	if err := ifaces.AddIP(ctx, orphanNIC.ID, "192.168.1.81", false); err != nil {
		t.Fatalf("orphan iface ip: %v", err)
	}
	usbNIC := &domain.Interface{ID: ids.New(), AssetID: orphan.ID, MAC: usb, Name: "USB Ethernet",
		Status: "down", FirstSeen: now, LastSeen: now}
	if err := ifaces.Upsert(ctx, usbNIC); err != nil {
		t.Fatalf("orphan usb iface: %v", err)
	}
	if err := ifaces.AddIP(ctx, usbNIC.ID, "192.168.1.82", false); err != nil {
		t.Fatalf("orphan usb iface ip: %v", err)
	}

	services := NewServiceRepo(db)
	// Port 443 exists on BOTH assets (the colliding move); port 8443 only on
	// the duplicate (the plain re-key).
	if err := services.Upsert(ctx, &domain.Service{ID: ids.New(), AssetID: target.ID, OrganizationID: org.ID,
		Protocol: "tcp", Port: 443, ServiceName: "https", State: "open",
		Exposure: domain.ExposureInternal, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("target svc 443: %v", err)
	}
	orphanSVC443 := &domain.Service{ID: ids.New(), AssetID: orphan.ID, OrganizationID: org.ID,
		Protocol: "tcp", Port: 443, ServiceName: "https", Product: "caddy", State: "open",
		Exposure: domain.ExposureInternal, FirstSeen: now, LastSeen: now}
	if err := services.Upsert(ctx, orphanSVC443); err != nil {
		t.Fatalf("orphan svc 443: %v", err)
	}
	if err := services.Upsert(ctx, &domain.Service{ID: ids.New(), AssetID: orphan.ID, OrganizationID: org.ID,
		Protocol: "tcp", Port: 8443, ServiceName: "https-alt", State: "open",
		Exposure: domain.ExposureInternal, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("orphan svc 8443: %v", err)
	}

	software := NewSoftwareRepo(db)
	if err := software.Upsert(ctx, &domain.Software{ID: ids.New(), AssetID: orphan.ID,
		Name: "openssh-server", Version: "1:9.6p1", Ecosystem: "os_debian",
		FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("orphan software: %v", err)
	}

	groups := NewGroupRepo(db)
	group := &domain.AssetGroup{ID: ids.New(), OrgID: org.ID, Name: "workstations-" + ids.New()[:8],
		Color: "slate", Icon: "boxes", Kind: "custom", CreatedAt: now, UpdatedAt: now}
	if err := groups.Create(ctx, group); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := groups.AddMembers(ctx, org.ID, group.ID, []string{orphan.ID}); err != nil {
		t.Fatalf("group membership: %v", err)
	}

	deviceID := ids.New()
	agentRepo := NewAgentRepo(db)
	if err := agentRepo.Enroll(ctx, &domain.Agent{ID: deviceID, OrganizationID: org.ID, SiteID: site.ID,
		AssetID: &orphan.ID, Hostname: "DESKTOP-RUFJN45", Platform: "windows", Status: "online",
		LastSeen: now, EnrolledAt: now}); err != nil {
		t.Fatalf("enroll device on the orphan: %v", err)
	}

	// --- the merge
	if err := assets.MergeAssets(ctx, orphan.ID, target.ID); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := assets.MergeAssets(ctx, orphan.ID, target.ID); err != nil {
		t.Fatalf("merge must be idempotent after the duplicate is gone (no rows match), got %v", err)
	}

	// The duplicate is gone.
	if a, err := assets.ByID(ctx, org.ID, orphan.ID); err == nil && a != nil {
		t.Fatalf("duplicate asset must be deleted, got %+v", a)
	}

	// Identifiers merged: the duplicate's hostname and both addresses now
	// resolve to the target.
	for _, pair := range [][2]string{{"hostname", "desktop-rufjn45"}, {"ip", "192.168.1.80"}, {"ip", "10.8.0.2"}} {
		holders, err := ident.FindByIdentifier(ctx, pair[0], pair[1])
		if err != nil {
			t.Fatalf("find %s/%s: %v", pair[0], pair[1], err)
		}
		found := false
		for _, h := range holders {
			if h == target.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("identifier %s/%s must resolve to the target after the merge, holders: %v", pair[0], pair[1], holders)
		}
	}

	// Interfaces: the target keeps its Ethernet NIC, which now also holds
	// the donated address; the USB NIC moved across with its address.
	targetIfaces, err := ifaces.ListForAsset(ctx, target.ID)
	if err != nil {
		t.Fatalf("list target ifaces: %v", err)
	}
	macs := map[string][]string{}
	for _, nic := range targetIfaces {
		literals := map[string]bool{}
		for _, ip := range nic.Addresses {
			literals[ip.IP] = true
		}
		for lit := range literals {
			macs[nic.MAC] = append(macs[nic.MAC], lit)
		}
	}
	if got := macs[ethernet]; len(got) != 2 {
		t.Fatalf("target Ethernet NIC must hold both addresses after the donation, got %v", got)
	}
	if got := macs[usb]; len(got) != 1 {
		t.Fatalf("target USB NIC must have moved across with its address, got %v", got)
	}

	// Services: 443 exists exactly once (the target's row), 8443 moved.
	targetSvcs, err := services.ListForAsset(ctx, target.ID)
	if err != nil {
		t.Fatalf("list target services: %v", err)
	}
	count443, count8443 := 0, 0
	for _, svc := range targetSvcs {
		if svc.Port == 443 && svc.Protocol == "tcp" {
			count443++
		}
		if svc.Port == 8443 && svc.Protocol == "tcp" {
			count8443++
		}
	}
	if count443 != 1 || count8443 != 1 {
		t.Fatalf("target must hold 443 once (got %d) and 8443 once (got %d)", count443, count8443)
	}

	// Software merged.
	targetSw, err := software.ListForAsset(ctx, target.ID)
	if err != nil {
		t.Fatalf("list target software: %v", err)
	}
	foundSw := false
	for _, sw := range targetSw {
		if sw.Name == "openssh-server" && sw.Ecosystem == "os_debian" {
			foundSw = true
		}
	}
	if !foundSw {
		t.Fatalf("target must carry the duplicate's package, got %+v", targetSw)
	}

	// Group membership follows the target.
	g, err := groups.ByID(ctx, org.ID, group.ID)
	if err != nil {
		t.Fatalf("group by id: %v", err)
	}
	memberOfTarget := false
	for _, m := range g.AssetIDs {
		if m == target.ID {
			memberOfTarget = true
		}
		if m == orphan.ID {
			t.Fatal("the deleted duplicate must not remain a group member")
		}
	}
	if !memberOfTarget {
		t.Fatalf("the target must inherit the group membership, members: %v", g.AssetIDs)
	}

	// The device bound to the duplicate now points at the target.
	devices, err := agentRepo.AgentIDsForAsset(ctx, target.ID)
	if err != nil {
		t.Fatalf("devices for target: %v", err)
	}
	foundDevice := false
	for _, d := range devices {
		if d == deviceID {
			foundDevice = true
		}
	}
	if !foundDevice {
		t.Fatalf("the device must be re-bound to the target, bound devices: %v", devices)
	}
}
