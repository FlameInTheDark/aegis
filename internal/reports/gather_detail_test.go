package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

var errDetailTest = errors.New("repository unavailable")

type detailFixture struct {
	calls    []string
	fail     string
	assetOrg string
	siteOrg  string
	assets   []domain.Asset
}

func (f *detailFixture) call(name, org string) error {
	f.calls = append(f.calls, name)
	if org != "org" {
		return fmt.Errorf("unexpected tenant")
	}
	if name == f.fail {
		return errDetailTest
	}
	return nil
}
func (f *detailFixture) Organization(_ context.Context, org string) (*domain.Organization, error) {
	if err := f.call("organization", org); err != nil {
		return nil, err
	}
	return &domain.Organization{ID: org, Name: "Example organization"}, nil
}
func (f *detailFixture) Site(_ context.Context, org, site string) (*domain.Site, error) {
	if err := f.call("site", org); err != nil {
		return nil, err
	}
	owner := org
	if f.siteOrg != "" {
		owner = f.siteOrg
	}
	return &domain.Site{ID: site, OrganizationID: owner, Name: "HQ"}, nil
}
func (f *detailFixture) Asset(_ context.Context, org, id string) (*domain.Asset, error) {
	if err := f.call("asset", org); err != nil {
		return nil, err
	}
	owner := org
	if f.assetOrg != "" {
		owner = f.assetOrg
	}
	return &domain.Asset{ID: id, OrganizationID: owner, SiteID: "site", PrimaryIP: "192.0.2.1", OSName: "Linux"}, nil
}
func (f *detailFixture) Inventory(_ context.Context, org, site string) ([]domain.Asset, error) {
	if err := f.call("inventory", org); err != nil {
		return nil, err
	}
	if f.assets != nil {
		return f.assets, nil
	}
	return []domain.Asset{{ID: "device", OrganizationID: org, SiteID: site, OSName: "Linux"}}, nil
}
func (f *detailFixture) Networks(_ context.Context, org, site string) ([]domain.Network, error) {
	if err := f.call("networks", org); err != nil {
		return nil, err
	}
	return []domain.Network{{OrganizationID: org, SiteID: site, CIDR: "192.0.2.0/24"}}, nil
}
func (f *detailFixture) Scans(_ context.Context, org, site string) ([]domain.Scan, error) {
	if err := f.call("scans", org); err != nil {
		return nil, err
	}
	return []domain.Scan{{ID: "site-scan", OrganizationID: org, SiteID: site, Name: "Weekly inventory"}}, nil
}
func (f *detailFixture) Device(_ context.Context, org, id string) (*pg.ReportDeviceRecords, error) {
	if err := f.call("device", org); err != nil {
		return nil, err
	}
	return &pg.ReportDeviceRecords{
		Asset:       domain.Asset{ID: id, OrganizationID: org, SiteID: "site", OSName: "Linux"},
		Identifiers: []domain.Identifier{{AssetID: id, Type: "ip", Value: "192.0.2.1", Weight: 0.2}},
		Interfaces:  []domain.Interface{{AssetID: id, Name: "eth0", Addresses: []domain.IPObservation{{IP: "192.0.2.1"}}}},
		Services: []domain.Service{
			{AssetID: id, OrganizationID: org, State: "open", Protocol: "tcp", Port: 443, Banner: "stored banner", HTTP: &domain.HTTPInfo{Title: "Admin console"}, TLS: &domain.TLSInfo{SubjectCN: "example.test"}},
			{AssetID: id, OrganizationID: org, State: "open", Protocol: "udp", Port: 443},
			{AssetID: id, OrganizationID: org, State: "closed", Protocol: "tcp", Port: 22},
		},
		Software: []domain.Software{{AssetID: id, Name: "example", Version: "1.0"}},
		Findings: []domain.Finding{{ID: "finding", AssetID: id, OrganizationID: org, Severity: domain.SeverityHigh, Title: "Stored finding"}},
		Evidence: []domain.Evidence{{FindingID: "finding", Statement: "Stored evidence"}},
		Scans:    []domain.Scan{{ID: "device-linked-scan", OrganizationID: org, SiteID: "site", Name: "Device inventory"}},
	}, nil
}

func TestGatherDetailCoverage(t *testing.T) {
	for _, typ := range []domain.ReportType{domain.ReportSiteDetail, domain.ReportDeviceDetail} {
		t.Run(string(typ), func(t *testing.T) {
			fixture := &detailFixture{}
			def := &domain.ReportDefinition{Type: typ, OrganizationID: "org", SiteID: "site"}
			if typ == domain.ReportDeviceDetail {
				def.AssetID = "device"
				def.SiteID = ""
			}
			data, err := (&Service{Details: fixture}).gather(context.Background(), "org", def)
			if err != nil {
				t.Fatal(err)
			}
			if data.OrgLabel != "Example organization" || data.SiteLabel != "HQ" {
				t.Fatalf("labels = %q / %q", data.OrgLabel, data.SiteLabel)
			}
			if data.Summary["assets"] != 1 || data.Summary["open_ports"] != 2 || data.OpenPortsByAsset["device"] != 2 {
				t.Fatalf("summary = %#v", data.Summary)
			}
			if _, ok := data.Summary["kev"]; ok {
				t.Fatal("detail must not invent KEV count")
			}
			if len(data.Details.Devices[0].Services) != 3 {
				t.Fatal("closed service dropped")
			}
			if data.Summary["total_findings"] != 1 || data.Summary["by_severity"].(map[string]int)["high"] != 1 {
				t.Fatal("findings summary inconsistent")
			}
			wantScan := "site-scan"
			if typ == domain.ReportDeviceDetail {
				wantScan = "device-linked-scan"
				if !reflect.DeepEqual(fixture.calls[:3], []string{"organization", "asset", "site"}) {
					t.Fatalf("ownership validation order = %v", fixture.calls)
				}
				if len(data.Details.Networks) != 0 {
					t.Fatal("device report leaked site networks")
				}
			}
			if data.Scans[0].ID != wantScan {
				t.Fatalf("scan scope = %v", data.Scans)
			}
			raw, ctype, err := renderJSON(data)
			if err != nil || ctype != "application/json" {
				t.Fatalf("JSON render: %s %v", ctype, err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, fragment := range []string{"\"details\"", "\"identifiers\"", "\"interfaces\"", "\"services\"", "\"software\"", "Stored evidence", "Admin console", "example.test", "Linux", "\"coverage\"", "\"omitted\""} {
				if !strings.Contains(string(raw), fragment) {
					t.Errorf("missing JSON detail %s", fragment)
				}
			}
		})
	}
}

func TestGatherDetailRejectsScopeBeforeSubordinates(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		typ                                 domain.ReportType
		org, assetOrg, siteOrg, site, asset string
		wantCalls                           []string
	}{
		{"missing org", domain.ReportDeviceDetail, "", "", "", "site", "device", nil},
		{"missing device", domain.ReportDeviceDetail, "org", "", "", "site", "", nil},
		{"missing site", domain.ReportSiteDetail, "org", "", "", "", "", nil},
		{"foreign device", domain.ReportDeviceDetail, "org", "foreign", "", "site", "device", []string{"organization", "asset"}},
		{"wrong site for device", domain.ReportDeviceDetail, "org", "", "", "other-site", "device", []string{"organization", "asset"}},
		{"foreign site", domain.ReportSiteDetail, "org", "", "foreign", "site", "", []string{"organization", "site"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &detailFixture{assetOrg: tc.assetOrg, siteOrg: tc.siteOrg}
			_, err := (&Service{Details: fixture}).gather(context.Background(), tc.org, &domain.ReportDefinition{Type: tc.typ, SiteID: tc.site, AssetID: tc.asset})
			if err == nil {
				t.Fatal("expected scope error")
			}
			if !reflect.DeepEqual(fixture.calls, tc.wantCalls) {
				t.Fatalf("subordinate reads before ownership validation: %v", fixture.calls)
			}
		})
	}
}

func TestGatherDetailPropagatesErrors(t *testing.T) {
	for _, stage := range []string{"organization", "site", "inventory", "networks", "scans", "device", "asset"} {
		t.Run(stage, func(t *testing.T) {
			fixture := &detailFixture{fail: stage}
			def := &domain.ReportDefinition{Type: domain.ReportSiteDetail, SiteID: "site"}
			if stage == "asset" {
				def.Type = domain.ReportDeviceDetail
				def.AssetID = "device"
			}
			data, err := (&Service{Details: fixture}).gather(context.Background(), "org", def)
			if !errors.Is(err, errDetailTest) || data != nil {
				t.Fatalf("partial success or lost error: data=%v err=%v", data, err)
			}
			if fixture.calls[len(fixture.calls)-1] != stage {
				t.Fatalf("continued after failure: %v", fixture.calls)
			}
		})
	}
}

func TestGatherDetailHasNoUIListCap(t *testing.T) {
	fixture := &detailFixture{}
	for i := 0; i < 1001; i++ {
		fixture.assets = append(fixture.assets, domain.Asset{ID: fmt.Sprintf("device-%d", i), OrganizationID: "org", SiteID: "site"})
	}
	data, err := (&Service{Details: fixture}).gather(context.Background(), "org", &domain.ReportDefinition{Type: domain.ReportSiteDetail, SiteID: "site"})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Details.Devices) != 1001 || len(data.Findings) != 1001 || data.Summary["open_ports"] != 2002 {
		t.Fatalf("silently capped report: %#v", data.Summary)
	}
}

func TestGatherDetailRejectsForeignInventory(t *testing.T) {
	fixture := &detailFixture{assets: []domain.Asset{{ID: "foreign-device", OrganizationID: "foreign", SiteID: "site"}}}
	_, err := (&Service{Details: fixture}).gather(context.Background(), "org", &domain.ReportDefinition{Type: domain.ReportSiteDetail, SiteID: "site"})
	if err == nil {
		t.Fatal("expected scope error")
	}
	if !reflect.DeepEqual(fixture.calls, []string{"organization", "site", "inventory"}) {
		t.Fatalf("subordinate fetch after foreign asset: %v", fixture.calls)
	}
}
