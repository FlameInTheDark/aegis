package reports

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// pdfText decodes PDF literal-string escape sequences so assertions match
// what a viewer actually renders: the writer emits "Evidence \(1\):" in the
// content stream, but the page shows "Evidence (1):".
func pdfText(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			i++
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

// intPtr is a fixture helper for optional network VLAN ids.
func intPtr(v int) *int { return &v }

// renderPDF must render the full detail contract for device/site detail
// reports: coverage/omitted statements, site and network metadata, per-device
// sections with services (all states), software, evidence, scans — and no
// machine UUIDs as labels.
func TestRenderPDFDetailSections(t *testing.T) {
	d := &reportData{
		Title: "Device Detail Report", Type: "device_detail",
		OrgID: "org-uuid-1", SiteID: "site-uuid-1", AssetID: "asset-uuid-1",
		OrgLabel: "Example Company", SiteLabel: "Head Office",
		GeneratedAt: time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Summary: map[string]any{
			"assets": 1, "open_ports": 2, "assets_with_open_ports": 1, "total_findings": 1,
			"by_severity": map[string]int{"high": 1},
		},
		OpenPortsByAsset: map[string]int{"asset-uuid-1": 2},
		Assets:           []domain.Asset{{ID: "asset-uuid-1", PrimaryIP: "192.0.2.10", OSName: "Linux", DeviceType: domain.DeviceServer, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal}},
		Findings:         []domain.Finding{{ID: "finding-uuid-1", AssetID: "asset-uuid-1", Severity: domain.SeverityHigh, Status: domain.FindingOpen, CVEID: "CVE-2024-9999", Title: "Stored finding title", RiskScore: 70}},
		Details: &ReportDetails{
			Site:     &domain.Site{ID: "site-uuid-1", OrganizationID: "org-uuid-1", Name: "Head Office", SiteType: "hq", Description: "Main campus"},
			Networks: []domain.Network{{ID: "net-uuid-1", SiteID: "site-uuid-1", OrganizationID: "org-uuid-1", CIDR: "192.0.2.0/24", Gateway: "192.0.2.1", Name: "Users", VLANID: intPtr(20)}},
			Devices:  []DeviceDetails{{ReportDeviceRecords: pgRecords()}},
			Scans:    []domain.Scan{{ID: "scan-uuid-1", Name: "Weekly inventory", Profile: domain.ProfileInventory, State: domain.ScanCompleted, CreatedAt: time.Date(2026, 9, 17, 8, 30, 0, 0, time.UTC)}},
			Coverage: []string{
				"Current stored asset attributes; identifiers (type, value, weight); interfaces and recorded IP addresses.",
				"All stored service states with banner, TLS, HTTP, version, CPE, confidence and source metadata; software inventory.",
			},
			Omitted: []string{"Raw scan observations and task payloads; service/software observation history and scan scopes/change bodies."},
		},
	}
	raw, _, err := renderPDF(d)
	if err != nil {
		t.Fatalf("renderPDF: %v", err)
	}
	text := pdfText(raw)
	for _, want := range []string{
		"Device Detail Report",
		"Example Company", "Head Office", // human labels
		"Coverage", "Omitted from this report",
		"Main campus",                     // site description
		"192.0.2.0/24", "VLAN", "gateway", // networks
		"Device: 192.0.2.10", // device label (IP, not UUID)
		"Operating system:", "Device type:",
		"ip=192.0.2.10",                            // identifiers
		"Interface eth0", "198.51.100.7 (primary)", // interface + address
		"(VLAN 20)",                              // network vlan annotation
		"443/tcp open https", "OpenSSH", "9.6p1", // service + product + version
		"(TLS CN", "web-01.example.test", // TLS metadata
		"(HTTP title", "Router admin", // HTTP metadata
		"Software:", "nginx 1.24.0",
		"Evidence (1)", "[banner]", "SSH banner identifies OpenSSH",
		"Scans (1)", "Weekly inventory", "completed",
	} {
		if !bytes.Contains([]byte(text), []byte(want)) {
			t.Errorf("detail PDF missing %q", want)
		}
	}
	for _, banned := range []string{"asset-uuid-1", "site-uuid-1", "org-uuid-1", "scan-uuid-1", "finding-uuid-1", "net-uuid-1", "svc-uuid-1", "if-uuid-1"} {
		if bytes.Contains([]byte(text), []byte(banned)) {
			t.Errorf("detail PDF leaks machine UUID %q", banned)
		}
	}
	// Closed/filtered services must appear too (all stored states).
	if !bytes.Contains([]byte(text), []byte("22/tcp closed")) {
		t.Error("non-open service state missing from detail PDF")
	}
	// Page tree must remain valid (multi-page growth from detail content).
	if !regexp.MustCompile(`/Count \d+`).Match(raw) {
		t.Fatal("page tree missing")
	}
	// Header spacing guard: meta must start below the title block.
	m := regexp.MustCompile(`1 0 0 1 48\.0 (\d+\.\d) Tm`).FindAllStringSubmatch(text, -1)
	if len(m) < 2 {
		t.Fatal("header text matrices missing")
	}
	titleY, _ := strconv.ParseFloat(m[0][1], 64)
	metaY, _ := strconv.ParseFloat(m[1][1], 64)
	if titleY-(metaY+8.5) < 6 {
		t.Fatalf("title/meta overlap: gap=%.1f", titleY-(metaY+8.5))
	}
}

// pgRecords builds one fully populated device record fixture.
func pgRecords() (r pg.ReportDeviceRecords) {
	r.Asset = domain.Asset{ID: "asset-uuid-1", OrganizationID: "org-uuid-1", SiteID: "site-uuid-1", PrimaryIP: "192.0.2.10", OSName: "Linux", DeviceType: domain.DeviceServer, RiskScore: 40, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal}
	r.Identifiers = []domain.Identifier{{AssetID: "asset-uuid-1", Type: "ip", Value: "192.0.2.10", Weight: 0.2}}
	r.Interfaces = []domain.Interface{{ID: "if-uuid-1", AssetID: "asset-uuid-1", Name: "eth0", MAC: "02:00:00:00:00:01", Addresses: []domain.IPObservation{{IP: "192.0.2.10", IsPrimary: true}, {IP: "198.51.100.7", IsPrimary: true}}}}
	r.Services = []domain.Service{
		{ID: "svc-uuid-1", AssetID: "asset-uuid-1", Protocol: "tcp", Port: 443, State: "open", ServiceName: "https", Product: "OpenSSH", DetectedVersion: "9.6p1",
			TLS: &domain.TLSInfo{SubjectCN: "web-01.example.test"}, HTTP: &domain.HTTPInfo{Title: "Router admin"}, Banner: "SSH-2.0-OpenSSH_9.6"},
		{ID: "svc-uuid-2", AssetID: "asset-uuid-1", Protocol: "tcp", Port: 22, State: "closed"},
	}
	r.Software = []domain.Software{{ID: "sw-uuid-1", AssetID: "asset-uuid-1", Name: "nginx", Version: "1.24.0"}}
	r.Findings = []domain.Finding{{ID: "finding-uuid-1", AssetID: "asset-uuid-1", Severity: domain.SeverityHigh, Status: domain.FindingOpen, CVEID: "CVE-2024-9999", Title: "Legacy service exposed", RiskScore: 72}}
	r.Evidence = []domain.Evidence{{ID: "ev-uuid-1", FindingID: "finding-uuid-1", Kind: "banner", Statement: "SSH banner identifies OpenSSH"}}
	r.Scans = []domain.Scan{{ID: "scan-uuid-1", Name: "Weekly inventory", Profile: domain.ProfileInventory, State: domain.ScanCompleted, CreatedAt: time.Date(2026, 9, 17, 8, 30, 0, 0, time.UTC)}}
	return r
}
