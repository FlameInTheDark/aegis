package reports

import (
	"bytes"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestInventoryPDFNamesPortsAndSpacing(t *testing.T) {
	d := &reportData{Title: "Network Inventory Report", Type: "network_inventory", OrgID: "org-private-id", SiteID: "site-private-id", OrgLabel: "Example Company", SiteLabel: "Head Office", GeneratedAt: time.Now(), Summary: map[string]any{"assets": 1, "total_findings": 0, "kev": 0, "open_ports": 2}, OpenPortsByAsset: map[string]int{"asset-private-id": 2}, Assets: []domain.Asset{{ID: "asset-private-id", PrimaryIP: "192.0.2.1", OSName: "Linux"}}}
	raw, _, err := renderPDF(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Example Company", "Head Office", "Open ports:", "192.0.2.1", "Open ports: 2"} {
		if !bytes.Contains(raw, []byte(s)) {
			t.Errorf("missing %q", s)
		}
	}
	for _, s := range []string{"org-private-id", "site-private-id", "asset-private-id", " ? "} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("unexpected %q", s)
		}
	}
	matrices := regexp.MustCompile(`BT /F[123] ([0-9.]+) Tf 1 0 0 1 [0-9.]+ ([0-9.]+) Tm`).FindAllSubmatch(raw, -1)
	if len(matrices) < 2 {
		t.Fatal("missing header text")
	}
	titleY, _ := strconv.ParseFloat(string(matrices[0][2]), 64)
	metaSize, _ := strconv.ParseFloat(string(matrices[1][1]), 64)
	metaY, _ := strconv.ParseFloat(string(matrices[1][2]), 64)
	if titleY-(metaY+metaSize) < 6 {
		t.Errorf("header gap too small: %v", titleY-(metaY+metaSize))
	}
}
