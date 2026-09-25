package vulnerabilities

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func strPtr(s string) *string { return &s }

func TestSuppressionMatches(t *testing.T) {
	cveSup := domain.Suppression{Scope: domain.SuppressionScope{
		Vulnerability: strPtr("CVE-2025-1234"), AssetID: strPtr("asset-1"),
	}}
	assetOnly := domain.Suppression{Scope: domain.SuppressionScope{AssetID: strPtr("asset-2")}}
	osvOnly := domain.Suppression{Scope: domain.SuppressionScope{Vulnerability: strPtr("GHSA-xxxx-yyyy")}}
	empty := domain.Suppression{}

	cases := []struct {
		name  string
		sups  []domain.Suppression
		cve   string
		osv   string
		asset string
		want  bool
	}{
		{"exact cve+asset match", []domain.Suppression{cveSup}, "CVE-2025-1234", "", "asset-1", true},
		{"osv id matches a cve-scoped suppression", []domain.Suppression{cveSup}, "", "CVE-2025-1234", "asset-1", true},
		{"different asset", []domain.Suppression{cveSup}, "CVE-2025-1234", "", "asset-9", false},
		{"different vuln", []domain.Suppression{cveSup}, "CVE-2025-9999", "", "asset-1", false},
		{"asset-only suppression covers any vuln on the asset", []domain.Suppression{assetOnly}, "CVE-2025-1", "", "asset-2", true},
		{"osv-scoped suppression matches advisory finding", []domain.Suppression{osvOnly}, "", "GHSA-xxxx-yyyy", "asset-2", true},
		{"suppression naming nothing never matches", []domain.Suppression{empty}, "CVE-2025-1", "", "asset-1", false},
		{"no suppressions", nil, "CVE-2025-1", "", "asset-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := suppressionMatches(tc.sups, tc.cve, tc.osv, tc.asset); got != tc.want {
				t.Fatalf("suppressionMatches = %v, want %v", got, tc.want)
			}
		})
	}
}
