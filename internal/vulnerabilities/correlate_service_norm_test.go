package vulnerabilities

import (
	"context"
	"log/slog"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// cpeDebServiceIndex is a fake index with one CVE whose affected range is
// a deb-ordered version interval over openssh: [10.0p2-5ubuntu5.3,
// 10.0p2-5ubuntu5.5).
func cpeDebServiceIndex() *fakeIndex {
	return &fakeIndex{
		cves: map[string]*domain.Vulnerability{
			"CVE-2026-2222": {
				CVEID: "CVE-2026-2222", State: domain.CVEStatePublished,
				CPEMatches: []domain.CPEMatch{{
					CPE:    "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
					Vendor: "openbsd", Product: "openssh",
					VersionStartIncl: "10.0p2-5ubuntu5.3", VersionEndExcl: "10.0p2-5ubuntu5.5",
					VersionType: "deb",
				}},
			},
		},
	}
}

// TestCorrelateServicePrefersNormalizedVersion pins the service-row
// contract the user directive requires: CVE checks run against the
// normalized version, never the raw banner string. The raw banner
// ("10.0p2 Ubuntu 5ubuntu5.4") is not a parseable deb version — under
// deb ordering it is incomparable and must never match; the normalized
// form ("10.0p2-5ubuntu5.4") falls inside the affected range and must.
func TestCorrelateServicePrefersNormalizedVersion(t *testing.T) {
	c := &Correlator{
		Index:    cpeDebServiceIndex(),
		Findings: &fakeFindingStore{},
		Evidence: &fakeEvidenceStore{},
		Log:      slog.Default(),
	}
	asset := &domain.Asset{ID: "asset-1"}
	svc := &domain.Service{
		ID: "svc-1", ServiceName: "ssh", Product: "OpenSSH", Vendor: "OpenBSD",
		DetectedVersion: "10.0p2 Ubuntu 5ubuntu5.4", // raw banner: space-separated distro revision
		VersionNorm:     "10.0p2-5ubuntu5.4",        // ingestion-normalized
		// nmap-style CPE: upstream version only, no distro revision.
		CPEs: []string{"cpe:2.3:a:openbsd:openssh:10.0p2:*:*:*:*:*:*:*"},
	}
	n, err := c.CorrelateService(context.Background(), "org-1", asset, svc)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	ff := c.Findings.(*fakeFindingStore)
	if len(ff.findings) != 1 || ff.findings[0].CVEID != "CVE-2026-2222" {
		t.Fatalf("findings wrong: %+v", ff.findings)
	}
}

// TestCorrelateServiceRawBannerNeverMatches is the guard rail: without
// the normalized form the raw banner version cannot be ordered under the
// deb grammar (it contains a space), so no version-bounded finding may
// be claimed from it.
func TestCorrelateServiceRawBannerNeverMatches(t *testing.T) {
	c := &Correlator{
		Index:    cpeDebServiceIndex(),
		Findings: &fakeFindingStore{},
		Evidence: &fakeEvidenceStore{},
		Log:      slog.Default(),
	}
	asset := &domain.Asset{ID: "asset-1"}
	svc := &domain.Service{
		ID: "svc-1", ServiceName: "ssh", Product: "OpenSSH", Vendor: "OpenBSD",
		DetectedVersion: "10.0p2 Ubuntu 5ubuntu5.4",
		CPEs:            []string{"cpe:2.3:a:openbsd:openssh:10.0p2:*:*:*:*:*:*:*"},
	}
	n, err := c.CorrelateService(context.Background(), "org-1", asset, svc)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("raw banner must not create a version-bounded finding, got %d", n)
	}
}

// TestServiceMatchVersionPrefersNorm pins the selection helper directly.
func TestServiceMatchVersionPrefersNorm(t *testing.T) {
	svc := &domain.Service{DetectedVersion: "10.0p2 Ubuntu 5ubuntu5.4", VersionNorm: "10.0p2-5ubuntu5.4"}
	if got := serviceMatchVersion(svc); got != "10.0p2-5ubuntu5.4" {
		t.Errorf("serviceMatchVersion = %q, want the normalized form", got)
	}
	svc.VersionNorm = ""
	if got := serviceMatchVersion(svc); got != "10.0p2 Ubuntu 5ubuntu5.4" {
		t.Errorf("serviceMatchVersion = %q, want raw fallback when norm empty", got)
	}
}
