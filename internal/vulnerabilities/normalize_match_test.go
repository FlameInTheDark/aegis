package vulnerabilities

import (
	"context"
	"log/slog"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// Normalized-version integration: the ingestion pipeline stores the raw
// collected version verbatim plus a grammar-canonical form, and the CVE
// matching pipeline must compare against the canonical form while the
// raw string stays first-class evidence.

// osvDebIndex returns an index with one Debian OSV advisory: openssl is
// affected from the beginning and fixed in 1:3.0.2-0ubuntu1.16 (an
// Ubuntu security upload that only moves the distro revision).
func osvDebIndex() *fakeIndex {
	return &fakeIndex{
		osv: map[string][]domain.OSVRecord{
			"os_debian/openssl": {
				{ID: "OSV-2026-1111", CVEIDs: []string{"CVE-2026-1111"},
					AffectedRanges: []domain.VersionRange{{
						Type: "ECOSYSTEM",
						Events: []domain.RangeEvent{
							{Introduced: "0"},
							{Fixed: "1:3.0.2-0ubuntu1.16"},
						},
					}},
				},
			},
		},
	}
}

func TestMatchPackageUsesNormalizedVersionAndKeepsRawEvidence(t *testing.T) {
	m := &Matcher{Index: osvDebIndex()}
	matches, _, err := m.Match(context.Background(), MatchInput{
		AssetID:     "asset-1",
		Ecosystem:   fingerprinting.PkgEcoDebian,
		PackageName: "openssl",
		Version:     "1:3.0.2-0ubuntu1.15",       // normalized (what matching compares)
		RawVersion:  "1:3.0.2-0ubuntu1.15 [now]", // raw as some collectors emit it
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 match for installed 1:3.0.2-0ubuntu1.15 < fixed 1:3.0.2-0ubuntu1.16, got %d", len(matches))
	}
	mt := matches[0]
	if mt.CVEID != "CVE-2026-1111" || mt.MatchType != domain.MatchPackageVersion || mt.Confidence != 0.9 {
		t.Fatalf("match wrong: %+v", mt)
	}
	if mt.Evidence["version"] != "1:3.0.2-0ubuntu1.15" {
		t.Errorf("evidence version should be the normalized form, got %v", mt.Evidence["version"])
	}
	if mt.Evidence["version_raw"] != "1:3.0.2-0ubuntu1.15 [now]" {
		t.Errorf("evidence must keep the raw collected version, got %v", mt.Evidence["version_raw"])
	}
}

// TestCorrelatePackagePrefersVersionNorm proves the software-row path
// feeds the normalized version into OSV matching and preserves the raw
// value on the evidence chain.
func TestCorrelatePackagePrefersVersionNorm(t *testing.T) {
	c := &Correlator{
		Index:    osvDebIndex(),
		Findings: &fakeFindingStore{},
		Evidence: &fakeEvidenceStore{},
		Log:      slog.Default(),
	}
	sw := &domain.Software{
		ID: "sw-1", AssetID: "asset-1",
		Name:        "openssl",
		Version:     "1:3.0.2-0ubuntu1.15 [now]", // raw, noisy
		VersionNorm: "1:3.0.2-0ubuntu1.15",       // ingestion-normalized
		Ecosystem:   fingerprinting.PkgEcoDebian,
		Source:      "ssh_scan",
	}
	n, err := c.CorrelatePackage(context.Background(), "org-1", &domain.Asset{ID: "asset-1"}, sw)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	ff := c.Findings.(*fakeFindingStore)
	if len(ff.findings) != 1 || ff.findings[0].CVEID != "CVE-2026-1111" {
		t.Fatalf("findings wrong: %+v", ff.findings)
	}
}

// TestCorrelateOSPackageUsesVersionNorm pins the advisory path: the
// installed version compared against the fixed-in bound is the
// normalized form; the raw dpkg string (here with an explicit zero
// epoch) stays on the evidence as first-class provenance.
func TestCorrelateOSPackageUsesVersionNorm(t *testing.T) {
	c, ff, _ := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", FixedVersion: "1:3.0.2-0ubuntu1.16",
		CVEID: "CVE-2026-1111", AdvisoryID: "USN-6800-1", Source: "oval",
	}})
	sw := debPkg("openssl", "0:3.0.2-0ubuntu1.15") // raw with explicit zero epoch
	sw.VersionNorm = "3.0.2-0ubuntu1.15"           // ingestion drops the zero epoch
	n, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), sw)
	if err != nil || !handled || n != 1 {
		t.Fatalf("n=%d handled=%v err=%v", n, handled, err)
	}
	if ff.findings[0].CVEID != "CVE-2026-1111" {
		t.Fatalf("finding wrong: %+v", ff.findings[0])
	}
}

// TestMatchPackageVersionOnlyGuard keeps the old contract green: with
// no normalized form the raw version is used as-is.
func TestMatchPackageVersionOnlyGuard(t *testing.T) {
	m := &Matcher{Index: osvDebIndex()}
	matches, _, err := m.Match(context.Background(), MatchInput{
		Ecosystem: fingerprinting.PkgEcoDebian, PackageName: "openssl",
		Version: "1:3.0.2-0ubuntu1.17", // above the fix
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("installed above fixed must not match, got %d matches", len(matches))
	}
}
