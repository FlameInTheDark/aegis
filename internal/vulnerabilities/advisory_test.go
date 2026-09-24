package vulnerabilities

import (
	"context"
	"log/slog"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// --- fakes (: deterministic, no database) ---

type fakeAdvisories struct {
	rows []domain.OSAdvisory
	err  error
}

func (f *fakeAdvisories) ForPackage(ctx context.Context, family, release, pkg string) ([]domain.OSAdvisory, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := []domain.OSAdvisory{}
	for _, r := range f.rows {
		if r.Family == family && r.Release == release && r.PackageName == pkg {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeFindingStore struct {
	upserts  int
	findings []*domain.Finding
}

func (f *fakeFindingStore) Upsert(ctx context.Context, fnd *domain.Finding) error {
	f.upserts++
	f.findings = append(f.findings, fnd)
	return nil
}

type fakeEvidenceStore struct {
	inserts int
	records []*domain.Evidence
}

func (f *fakeEvidenceStore) Insert(ctx context.Context, e *domain.Evidence) error {
	f.inserts++
	f.records = append(f.records, e)
	return nil
}

func newAdvisoryTestCorrelator(advs []domain.OSAdvisory) (*Correlator, *fakeFindingStore, *fakeEvidenceStore) {
	ff := &fakeFindingStore{}
	fe := &fakeEvidenceStore{}
	// DistroResolver stays the default: the ubuntu asset resolves through
	// the real fingerprinting.DistroOf path.
	c := &Correlator{
		Findings: ff, Evidence: fe, Log: slog.Default(),
		Advisories: &fakeAdvisories{rows: advs},
	}
	return c, ff, fe
}

func ubuntuAsset() *domain.Asset {
	return &domain.Asset{ID: "asset-1", OrganizationID: "org-1", OSFamily: "ubuntu", OSName: "Ubuntu 22.04", OSVersion: "22.04"}
}

func debPkg(name, version string) *domain.Software {
	return &domain.Software{ID: "sw-1", AssetID: "asset-1", Name: name, Version: version, Ecosystem: fingerprinting.PkgEcoDebian, Source: "endpoint_agent"}
}

func TestCorrelateOSPackageFixedHit(t *testing.T) {
	c, ff, fe := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", FixedVersion: "3.0.2-0ubuntu1.16",
		CVEID: "CVE-2024-1111", AdvisoryID: "USN-6800-1", Source: "oval",
	}})
	n, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), debPkg("openssl", "3.0.2-0ubuntu1.15"))
	if err != nil || !handled || n != 1 {
		t.Fatalf("n=%d handled=%v err=%v", n, handled, err)
	}
	if ff.upserts != 1 || fe.inserts != 1 {
		t.Fatalf("upserts=%d evidence=%d", ff.upserts, fe.inserts)
	}
	f := ff.findings[0]
	if f.MatchType != domain.MatchOSPackage || f.CVEID != "CVE-2024-1111" || f.Confidence != 1.0 {
		t.Fatalf("finding wrong: %+v", f)
	}
	if f.Remediation != "Upgrade openssl to 3.0.2-0ubuntu1.16 (USN-6800-1)." {
		t.Fatalf("remediation wrong: %q", f.Remediation)
	}
}

func TestCorrelateOSPackageNotFixedYet(t *testing.T) {
	c, ff, _ := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", NotFixedYet: true,
		CVEID: "CVE-2024-2222", AdvisoryID: "USN-6801-1", Source: "oval",
	}})
	// A not-fixed-yet advisory affects every installed version.
	for _, v := range []string{"1.0", "99.9.9-x"} {
		n, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), debPkg("openssl", v))
		if err != nil || !handled || n != 1 {
			t.Fatalf("v=%s n=%d handled=%v err=%v", v, n, handled, err)
		}
		if ff.findings[0].Remediation == "" || ff.findings[0].Remediation[:2] != "No" {
			t.Fatalf("unfixed remediation wrong: %q", ff.findings[0].Remediation)
		}
	}
}

func TestCorrelateOSPackageNotVulnerable(t *testing.T) {
	c, ff, _ := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", FixedVersion: "3.0.2-0ubuntu1.16",
		CVEID: "CVE-2024-1111", AdvisoryID: "USN-6800-1", Source: "oval",
	}})
	// Installed version IS the fix (and above it) — no finding, but the
	// release is covered: handled=true blocks OSV fallback.
	for _, v := range []string{"3.0.2-0ubuntu1.16", "3.0.2-0ubuntu1.20", "4:1.0-1"} {
		n, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), debPkg("openssl", v))
		if err != nil || !handled || n != 0 {
			t.Fatalf("v=%s n=%d handled=%v err=%v", v, n, handled, err)
		}
	}
	if ff.upserts != 0 {
		t.Fatalf("unexpected findings: %d", ff.upserts)
	}
}

func TestCorrelateOSPackageEcosystemMismatchNeverJudged(t *testing.T) {
	c, ff, _ := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", NotFixedYet: true,
		CVEID: "CVE-2024-2222", AdvisoryID: "USN-6801-1", Source: "oval",
	}})
	// An rpm-recorded package on a debian asset is data corruption.
	sw := debPkg("openssl", "1.0")
	sw.Ecosystem = fingerprinting.PkgEcoRPM
	_, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), sw)
	if err != nil || handled || ff.upserts != 0 {
		t.Fatalf("cross-ecosystem must not judge: n handled=%v err=%v", handled, err)
	}
}

func TestCorrelateOSPackageNoDistro(t *testing.T) {
	c, ff, _ := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssl", FixedVersion: "1", CVEID: "CVE-1", AdvisoryID: "USN-1",
	}})
	asset := ubuntuAsset()
	asset.OSFamily, asset.OSName, asset.OSVersion = "windows", "Microsoft Windows Server 2022", ""
	_, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", asset, debPkg("openssl", "1.0"))
	if err != nil || handled || ff.upserts != 0 {
		t.Fatalf("unresolvable distro must not judge: handled=%v", handled)
	}
}

func TestCorrelateOSPackageNoCoverageFallsThrough(t *testing.T) {
	// No advisory rows for the package at all: handled=false so the caller
	// falls back to the OSV path.
	c, _, _ := newAdvisoryTestCorrelator(nil)
	_, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), debPkg("curl", "8.5.0-1"))
	if err != nil || handled {
		t.Fatalf("no coverage must not be handled: handled=%v", handled)
	}
}
