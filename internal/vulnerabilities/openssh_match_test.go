package vulnerabilities

import (
	"context"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// End-to-end matcher regressions for the version-domain fix: an
// installed distro package version ("1:10.0p1-5ubuntu5.4") and an
// upstream CVE boundary ("10.5") live in different comparison domains,
// and every test here pins a verdict the old full-Debian comparison
// got wrong (the epoch made the bound sort below the package, hiding
// every OpenSSH CVE) or could have broken while routing was added.

// osvUpstreamBoundIndex holds one Ubuntu OSV advisory whose range carries
// an UPSTREAM-ONLY fixed version ("10.5") — the OSV shape that mirrors an
// upstream OpenSSH CVE — plus one with the distro-format fixed-in.
func osvUpstreamBoundIndex() *fakeIndex {
	return &fakeIndex{
		osv: map[string][]domain.OSVRecord{
			"os_debian/openssh-server": {
				{ID: "OSV-2026-73281", CVEIDs: []string{"CVE-2026-73281"}, Ecosystem: "Ubuntu:25.10",
					AffectedRanges: []domain.VersionRange{{
						Type:   "ECOSYSTEM",
						Events: []domain.RangeEvent{{Introduced: "0"}, {Fixed: "10.5"}},
					}}},
				{ID: "OSV-2026-73282", CVEIDs: []string{"CVE-2026-73282"}, Ecosystem: "Ubuntu:25.10",
					AffectedRanges: []domain.VersionRange{{
						Type:   "ECOSYSTEM",
						Events: []domain.RangeEvent{{Introduced: "0"}, {Fixed: "1:10.0p1-5ubuntu5.5"}},
					}}},
			},
		},
	}
}

// TestOSVUpstreamBoundMatchesPackagedOpenSSH is THE user scenario:
// openssh-server reports 1:10.0p1-5ubuntu5.4; the CVE says OpenSSH < 10.5
// is affected. The verdict must come from the structured OpenSSH domain
// (upstream 10.0p1 < 10.5), not from Debian ordering (epoch 1 > no epoch
// would call the package "newer" than every upstream bound).
func TestOSVUpstreamBoundMatchesPackagedOpenSSH(t *testing.T) {
	m := &Matcher{Index: osvUpstreamBoundIndex()}
	matches, _, err := m.Match(context.Background(), MatchInput{
		Ecosystem:   fingerprinting.PkgEcoDebian,
		PackageName: "openssh-server",
		Version:     "1:10.0p1-5ubuntu5.4", // normalized installed version
		RawVersion:  "1:10.0p1-5ubuntu5.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both advisories of the index affect this version (the upstream-bound
	// one via the OpenSSH projection, the distro-bound one via Debian
	// ordering) — find the upstream-bound match and pin its evidence.
	var mt *Match
	for i := range matches {
		if matches[i].OSVID == "OSV-2026-73281" {
			mt = &matches[i]
		}
	}
	if mt == nil {
		t.Fatalf("10.0p1 < 10.5 must match the upstream-bound advisory, got %+v", matches)
	}
	if mt.CVEID != "CVE-2026-73281" || mt.MatchType != domain.MatchPackageVersion {
		t.Fatalf("match wrong: %+v", mt)
	}
	if mt.Evidence["bound_domain"] != string(fingerprinting.DomainOpenSSH) {
		t.Errorf("bound_domain = %v, want openssh", mt.Evidence["bound_domain"])
	}
	if mt.Evidence["projected_version"] != "10.0p1" {
		t.Errorf("projected_version = %v, want the upstream part 10.0p1", mt.Evidence["projected_version"])
	}
	constraint, ok := mt.Evidence["constraint"].(domain.VersionConstraint)
	if !ok || constraint.Domain != domain.DomainOpenSSH || constraint.Fixed != "10.5" {
		t.Errorf("constraint evidence = %+v, want {openssh, fixed 10.5}", mt.Evidence["constraint"])
	}

	// Fixed upstream release: 10.5 == bound, and 10.6 > bound — no match.
	for _, fixed := range []string{"1:10.5-0ubuntu1", "1:10.6-0ubuntu1.1"} {
		matches, _, _ := m.Match(context.Background(), MatchInput{
			Ecosystem: fingerprinting.PkgEcoDebian, PackageName: "openssh-server", Version: fixed,
		})
		for _, mt := range matches {
			if mt.CVEID == "CVE-2026-73281" {
				t.Fatalf("%s must not match the upstream < 10.5 advisory", fixed)
			}
		}
	}

	// Update levels stay ordered inside the same base: 10.0p2 also matches.
	matches, _, _ = m.Match(context.Background(), MatchInput{
		Ecosystem: fingerprinting.PkgEcoDebian, PackageName: "openssh-server", Version: "1:10.0p2-5ubuntu5.1",
	})
	if len(matches) == 0 {
		t.Fatal("10.0p2 < 10.5 must match as well")
	}
}

// TestOSVDistroBoundStillDebianOrdered guards the other direction: an
// Ubuntu advisory with a distro-format fixed-in must keep ordering fully
// under Debian semantics — revision-only security uploads stay decisive.
func TestOSVDistroBoundStillDebianOrdered(t *testing.T) {
	m := &Matcher{Index: osvUpstreamBoundIndex()}

	matches, _, err := m.Match(context.Background(), MatchInput{
		Ecosystem: fingerprinting.PkgEcoDebian, PackageName: "openssh-server",
		Version: "1:10.0p1-5ubuntu5.4", // one revision below the fix
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mt := range matches {
		if mt.CVEID == "CVE-2026-73282" {
			found = true
			if mt.Evidence["bound_domain"] != string(fingerprinting.DomainDebian) {
				t.Errorf("distro-format bound must be judged in the debian domain, got %v", mt.Evidence["bound_domain"])
			}
			if _, has := mt.Evidence["projected_version"]; has {
				t.Errorf("no projection may be reported for a distro-format bound, got %v", mt.Evidence["projected_version"])
			}
		}
	}
	if !found {
		t.Fatal("installed below the distro fixed-in must match")
	}

	// Same upstream, security revision applied: fixed.
	matches, _, _ = m.Match(context.Background(), MatchInput{
		Ecosystem: fingerprinting.PkgEcoDebian, PackageName: "openssh-server",
		Version: "1:10.0p1-5ubuntu5.6", // above 1:10.0p1-5ubuntu5.5
	})
	for _, mt := range matches {
		if mt.CVEID == "CVE-2026-73282" {
			t.Fatal("installed above the distro fixed-in must not match")
		}
	}
}

// cpeOpenSSHIndex is one NVD-style CPE range: OpenSSH affected below
// 10.5 (exclusive), versionType custom — the shape NVD publishes.
func cpeOpenSSHIndex() *fakeIndex {
	return &fakeIndex{cves: map[string]*domain.Vulnerability{
		"CVE-2026-73281": {CVEID: "CVE-2026-73281", State: domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{
				CPE:    "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
				Vendor: "openbsd", Product: "openssh",
				VersionEndExcl: "10.5", VersionType: "custom",
			}}},
	}}
}

func TestCPERangeOpenSSHStructuredDomain(t *testing.T) {
	m := &Matcher{Index: cpeOpenSSHIndex()}

	affected := []string{"10.0p2", "10.0p1", "10.4p2", "9.9p2", "10.0p2-5ubuntu5.4"}
	for _, v := range affected {
		matches, _, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: v})
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || matches[0].MatchType != domain.MatchCPERange {
			t.Errorf("%s is inside (< 10.5) and must match as CPE range, got %+v", v, matches)
			continue
		}
		if matches[0].Evidence["bound_domain"] != string(fingerprinting.DomainOpenSSH) {
			t.Errorf("%s: bound_domain = %v, want openssh", v, matches[0].Evidence["bound_domain"])
		}
	}

	fixed := []string{"10.5", "10.5p1", "10.6", "11.0"}
	for _, v := range fixed {
		matches, _, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: v})
		if len(matches) != 0 {
			t.Errorf("%s is outside (< 10.5) and must not match, got %+v", v, matches)
		}
	}

	// The banner-normalized deb form must carry the projection evidence.
	matches, _, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2-5ubuntu5.4"})
	if len(matches) == 1 && matches[0].Evidence["projected_version"] != "10.0p2" {
		t.Errorf("projected_version = %v, want 10.0p2", matches[0].Evidence["projected_version"])
	}
}

// TestCPERangeStartExclStillEvaluated guards the one CPE bound the
// OSV-shaped VersionConstraint cannot carry: versionStartExcl is
// evaluated as a separate exclusive greater-than bound.
func TestCPERangeStartExclStillEvaluated(t *testing.T) {
	idx := &fakeIndex{cves: map[string]*domain.Vulnerability{
		"CVE-2026-RANGE": {CVEID: "CVE-2026-RANGE", State: domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{
				CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Vendor: "openbsd", Product: "openssh",
				VersionStartExcl: "10.0", VersionEndIncl: "10.4", VersionType: "custom",
			}}},
	}}
	m := &Matcher{Index: idx}

	// Exactly at the exclusive start: outside.
	if matches, _, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0"}); len(matches) != 0 {
		t.Errorf("10.0 is excluded by versionStartExcl, got %+v", matches)
	}
	// One update above the start, inside the inclusive end: in range.
	if matches, _, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p1"}); len(matches) != 1 {
		t.Errorf("10.0p1 is inside (10.0, 10.4], got %+v", matches)
	}
	// Above the inclusive end: outside — 10.4p1 > 10.4.
	if matches, _, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.4p1"}); len(matches) != 0 {
		t.Errorf("10.4p1 is outside (10.0, 10.4], got %+v", matches)
	}
}

// TestAdvisoryPlaneUpstreamFixedIn covers the distro advisory path with
// an upstream-only fixed-in: the projection must apply there too.
func TestAdvisoryPlaneUpstreamFixedIn(t *testing.T) {
	c, _, fe := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssh-server",
		FixedVersion: "10.5", CVEID: "CVE-2026-73281", AdvisoryID: "USN-8000-1", Source: "oval",
	}})
	sw := debPkg("openssh-server", "1:10.0p1-5ubuntu5.4")
	n, handled, err := c.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), sw)
	if err != nil || !handled || n != 1 {
		t.Fatalf("n=%d handled=%v err=%v", n, handled, err)
	}
	ev := fe.records[0].Detail
	if ev["compare_domain"] != string(fingerprinting.DomainOpenSSH) {
		t.Errorf("compare_domain = %v, want openssh", ev["compare_domain"])
	}
	if ev["projected_version"] != "10.0p1" {
		t.Errorf("projected_version = %v, want 10.0p1", ev["projected_version"])
	}

	// The distro-format fixed-in keeps Debian ordering and no projection.
	c2, _, fe2 := newAdvisoryTestCorrelator([]domain.OSAdvisory{{
		Family: "ubuntu", Release: "22.04", PackageName: "openssh-server",
		FixedVersion: "1:10.0p1-5ubuntu5.5", CVEID: "CVE-2026-73281", AdvisoryID: "USN-8000-1", Source: "oval",
	}})
	if _, handled, err := c2.CorrelateOSPackage(context.Background(), "org-1", ubuntuAsset(), sw); err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	ev2 := fe2.records[0].Detail
	if ev2["compare_domain"] != string(fingerprinting.DomainDebian) {
		t.Errorf("compare_domain = %v, want debian", ev2["compare_domain"])
	}
	if _, has := ev2["projected_version"]; has {
		t.Errorf("distro-format bound must not project, got %v", ev2["projected_version"])
	}
}
