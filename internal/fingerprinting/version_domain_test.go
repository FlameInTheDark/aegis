package fingerprinting

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Domain-routing tests: the installed version and the feed bound may
// live in different comparison domains, and the router must resolve the
// right one per bound. The headline case: an Ubuntu openssh package
// ("1:10.0p1-5ubuntu5.4") against an upstream OpenSSH CVE boundary
// ("10.5") — full Debian ordering would let the epoch 1 hide the
// vulnerability forever.

func TestComparePackageBoundDebRouting(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		bound     string
		eco       string
		wantCmp   int
		wantDom   domain.VersionDomain
		wantProj  string
	}{
		{
			name:      "THE regression: epoch-carrying package vs upstream CVE bound",
			installed: "1:10.0p1-5ubuntu5.4", bound: "10.5", eco: PkgEcoDebian,
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p1",
		},
		{
			name:      "newer upstream than the bound",
			installed: "1:10.6-0ubuntu1", bound: "10.5", eco: PkgEcoDebian,
			wantCmp: 1, wantDom: domain.DomainOpenSSH, wantProj: "10.6",
		},
		{
			name:      "upstream equal to the bound is fixed",
			installed: "1:10.5-0ubuntu1", bound: "10.5", eco: PkgEcoDebian,
			wantCmp: 0, wantDom: domain.DomainOpenSSH, wantProj: "10.5",
		},
		{
			name:      "banner-normalized deb form projects to the upstream release",
			installed: "10.0p2-5ubuntu5.4", bound: "10.5", eco: PkgEcoDebian,
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p2",
		},
		{
			name:      "distro-format bound orders fully under Debian",
			installed: "1:10.0p1-5ubuntu5.4", bound: "1:10.0p1-5ubuntu5.5", eco: PkgEcoDebian,
			wantCmp: -1, wantDom: domain.DomainDebian,
		},
		{
			name:      "distro-format bound equality",
			installed: "1:10.0p1-5ubuntu5.5", bound: "1:10.0p1-5ubuntu5.5", eco: PkgEcoDebian,
			wantCmp: 0, wantDom: domain.DomainDebian,
		},
		{
			name:      "epoch participates in distro-format bounds",
			installed: "0:3.0.2-0ubuntu1.15", bound: "1:3.0.2-0ubuntu1.16", eco: PkgEcoDebian,
			wantCmp: -1, wantDom: domain.DomainDebian,
		},
		{
			name:      "letter patch level orders under dpkg upstream rules",
			installed: "1.0.2g-1", bound: "1.0.2k", eco: PkgEcoDebian,
			wantCmp: -1, wantDom: domain.DomainUpstream, wantProj: "1.0.2g",
		},
		{
			name:      "tilde pre-release upstream bound",
			installed: "2.0-1", bound: "2.0~rc1", eco: PkgEcoDebian,
			wantCmp: 1, wantDom: domain.DomainUpstream, wantProj: "2.0",
		},
		{
			name:      "malformed installed version is never judged",
			installed: "1.0:2-1", bound: "1.0-1", eco: PkgEcoDebian,
			wantCmp: 2, wantDom: domain.DomainDebian,
		},
		{
			name:      "malformed bound is never judged",
			installed: "1.0-1", bound: "1.0:2", eco: PkgEcoDebian,
			wantCmp: 2, wantDom: domain.DomainDebian,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComparePackageBound(tt.installed, tt.bound, tt.eco)
			if got.Compare != tt.wantCmp {
				t.Errorf("Compare = %d, want %d (verdict %+v)", got.Compare, tt.wantCmp, got)
			}
			if got.Domain != tt.wantDom {
				t.Errorf("Domain = %q, want %q", got.Domain, tt.wantDom)
			}
			if got.Projected != tt.wantProj {
				t.Errorf("Projected = %q, want %q", got.Projected, tt.wantProj)
			}
		})
	}
}

func TestComparePackageBoundRpmApkSemver(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		bound     string
		eco       string
		wantCmp   int
		wantDom   domain.VersionDomain
		wantProj  string
	}{
		{
			name:      "rpm distro-format bound orders fully",
			installed: "0:9.8p1-4.el9", bound: "9.8p1-5.el9", eco: PkgEcoRPM,
			wantCmp: -1, wantDom: domain.DomainRPM,
		},
		{
			name:      "rpm upstream-only bound projects to the version component",
			installed: "1:10.0p1-5.el9", bound: "10.5", eco: PkgEcoRPM,
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p1",
		},
		{
			name:      "apk upstream-only bound strips the -rN build suffix",
			installed: "3.0-r0", bound: "3.0", eco: PkgEcoAlpine,
			wantCmp: 0, wantDom: domain.DomainAPK, wantProj: "3.0",
		},
		{
			name:      "apk distro-format bound orders fully",
			installed: "9.7_p1-r0", bound: "9.7_p1-r1", eco: PkgEcoAlpine,
			wantCmp: -1, wantDom: domain.DomainAPK,
		},
		{
			name:      "npm stays semver",
			installed: "1.2.3", bound: "1.2.4", eco: "npm",
			wantCmp: -1, wantDom: domain.DomainSemVer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComparePackageBound(tt.installed, tt.bound, tt.eco)
			if got.Compare != tt.wantCmp || got.Domain != tt.wantDom || got.Projected != tt.wantProj {
				t.Errorf("got %+v, want cmp=%d dom=%q proj=%q", got, tt.wantCmp, tt.wantDom, tt.wantProj)
			}
		})
	}
}

func TestCompareCPEBound(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		bound     string
		vType     string
		wantCmp   int
		wantDom   domain.VersionDomain
		wantProj  string
	}{
		{
			name:      "upstream observed version vs OpenSSH CVE bound",
			installed: "10.0p2", bound: "10.5", vType: "custom",
			wantCmp: -1, wantDom: domain.DomainOpenSSH,
		},
		{
			name:      "banner-normalized deb form projects before the OpenSSH verdict",
			installed: "10.0p2-5ubuntu5.4", bound: "10.5", vType: "custom",
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p2",
		},
		{
			name:      "epoch-carrying package form projects the same way",
			installed: "1:10.0p1-5ubuntu5.4", bound: "10.5", vType: "",
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p1",
		},
		{
			name:      "update level above the plain bound",
			installed: "10.5p1", bound: "10.5", vType: "",
			wantCmp: 1, wantDom: domain.DomainOpenSSH,
		},
		{
			name:      "patch level sorts after the base release",
			installed: "10.4p1", bound: "10.4", vType: "custom",
			wantCmp: 1, wantDom: domain.DomainOpenSSH,
		},
		{
			name:      "newer release above the bound",
			installed: "10.6-0ubuntu1", bound: "10.5", vType: "",
			wantCmp: 1, wantDom: domain.DomainOpenSSH, wantProj: "10.6",
		},
		{
			name:      "pre-release words keep generic ordering",
			installed: "2.0rc1", bound: "2.0", vType: "custom",
			wantCmp: -1, wantDom: domain.DomainGeneric,
		},
		{
			name:      "empty observed version is incomparable",
			installed: "n/a", bound: "10.5", vType: "",
			wantCmp: 2, wantDom: domain.DomainGeneric,
		},
		{
			name:      "deb versionType with upstream-only bound still projects",
			installed: "1:10.0p1-5ubuntu5.4", bound: "10.5", vType: "deb",
			wantCmp: -1, wantDom: domain.DomainOpenSSH, wantProj: "10.0p1",
		},
		{
			name:      "deb versionType with distro-format bound orders fully",
			installed: "10.0p2-5ubuntu5.4", bound: "10.0p2-5ubuntu5.5", vType: "deb",
			wantCmp: -1, wantDom: domain.DomainDebian,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareCPEBound(tt.installed, tt.bound, tt.vType)
			if got.Compare != tt.wantCmp || got.Domain != tt.wantDom || got.Projected != tt.wantProj {
				t.Errorf("got %+v, want cmp=%d dom=%q proj=%q", got, tt.wantCmp, tt.wantDom, tt.wantProj)
			}
		})
	}
}

// TestDomainForEcosystem pins the ecosystem label resolution the OSV
// path relies on ("Ubuntu:25.10" / "Debian:12" style feed labels).
func TestDomainForEcosystem(t *testing.T) {
	tests := map[string]domain.VersionDomain{
		"os_debian":    domain.DomainDebian,
		"Debian:12":    domain.DomainDebian,
		"Ubuntu:25.10": domain.DomainDebian,
		"os_rpm":       domain.DomainRPM,
		"Red Hat":      domain.DomainRPM,
		"os_alpine":    domain.DomainAPK,
		"npm":          domain.DomainSemVer,
		"PyPI":         domain.DomainPython,
		"some-unknown": domain.DomainGeneric,
		"cpe":          domain.DomainGeneric,
	}
	for eco, want := range tests {
		if got := DomainForEcosystem(eco); got != want {
			t.Errorf("DomainForEcosystem(%q) = %q, want %q", eco, got, want)
		}
	}
}

// TestVersionConstraintMaterialization pins the domain-tagged constraint
// model the matcher attaches to match evidence.
func TestVersionConstraintMaterialization(t *testing.T) {
	// OpenSSH CVE shape: an NVD CPE range with an exclusive end.
	cm := domain.CPEMatch{
		Vendor: "openbsd", Product: "openssh",
		VersionEndExcl: "10.5", VersionType: "custom",
	}
	c := cm.Constraint()
	if c.Domain != domain.DomainGeneric || c.LessThan != "10.5" || c.Fixed != "" || c.Introduced != "" {
		t.Errorf("CPE constraint = %+v", c)
	}

	// Ubuntu advisory shape: an OSV ECOSYSTEM range with a distro fixed-in.
	r := domain.VersionRange{Type: "ECOSYSTEM", Events: []domain.RangeEvent{
		{Introduced: "0"}, {Fixed: "1:10.0p1-5ubuntu5.5"},
	}}
	rc := r.Constraint(domain.DomainDebian)
	if rc.Domain != domain.DomainDebian || rc.Fixed != "1:10.0p1-5ubuntu5.5" || rc.Introduced != "" {
		t.Errorf("OSV constraint = %+v", rc)
	}

	// versionType resolution: deb/dpkg -> debian, semver -> semver,
	// maven/unknown -> generic.
	if got := domain.VersionDomainForType("deb"); got != domain.DomainDebian {
		t.Errorf("VersionDomainForType(deb) = %q", got)
	}
	if got := domain.VersionDomainForType("maven"); got != domain.DomainGeneric {
		t.Errorf("VersionDomainForType(maven) = %q", got)
	}
}
