package vulnerabilities

import (
	"context"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// fakeIndex is a deterministic in-memory index for table-driven tests.
type fakeIndex struct {
	cves map[string]*domain.Vulnerability
	osv  map[string][]domain.OSVRecord
}

func (f *fakeIndex) CandidateCVEsByProduct(ctx context.Context, vendor, product string, limit int) ([]string, error) {
	var out []string
	for id, v := range f.cves {
		for _, cm := range v.CPEMatches {
			if cm.Vendor == vendor && cm.Product == product {
				out = append(out, id)
				break
			}
		}
	}
	return out, nil
}

func (f *fakeIndex) CVE(ctx context.Context, id string) (*domain.Vulnerability, error) {
	return f.cves[id], nil
}

func (f *fakeIndex) EPSSForCVEs(ctx context.Context, ids []string) (map[string]float64, error) {
	return map[string]float64{}, nil
}

func (f *fakeIndex) KEVSet(ctx context.Context) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func (f *fakeIndex) OSVForPackage(ctx context.Context, eco, name string) ([]domain.OSVRecord, error) {
	return f.osv[eco+"/"+name], nil
}

func testIndex() *fakeIndex {
	cpe := func(v, p, ver string) domain.CPEMatch {
		return domain.CPEMatch{CPE: "cpe:2.3:a:" + v + ":" + p + ":" + ver + ":*:*:*:*:*:*:*", Vendor: v, Product: p, Version: ver}
	}
	ranged := domain.CPEMatch{Vendor: "apache", Product: "httpd",
		VersionStartIncl: "2.4.0", VersionEndExcl: "2.4.51",
		CPE: "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*"}
	return &fakeIndex{
		cves: map[string]*domain.Vulnerability{
			"CVE-2021-23017": {CVEID: "CVE-2021-23017", State: domain.CVEStatePublished, CPEMatches: []domain.CPEMatch{cpe("nginx", "nginx", "1.24.0")}},
			"CVE-2021-41773": {CVEID: "CVE-2021-41773", State: domain.CVEStatePublished, CPEMatches: []domain.CPEMatch{ranged}},
			"CVE-2099-0001":  {CVEID: "CVE-2099-0001", State: domain.CVEStateRejected, CPEMatches: []domain.CPEMatch{cpe("nginx", "nginx", "1.24.0")}},
		},
		osv: map[string][]domain.OSVRecord{
			"go/github.com/example/app": {
				{ID: "OSV-2026-0001", CVEIDs: []string{"CVE-2026-0001"},
					AffectedRanges: []domain.VersionRange{{Type: "SEMVER", Events: []domain.RangeEvent{{Introduced: "1.0.0", Fixed: "1.2.3"}}}}},
			},
			"npm/left-pad": {
				{ID: "GHSA-xxxx-yyyy", AffectedRanges: []domain.VersionRange{}},
			},
		},
	}
}

func TestMatchExactCPE(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, err := m.Match(context.Background(), MatchInput{Vendor: "nginx", Product: "nginx", Version: "1.24.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].MatchType != domain.MatchExactCPE {
		t.Fatalf("want exact CPE match, got %+v", matches)
	}
	if matches[0].Confidence < 0.9 {
		t.Fatalf("exact match confidence too low: %v", matches[0].Confidence)
	}
}

func TestMatchCPERange(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, _ := m.Match(context.Background(), MatchInput{Vendor: "apache", Product: "httpd", Version: "2.4.49"})
	if len(matches) != 1 || matches[0].MatchType != domain.MatchCPERange {
		t.Fatalf("want CPE_RANGE for 2.4.49, got %+v", matches)
	}
	// 2.4.51 is outside the range: no match.
	matches, _ = m.Match(context.Background(), MatchInput{Vendor: "apache", Product: "httpd", Version: "2.4.51"})
	if len(matches) != 0 {
		t.Fatalf("2.4.51 must not match, got %+v", matches)
	}
}

func TestMatchUnknownVersionIsHeuristic(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, _ := m.Match(context.Background(), MatchInput{Vendor: "apache", Product: "httpd"})
	if len(matches) != 1 || matches[0].MatchType != domain.MatchHeuristic {
		t.Fatalf("version-unknown must be heuristic (potential), got %+v", matches)
	}
	if matches[0].Confidence > 0.5 {
		t.Fatalf("heuristic confidence must stay low, got %v", matches[0].Confidence)
	}
}

func TestRejectedCVEsNeverMatch(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, _ := m.Match(context.Background(), MatchInput{Vendor: "nginx", Product: "nginx", Version: "1.21.0"})
	for _, match := range matches {
		if match.CVEID == "CVE-2099-0001" {
			t.Fatal("rejected CVE must be excluded")
		}
	}
}

func TestPackageMatchingOSV(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, _ := m.Match(context.Background(), MatchInput{Ecosystem: "go", PackageName: "github.com/example/app", Version: "1.1.0"})
	if len(matches) != 1 || matches[0].CVEID != "CVE-2026-0001" || matches[0].OSVID != "OSV-2026-0001" {
		t.Fatalf("want OSV package match, got %+v", matches)
	}
	// Fixed version: no match.
	matches, _ = m.Match(context.Background(), MatchInput{Ecosystem: "go", PackageName: "github.com/example/app", Version: "1.2.3"})
	if len(matches) != 0 {
		t.Fatalf("fixed version must not match, got %+v", matches)
	}
}

func TestPackageVersionUnknownStaysPotential(t *testing.T) {
	m := &Matcher{Index: testIndex()}
	matches, _ := m.Match(context.Background(), MatchInput{Ecosystem: "npm", PackageName: "left-pad"})
	if len(matches) != 1 || matches[0].MatchType != domain.MatchHeuristic {
		t.Fatalf("advisory without ranges must stay potential, got %+v", matches)
	}
}

func TestBestSeverityPreference(t *testing.T) {
	v := &domain.Vulnerability{
		CVSSv2: &domain.CVSS{Score: 5.0},
		CVSSv3: &domain.CVSS{Score: 8.8},
		CVSSv4: &domain.CVSS{Score: 9.1},
	}
	score, _ := BestSeverity(v)
	if score != 8.8 {
		t.Fatalf("v3 preferred, got %v", score)
	}
}

// TestMatchUserCaseOpenSSH pins the full field scenario: the CVE says
// OpenSSH is affected below 10.4 (versionType custom, start 0); the scanner
// observed banner version "10.0p2 Debian 7" — it must match as a CPE range
// finding. The fixed release (10.4p1) must NOT match at all: the range
// rejects it and the versionless identity candidate may not resurrect it
// as a "potential".
func TestMatchUserCaseOpenSSH(t *testing.T) {
	idx := &fakeIndex{cves: map[string]*domain.Vulnerability{
		"CVE-2026-OPENSSH": {CVEID: "CVE-2026-OPENSSH", State: domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{
				CPE:    "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
				Vendor: "openbsd", Product: "openssh",
				VersionStartIncl: "0", VersionEndExcl: "10.4", VersionType: "custom",
			}}},
	}}
	m := &Matcher{Index: idx}
	matches, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2 Debian 7"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].MatchType != domain.MatchCPERange {
		t.Fatalf("10.0p2 Debian 7 must match as CPE range, got %+v", matches)
	}
	if matches[0].Confidence != 0.9 {
		t.Errorf("range confidence = %v, want 0.9", matches[0].Confidence)
	}

	// Fixed release: outside the range — and no potential downgrade.
	matches, _ = m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.4p1 Debian 3"})
	if len(matches) != 0 {
		t.Fatalf("10.4p1 is fixed and must not match in any form, got %+v", matches)
	}

	// Unknown version stays a low-confidence potential (honest).
	matches, _ = m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH"})
	if len(matches) != 1 || matches[0].MatchType != domain.MatchHeuristic {
		t.Fatalf("unknown version must stay heuristic potential, got %+v", matches)
	}
}

// TestMatchExactPinWithBannerNoise: a pinned CPE version still matches when
// the observed string carries scanner noise ("10.0p2 Debian 7" vs "10.0p2").
func TestMatchExactPinWithBannerNoise(t *testing.T) {
	idx := &fakeIndex{cves: map[string]*domain.Vulnerability{
		"CVE-2026-PIN": {CVEID: "CVE-2026-PIN", State: domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{
				CPE:    "cpe:2.3:a:openbsd:openssh:10.0p2:*:*:*:*:*:*:*",
				Vendor: "openbsd", Product: "openssh", Version: "10.0p2",
			}}},
	}}
	m := &Matcher{Index: idx}
	matches, _ := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2 Debian 7"})
	if len(matches) != 1 || matches[0].MatchType != domain.MatchExactCPE {
		t.Fatalf("pinned version must match despite banner noise, got %+v", matches)
	}
	// A different patch level is not the pinned version.
	matches, _ = m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p1 Debian 7"})
	if len(matches) != 0 {
		t.Fatalf("10.0p1 must not match pin 10.0p2, got %+v", matches)
	}
}

// TestRangeMissBlocksPotential: with a known observed version that does not
// fit the CVE's declared range, the versionless CPE candidate must not
// produce a "potential" finding for the same CVE.
func TestRangeMissBlocksPotential(t *testing.T) {
	idx := &fakeIndex{cves: map[string]*domain.Vulnerability{
		"CVE-2026-R": {CVEID: "CVE-2026-R", State: domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{
				CPE: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", Vendor: "v", Product: "p",
				VersionEndExcl: "2.0",
			}}},
	}}
	m := &Matcher{Index: idx}
	matches, _ := m.Match(context.Background(), MatchInput{Vendor: "v", Product: "p", Version: "3.0"})
	if len(matches) != 0 {
		t.Fatalf("3.0 is outside [0,2.0): no match of any kind, got %+v", matches)
	}
}
