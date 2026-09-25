package vulnerabilities

import (
	"context"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// The acceptance matrix from the implementation plan, matcher section:
// heuristics cannot starve a definitive result, a wrong or versionless
// identity seen first cannot suppress a later correct range, and the
// caller cap applies after ranking with an explicit truncated flag.

// opensshIndex builds an index with the NVD OpenSSH applicability shape:
// one range CVE (< 10.5 exclusive), plus `heuristicCVEs` identity-only
// CVEs of the same product that sort early and used to starve everything
// behind the per-identity candidate cap.
func opensshIndex(heuristicCVEs int) *fakeIndex {
	ranged := domain.CPEMatch{
		Vendor: "openbsd", Product: "openssh",
		VersionStartIncl: "", VersionEndExcl: "10.5",
		CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
	}
	cves := map[string]*domain.Vulnerability{}
	for i := 0; i < heuristicCVEs; i++ {
		id := "CVE-2026-0" + string(rune('0'+i/10)) + string(rune('0'+i%10))
		cves[id] = &domain.Vulnerability{
			CVEID:      id,
			State:      domain.CVEStatePublished,
			CPEMatches: []domain.CPEMatch{{Vendor: "openbsd", Product: "openssh", CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}},
		}
	}
	// The definitive CVE sits last in the candidate order.
	cves["CVE-2026-9999"] = &domain.Vulnerability{
		CVEID:      "CVE-2026-9999",
		State:      domain.CVEStatePublished,
		CPEMatches: []domain.CPEMatch{ranged},
	}
	return &fakeIndex{cves: cves}
}

// Fifty heuristics must not starve a later definitive range result.
func TestHeuristicsCannotStarveDefinitiveRange(t *testing.T) {
	m := &Matcher{Index: opensshIndex(60), MaxPerItem: 10}
	matches, _, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2 Debian 7"})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	var definitive int
	for _, mt := range matches {
		if mt.MatchType == domain.MatchCPERange {
			definitive++
		}
	}
	if definitive == 0 {
		t.Fatalf("no CPE_RANGE match among %d results — the definitive result was starved", len(matches))
	}
	if len(matches) != 10 {
		t.Errorf("matches = %d, want the caller cap of 10", len(matches))
	}
}

// The caller cap applies after ranking: when more matches exist than fit,
// the matcher must say so instead of silently dropping the tail.
func TestTruncatedFlagReportsCapHiding(t *testing.T) {
	m := &Matcher{Index: opensshIndex(60), MaxPerItem: 10}
	_, truncated, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2 Debian 7"})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if !truncated {
		t.Fatalf("truncated = false, want true (61 candidates, cap 10)")
	}
}

// 10.0p1 / 10.0p2 match the exclusive <10.5 bound in the OpenSSH domain;
// 10.5 and later fixed releases do not (plan acceptance 1-3).
func TestOpenSSHExclusiveBoundEnds(t *testing.T) {
	m := &Matcher{Index: opensshIndex(0), MaxPerItem: 10}
	for _, ver := range []string{"10.0p1", "10.0p2 Debian 7", "10.4p1 Debian 3", "9.9"} {
		matches, _, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: ver})
		if err != nil {
			t.Fatalf("match %q: %v", ver, err)
		}
		if len(matches) != 1 || matches[0].MatchType != domain.MatchCPERange {
			t.Errorf("version %q: matches = %v, want one CPE_RANGE", ver, matches)
		}
	}
	for _, ver := range []string{"10.5", "10.5p1", "10.7p2"} {
		matches, _, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: ver})
		if err != nil {
			t.Fatalf("match %q: %v", ver, err)
		}
		if len(matches) != 0 {
			t.Errorf("fixed version %q must not match the exclusive bound, got %v", ver, matches)
		}
	}
}

// A versionless identity must not resurrect a CVE whose versioned bounds
// rejected the observed version — even when the CVE also carries a
// versionless CPE expression of the same product (the mixed-expression
// shape real NVD records have).
func TestVersionlessCandidateCannotResurrectRangeMiss(t *testing.T) {
	vuln := &domain.Vulnerability{
		CVEID: "CVE-2026-4321",
		State: domain.CVEStatePublished,
		CPEMatches: []domain.CPEMatch{
			// Versioned statement the observed version does not fit.
			{Vendor: "openbsd", Product: "openssh", VersionEndExcl: "10.5", CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
			// Versionless expression of the same product.
			{Vendor: "openbsd", Product: "openssh", CPE: "cpe:2.3:a:openbsd:openssh"},
		},
	}
	m := &Matcher{Index: &fakeIndex{cves: map[string]*domain.Vulnerability{"CVE-2026-4321": vuln}}, MaxPerItem: 10}
	matches, _, err := m.Match(context.Background(), MatchInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.7p2"})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("fixed version must not surface via the versionless expression, got %v", matches)
	}
}

// A wrong identity evaluated first cannot suppress a later correct range
// verdict on the same CVE (multi-identity evaluation, plan acceptance 4).
func TestWrongIdentityCannotSuppressLaterCorrectRange(t *testing.T) {
	// One CVE carrying two applicability statements: a pinned old release
	// for a DIFFERENT candidate identity order, and the OpenSSH range.
	vuln := &domain.Vulnerability{
		CVEID: "CVE-2026-8765",
		State: domain.CVEStatePublished,
		CPEMatches: []domain.CPEMatch{
			// A pin that the WRONG identity (explicit scanner CPE with an
			// old upstream version) rejects...
			{Vendor: "openbsd", Product: "openssh", Version: "9.1", CPE: "cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*:*"},
			// ...and the range the authoritative observed version fits.
			{Vendor: "openbsd", Product: "openssh", VersionEndExcl: "10.5", CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
		},
	}
	m := &Matcher{Index: &fakeIndex{cves: map[string]*domain.Vulnerability{"CVE-2026-8765": vuln}}, MaxPerItem: 10}
	// The explicit CPE carries a stale upstream version; the synthesized
	// identity (first, authoritative) carries the true observed one.
	matches, _, err := m.Match(context.Background(), MatchInput{
		Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.0p2 Debian 7",
		CPEs: []string{"cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*:*"},
	})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %v, want the CPE_RANGE verdict", matches)
	}
	if matches[0].MatchType != domain.MatchCPERange {
		t.Errorf("match type = %s, want CPE_RANGE (the rejected pin must not downgrade it)", matches[0].MatchType)
	}
}
