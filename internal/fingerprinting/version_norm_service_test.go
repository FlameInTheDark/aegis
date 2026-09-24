package fingerprinting

import "testing"

// TestNormalizeServiceVersion pins the banner-version normalization the
// service pipeline depends on: nmap -sV versions like "10.0p2 Ubuntu
// 5ubuntu5.4" must become grammar-canonical, comparable deb versions
// with the structured epoch/upstream/revision breakdown filled — not
// truncated to the first token like CleanVersion does.
func TestNormalizeServiceVersion(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		wantNormalized string
		wantGrammar    VersionGrammar
		wantWellFormed bool
		wantEpoch      uint64
		wantUpstream   string
		wantRevision   string
	}{
		{
			name: "banner with space-separated ubuntu revision",
			raw:  "10.0p2 Ubuntu 5ubuntu5.4", wantNormalized: "10.0p2-5ubuntu5.4",
			wantGrammar: GrammarDeb, wantWellFormed: true,
			wantUpstream: "10.0p2", wantRevision: "5ubuntu5.4",
		},
		{
			name: "banner with hyphenated ubuntu revision",
			raw:  "10.0p2 Ubuntu-5ubuntu5.4", wantNormalized: "10.0p2-5ubuntu5.4",
			wantGrammar: GrammarDeb, wantWellFormed: true,
			wantUpstream: "10.0p2", wantRevision: "5ubuntu5.4",
		},
		{
			name: "banner with distro decoration words",
			raw:  "8.9p1 Ubuntu Linux 3ubuntu0.4", wantNormalized: "8.9p1-3ubuntu0.4",
			wantGrammar: GrammarDeb, wantWellFormed: true,
			wantUpstream: "8.9p1", wantRevision: "3ubuntu0.4",
		},
		{
			name: "banner with product prefix and debian revision",
			raw:  "OpenSSH_10.0p2 Debian 7", wantNormalized: "10.0p2-7",
			wantGrammar: GrammarDeb, wantWellFormed: true,
			wantUpstream: "10.0p2", wantRevision: "7",
		},
		{
			name: "banner with epoch riding along",
			raw:  "2:9.6p1 Ubuntu 5ubuntu5", wantNormalized: "2:9.6p1-5ubuntu5",
			wantGrammar: GrammarDeb, wantWellFormed: true,
			wantEpoch: 2, wantUpstream: "9.6p1", wantRevision: "5ubuntu5",
		},
		{
			name: "plain upstream version falls back to generic",
			raw:  "9.6p1", wantNormalized: "9.6p1",
			wantGrammar: GrammarGeneric, wantWellFormed: true,
		},
		{
			name: "semver-shaped banner falls back to generic",
			raw:  "1.24.0", wantNormalized: "1.24.0",
			wantGrammar: GrammarGeneric, wantWellFormed: true,
		},
		{
			name: "product prefix without tail falls back to generic",
			raw:  "OpenSSH_10.0p2", wantNormalized: "10.0p2",
			wantGrammar: GrammarGeneric, wantWellFormed: true,
		},
		{
			name: "distro token with no revision tail falls back to generic",
			raw:  "10.0p2 Ubuntu", wantNormalized: "10.0p2",
			wantGrammar: GrammarGeneric, wantWellFormed: true,
		},
		{
			name: "empty version stays empty and malformed",
			raw:  "", wantNormalized: "",
			wantGrammar: GrammarGeneric, wantWellFormed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nv := NormalizeServiceVersion(tc.raw)
			if nv.Raw != tc.raw {
				t.Errorf("Raw = %q, want %q (raw must stay verbatim)", nv.Raw, tc.raw)
			}
			if nv.Normalized != tc.wantNormalized {
				t.Errorf("Normalized = %q, want %q", nv.Normalized, tc.wantNormalized)
			}
			if nv.Grammar != tc.wantGrammar {
				t.Errorf("Grammar = %q, want %q", nv.Grammar, tc.wantGrammar)
			}
			if nv.WellFormed != tc.wantWellFormed {
				t.Errorf("WellFormed = %v, want %v", nv.WellFormed, tc.wantWellFormed)
			}
			if nv.Epoch != tc.wantEpoch || nv.Upstream != tc.wantUpstream || nv.Revision != tc.wantRevision {
				t.Errorf("breakdown = {%d %q %q}, want {%d %q %q}",
					nv.Epoch, nv.Upstream, nv.Revision, tc.wantEpoch, tc.wantUpstream, tc.wantRevision)
			}
		})
	}
}

// TestNormalizeObservedVersionDebDetail pins the structured breakdown on
// the generic ingestion path: once a deb version parses, the API can
// render the exact parts CVE matching compares without re-parsing.
func TestNormalizeObservedVersionDebDetail(t *testing.T) {
	nv := NormalizeObservedVersion("1:10.0p1-5ubuntu5.4", "os_debian")
	if !nv.WellFormed || nv.Normalized != "1:10.0p1-5ubuntu5.4" {
		t.Fatalf("normalized = %q wellformed=%v, want canonical well-formed", nv.Normalized, nv.WellFormed)
	}
	if nv.Epoch != 1 || nv.Upstream != "10.0p1" || nv.Revision != "5ubuntu5.4" {
		t.Errorf("breakdown = {%d %q %q}, want {1 10.0p1 5ubuntu5.4}", nv.Epoch, nv.Upstream, nv.Revision)
	}
	// Zero epoch: canonical form drops it, the breakdown keeps the parts.
	nv = NormalizeObservedVersion("0:1.0-1", "os_debian")
	if nv.Normalized != "1.0-1" || nv.Epoch != 0 || nv.Upstream != "1.0" || nv.Revision != "1" {
		t.Errorf("zero-epoch breakdown wrong: %q {%d %q %q}", nv.Normalized, nv.Epoch, nv.Upstream, nv.Revision)
	}
	// Canonical input is idempotent: normalizing the normalized value
	// must not drift (the property the persisted version_norm relies on).
	nv = NormalizeObservedVersion("5.0.0~alpha1-0ubuntu8", "os_debian")
	if !nv.WellFormed || nv.Normalized != "5.0.0~alpha1-0ubuntu8" {
		t.Errorf("canonical passthrough broken: %q wellformed=%v", nv.Normalized, nv.WellFormed)
	}
	if nv.Upstream != "5.0.0~alpha1" || nv.Revision != "0ubuntu8" {
		t.Errorf("tilde breakdown wrong: {%d %q %q}", nv.Epoch, nv.Upstream, nv.Revision)
	}
}
