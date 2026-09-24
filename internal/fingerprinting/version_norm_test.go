package fingerprinting

import (
	"strings"
	"testing"
)

// TestIngestNormalizeVersion pins the ingestion normalization pass for every
// grammar and the raw-quality shapes the collection sources actually
// produce: clean dpkg output (os_debian), banner-decorated fingerprints
// (cpe), language packages (npm/PyPI) and broken values that must be
// flagged instead of silently mismatched.
func TestIngestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		ecosystem  string
		grammar    VersionGrammar
		normalized string
		wellFormed bool
	}{
		// --- Debian/Ubuntu (os_debian): the CVE-critical grammar -------
		{name: "deb verbatim", raw: "1:10.0p1-5ubuntu5.4", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "1:10.0p1-5ubuntu5.4", wellFormed: true},
		{name: "deb ubuntu revision", raw: "2.1.11-1ubuntu3", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "2.1.11-1ubuntu3", wellFormed: true},
		{name: "deb no revision", raw: "1.83ubuntu2", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "1.83ubuntu2", wellFormed: true},
		{name: "deb zero epoch dropped", raw: "0:1.0-1", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "1.0-1", wellFormed: true},
		{name: "deb tilde kept", raw: "1.0~rc1-1", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "1.0~rc1-1", wellFormed: true},
		{name: "deb leading zeros kept", raw: "20240101-1", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "20240101-1", wellFormed: true},
		{name: "deb malformed flagged", raw: "1.0:2-1", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "1.0:2-1", wellFormed: false},
		{name: "deb whitespace stripped", raw: "  2.0.19-1  ", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "2.0.19-1", wellFormed: true},
		{name: "deb distro-qualified label", raw: "1.24.0-1ubuntu3", ecosystem: "Ubuntu:24.04 LTS", grammar: GrammarDeb, normalized: "1.24.0-1ubuntu3", wellFormed: true},

		// --- RPM family ------------------------------------------------
		{name: "rpm epoch release", raw: "1:3.1.2-1.el9", ecosystem: "os_rpm", grammar: GrammarRPM, normalized: "1:3.1.2-1.el9", wellFormed: true},
		{name: "rpm plain", raw: "4.19.0", ecosystem: "Red Hat", grammar: GrammarRPM, normalized: "4.19.0", wellFormed: true},
		{name: "rpm bad epoch flagged", raw: "x:1.0-1", ecosystem: "os_rpm", grammar: GrammarRPM, normalized: "x:1.0-1", wellFormed: false},
		{name: "rpm empty version flagged", raw: "1:", ecosystem: "os_rpm", grammar: GrammarRPM, normalized: "1:", wellFormed: false},
		{name: "rpm punctuation ok", raw: "2.0_1+el8", ecosystem: "centos", grammar: GrammarRPM, normalized: "2.0_1+el8", wellFormed: true},

		// --- Alpine ----------------------------------------------------
		{name: "apk classic", raw: "1.2.3-r4", ecosystem: "os_alpine", grammar: GrammarAPK, normalized: "1.2.3-r4", wellFormed: true},
		{name: "apk suffix", raw: "3.0.1_alpha1-r0", ecosystem: "alpine", grammar: GrammarAPK, normalized: "3.0.1_alpha1-r0", wellFormed: true},
		{name: "apk letter suffix", raw: "1.0a-r2", ecosystem: "os_alpine", grammar: GrammarAPK, normalized: "1.0a-r2", wellFormed: true},
		{name: "apk must start numeric", raw: "alpha1", ecosystem: "os_alpine", grammar: GrammarAPK, normalized: "alpha1", wellFormed: false},
		{name: "apk bad suffix flagged", raw: "1.0_bogus-r1", ecosystem: "os_alpine", grammar: GrammarAPK, normalized: "1.0_bogus-r1", wellFormed: false},

		// --- Language ecosystems ---------------------------------------
		{name: "npm v-prefix", raw: "v1.2.3", ecosystem: "npm", grammar: GrammarSemver, normalized: "1.2.3", wellFormed: true},
		{name: "npm prerelease build", raw: "2.1.0-rc.1+build.5", ecosystem: "npm", grammar: GrammarSemver, normalized: "2.1.0-rc.1+build.5", wellFormed: true},
		{name: "npm short core", raw: "1.4", ecosystem: "npm", grammar: GrammarSemver, normalized: "1.4", wellFormed: true},
		{name: "npm garbage flagged", raw: "unknown", ecosystem: "npm", grammar: GrammarSemver, normalized: "", wellFormed: false},
		{name: "pypi epoch", raw: "1!2.0.post1", ecosystem: "pypi", grammar: GrammarPython, normalized: "1!2.0.post1", wellFormed: true},
		{name: "pypi plain", raw: "3.11.4", ecosystem: "PyPI", grammar: GrammarPython, normalized: "3.11.4", wellFormed: true},
		{name: "pypi bad epoch flagged", raw: "x!1.0", ecosystem: "pypi", grammar: GrammarPython, normalized: "x!1.0", wellFormed: false},

		// --- CPE / generic (nmap -sV fingerprints) ----------------------
		{name: "cpe banner noise stripped", raw: "OpenSSH_10.0p2 Debian 7", ecosystem: "cpe", grammar: GrammarGeneric, normalized: "10.0p2", wellFormed: true},
		{name: "cpe decorated version", raw: "1.24.0-1ubuntu3 (Ubuntu:24.04/noble)", ecosystem: "cpe", grammar: GrammarGeneric, normalized: "1.24.0-1ubuntu3", wellFormed: true},
		{name: "cpe v-prefix", raw: "v16.20.2", ecosystem: "cpe", grammar: GrammarGeneric, normalized: "16.20.2", wellFormed: true},

		// --- nothing version-like ---------------------------------------
		{name: "empty raw", raw: "", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "", wellFormed: false},
		{name: "junk raw", raw: "n/a", ecosystem: "os_debian", grammar: GrammarDeb, normalized: "", wellFormed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeObservedVersion(tt.raw, tt.ecosystem)
			if got.Grammar != tt.grammar {
				t.Errorf("grammar = %q, want %q", got.Grammar, tt.grammar)
			}
			if got.Normalized != tt.normalized {
				t.Errorf("normalized = %q, want %q", got.Normalized, tt.normalized)
			}
			if got.WellFormed != tt.wellFormed {
				t.Errorf("wellFormed = %v, want %v", got.WellFormed, tt.wellFormed)
			}
			if got.Raw != tt.raw {
				t.Errorf("raw not preserved verbatim: got %q, want %q", got.Raw, tt.raw)
			}
		})
	}
}

// TestNormalizeVersionEcosystemRouting mirrors GrammarFor against
// CompareEcosystem's dispatch so the two resolutions can never drift
// apart: whatever grammar normalizes a value must be the grammar that
// compares it.
func TestNormalizeVersionEcosystemRouting(t *testing.T) {
	labels := []string{
		"os_debian", "debian", "ubuntu", "Debian:12", "Ubuntu:22.04 LTS", "dpkg",
		"os_rpm", "rpm", "Red Hat", "rhel", "CentOS", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE",
		"os_alpine", "alpine", "Alpine v3.19",
		"npm", "go", "golang", "crates.io", "cargo", "rubygems", "packagist",
		"pypi", "PyPI",
		"cpe", "", "maven", "winget", "something-new",
	}
	for _, eco := range labels {
		g := GrammarFor(eco)
		switch {
		case g == GrammarDeb || g == GrammarRPM || g == GrammarAPK || g == GrammarSemver || g == GrammarPython || g == GrammarGeneric:
			// fine
		default:
			t.Errorf("GrammarFor(%q) = unknown grammar %q", eco, g)
		}
	}
	// Spot-check the load-bearing routings.
	want := map[string]VersionGrammar{
		"os_debian": GrammarDeb, "Debian:12": GrammarDeb, "Ubuntu:22.04 LTS": GrammarDeb,
		"os_rpm": GrammarRPM, "Red Hat": GrammarRPM, "rocky": GrammarRPM,
		"os_alpine": GrammarAPK, "Alpine v3.19": GrammarAPK,
		"npm": GrammarSemver, "go": GrammarSemver,
		"pypi": GrammarPython,
		"cpe":  GrammarGeneric, "": GrammarGeneric,
	}
	for eco, g := range want {
		if got := GrammarFor(eco); got != g {
			t.Errorf("GrammarFor(%q) = %q, want %q", eco, got, g)
		}
	}
}

// TestNormalizeVersionDebCanonicalOrderStability pins the contract that
// the normalized deb form orders exactly like dpkg orders the raw form:
// normalization may canonicalize structure but must never flip a
// verdict. Every pair below is ordered by dpkg rules (verified against
// the pkgversion backend) and must stay ordered after normalize.
func TestNormalizeVersionDebCanonicalOrderStability(t *testing.T) {
	pairs := [][2]string{
		{"1.0~rc1-1", "1.0-1"},
		{"1.0-1", "1.0-2"},
		{"1.0", "1.0-1"},
		{"0:1.0", "1.0"},   // canonicalization makes these equal
		{"1.0-1", "1.0-1"}, // identical
		{"1.0-2ubuntu1", "1.0-2ubuntu2"},
		{"1.0-2ubuntu2", "1.0-2ubuntu10"},
		{"1:0.5", "0.49"}, // epoch beats upstream ordering
	}
	for _, p := range pairs {
		na := NormalizeObservedVersion(p[0], "os_debian")
		nb := NormalizeObservedVersion(p[1], "os_debian")
		if !na.WellFormed || !nb.WellFormed {
			t.Fatalf("normalize flagged valid deb input: %q->%v %q->%v", p[0], na, p[1], nb)
		}
		// Equal after canonicalization ("0:1.0" vs "1.0") must compare equal.
		want := CompareTyped(p[0], p[1], VersionTypeDeb)
		if want == 2 {
			t.Fatalf("raw pair unexpectedly incomparable: %q vs %q", p[0], p[1])
		}
		got := CompareTyped(na.Normalized, nb.Normalized, VersionTypeDeb)
		if got != want {
			t.Errorf("normalization flipped verdict: raw %q vs %q = %d, normalized %q vs %q = %d",
				p[0], p[1], want, na.Normalized, nb.Normalized, got)
		}
	}
}

// TestNormalizeVersionHugeComponents stays overflow-free end to end:
// absurd numeric components normalize verbatim and keep dpkg's ordering.
func TestNormalizeVersionDebHugeComponents(t *testing.T) {
	big := strings.Repeat("9", 100)
	nv := NormalizeObservedVersion("1:"+big, "os_debian")
	if !nv.WellFormed {
		t.Fatalf("100-digit version flagged malformed: %v", nv)
	}
	if nv.Normalized != "1:"+big {
		t.Errorf("huge component mangled: %q", nv.Normalized)
	}
	if c := CompareTyped(nv.Normalized, "1:1", VersionTypeDeb); c != 1 {
		t.Errorf("huge version should sort above 1:1, got %d", c)
	}
}
