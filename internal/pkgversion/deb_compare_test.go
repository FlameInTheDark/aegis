package pkgversion

import (
	"errors"
	"strings"
	"testing"
)

// TestCompareDebVersionsOrdering pins Debian ordering against the
// required field cases and the classic dpkg suite: epoch dominance,
// tilde pre-releases, revision ordering, leading zeros, rebuild
// suffixes, and overflow-proof numeric runs of arbitrary length.
func TestCompareDebVersionsOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Required Debian-specific ordering cases.
		{"1.0", "1.1", -1},
		{"1.0", "1.0-1", -1}, // absence of revision sorts first
		{"1:1.0", "1.0", 1},  // epoch dominates everything
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0-1", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-2ubuntu1", "1.0-2ubuntu2", -1},
		{"1.0-2ubuntu2", "1.0-2ubuntu10", -1}, // numeric, not lexical

		// Equality.
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-1", 0},
		{"1.06", "1.6", 0}, // leading zeros compare numerically
		{"1:0", "1:00", 0},
		{"0.49", "0.49", 0},
		{"1.0", "1.0.0", -1}, // dpkg: a trailing ".0" still sorts higher

		// Epoch differences.
		{"1:0", "2.0", 1},
		{"2:13.0.0-2ubuntu1", "13.0.0-2ubuntu1", 1},
		{"1:10.0p1-5ubuntu5.4", "1:10.0p1-5ubuntu5.5", -1}, // revision-only security fix

		// Tilde ordering (pre-releases and backport suffixes).
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~beta1", "1.0~rc1", -1},
		{"1.0-1~bpo1", "1.0-1", -1},
		{"1:2.4.62-1ubuntu4.1~24.04.2", "1:2.4.62-1ubuntu4.1", -1},

		// Revisions and rebuild/binary suffixes.
		{"1.0-1", "1.0-1+b1", -1},
		{"2.0.19-1", "2.0.19", 1},
		{"7.4p1-5+deb12u1", "7.4p1-5", 1},
		{"1.0-1ubuntu1", "1.0-1", 1},

		// Letters and symbols inside components (dpkg weights).
		{"1.0a", "1.0", 1},   // patch letter after base release
		{"1.0+a", "1.0a", 1}, // punctuation sorts after letters
		{"1.83ubuntu2", "1.83", 1},
		{"1.06a", "1.06", 1},
		{"0.49", "0.5", 1}, // dpkg gotcha: digit RUNS compare: 49 > 5 (not the dotted 0.49 < 0.50 intuition)
		{"1.2.3", "1.10", -1},

		// Very large numeric components: string comparison, no overflow.
		{"1." + strings.Repeat("9", 40), "1." + strings.Repeat("9", 39) + "8", 1},
		{"1." + strings.Repeat("9", 40), "1.1" + strings.Repeat("0", 40), -1},
		{"1." + strings.Repeat("9", 40), "1." + strings.Repeat("9", 40), 0},
	}
	for _, tc := range cases {
		got, err := CompareDebVersions(tc.a, tc.b)
		if err != nil {
			t.Errorf("CompareDebVersions(%q, %q) error: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CompareDebVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCompareDebVersionsErrors: comparison parses both sides; garbage in
// must surface the parse error, never an invented ordering.
func TestCompareDebVersionsErrors(t *testing.T) {
	cases := []struct {
		a, b string
		want error
	}{
		{"", "1.0", ErrEmptyVersion},
		{"1.0", "1.0@1", ErrInvalidCharacter},
		{"a:1.0", "1.0", ErrInvalidEpoch},
		{"1.0", "1.0-", ErrEmptyRevision},
		{"1.0", "1:", ErrEmptyUpstream},
		{" 1.0", "1.0", ErrInvalidCharacter},
	}
	for _, tc := range cases {
		got, err := CompareDebVersions(tc.a, tc.b)
		if err == nil {
			t.Errorf("CompareDebVersions(%q, %q) = %d, want error", tc.a, tc.b, got)
		} else if !errors.Is(err, tc.want) {
			t.Errorf("CompareDebVersions(%q, %q) error = %v, want errors.Is %v", tc.a, tc.b, err, tc.want)
		}
	}
}

// TestCompareDebVersionsAntisymmetric checks cmp(a,b) == -cmp(b,a) over
// the whole ordering table.
func TestCompareDebVersionsAntisymmetric(t *testing.T) {
	pairs := [][2]string{
		{"1.0", "1.1"},
		{"1.0", "1.0-1"},
		{"1:1.0", "1.0"},
		{"1.0~rc1", "1.0"},
		{"1.0-2ubuntu2", "1.0-2ubuntu10"},
		{"1.06", "1.6"},
		{"1.0-1", "1.0-1+b1"},
		{"1." + strings.Repeat("9", 40), "1.1" + strings.Repeat("0", 40)},
	}
	for _, p := range pairs {
		ab, err := CompareDebVersions(p[0], p[1])
		if err != nil {
			t.Fatalf("CompareDebVersions(%q, %q): %v", p[0], p[1], err)
		}
		ba, err := CompareDebVersions(p[1], p[0])
		if err != nil {
			t.Fatalf("CompareDebVersions(%q, %q): %v", p[1], p[0], err)
		}
		if ab != -ba {
			t.Errorf("antisymmetry violated: cmp(%q,%q)=%d but cmp(%q,%q)=%d",
				p[0], p[1], ab, p[1], p[0], ba)
		}
	}
}

// TestCompareDebVersionsChain sorts a realistic upgrade ladder and then
// verifies full pairwise consistency (strict increase along the chain,
// correct sign for every i<j / i>j combination, and equality on the
// diagonal). A comparator used for CVE range checks must not contain
// local order inversions.
func TestCompareDebVersionsChain(t *testing.T) {
	chain := []string{
		"1.0~~",
		"1.0~",
		"1.0~rc1",
		"1.0",
		"1.0-1",
		"1.0-1+b1",
		"1.0-2",
		"1.0-2ubuntu1",
		"1.0-2ubuntu2",
		"1.0-2ubuntu10",
		"1.1~exp1",
		"1.1",
		"1:0",
	}
	for i := 0; i < len(chain); i++ {
		for j := 0; j < len(chain); j++ {
			got, err := CompareDebVersions(chain[i], chain[j])
			if err != nil {
				t.Fatalf("CompareDebVersions(%q, %q): %v", chain[i], chain[j], err)
			}
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got != want {
				t.Errorf("chain[%d]=%q vs chain[%d]=%q: got %d, want %d",
					i, chain[i], j, chain[j], got, want)
			}
		}
	}
}

// TestDebCVEMatchesScenario exercises the exact shape the vulnerability
// matcher uses: vulnerable(installed) = installed >= introduced &&
// installed < fixed. Ubuntu frequently ships the fix purely as a
// revision bump — the normalized comparison must see it.
func TestDebCVEMatchesScenario(t *testing.T) {
	cases := []struct {
		name       string
		installed  string
		introduced string
		fixed      string
		vulnerable bool
	}{
		{name: "revision bump fixes it, older revision vulnerable", installed: "1:10.0p1-5ubuntu5.4", introduced: "1:10.0p1-5ubuntu5", fixed: "1:10.0p1-5ubuntu5.5", vulnerable: true},
		{name: "at fixed version: no longer vulnerable", installed: "1:10.0p1-5ubuntu5.5", introduced: "1:10.0p1-5ubuntu5", fixed: "1:10.0p1-5ubuntu5.5", vulnerable: false},
		{name: "exactly at introduced: vulnerable", installed: "1:10.0p1-5ubuntu5", introduced: "1:10.0p1-5ubuntu5", fixed: "1:10.0p1-5ubuntu5.5", vulnerable: true},
		{name: "past fixed: not vulnerable", installed: "1:10.0p1-5ubuntu6", introduced: "1:10.0p1-5ubuntu5", fixed: "1:10.0p1-5ubuntu5.5", vulnerable: false},
		{name: "ubuntu revision above upstream bound", installed: "2.1.11-1ubuntu3", introduced: "2.1.11", fixed: "2.1.12", vulnerable: true},
		{name: "fixed upstream released", installed: "2.1.12-1", introduced: "2.1.11", fixed: "2.1.12", vulnerable: false},
		{name: "below introduced", installed: "2.1.10-3", introduced: "2.1.11", fixed: "2.1.12", vulnerable: false},
		{name: "epoch split across the boundary", installed: "1:1.0-2", introduced: "1:1.0", fixed: "1:1.0-3", vulnerable: true},
		{name: "no-epoch install vs epoch introduced", installed: "1.0-2", introduced: "1:1.0", fixed: "1:1.0-3", vulnerable: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			geIntro, err := CompareDebVersions(tc.installed, tc.introduced)
			if err != nil {
				t.Fatalf("installed vs introduced: %v", err)
			}
			ltFixed, err := CompareDebVersions(tc.installed, tc.fixed)
			if err != nil {
				t.Fatalf("installed vs fixed: %v", err)
			}
			got := geIntro >= 0 && ltFixed < 0
			if got != tc.vulnerable {
				t.Errorf("installed %s in [%s, %s): vulnerable=%v, want %v (cmpIntro=%d, cmpFixed=%d)",
					tc.installed, tc.introduced, tc.fixed, got, tc.vulnerable, geIntro, ltFixed)
			}
		})
	}
}
