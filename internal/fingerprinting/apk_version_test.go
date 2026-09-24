package fingerprinting

import "testing"

// Canonical apk ordering vectors from the Alpine packaging documentation
// (APKBUILD pkgver grammar, apk-tools version.c): pre-release suffixes
// alpha/beta/pre/rc rank BELOW the bare version, post-release suffixes
// git/p and the -rN package revision rank ABOVE it, letters attach to the
// preceding numeric component, and leading zeros compare by zero count.
func TestApkCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.1", -1},
		{"1.9", "1.10", -1},
		{"1.2", "1.2.1", -1},
		{"1.2.3", "1.2.3", 0},
		{"1.2_alpha", "1.2", -1},
		{"1.2_alpha1", "1.2_alpha2", -1},
		{"1.2_alpha", "1.2_beta", -1},
		{"1.2_beta", "1.2_rc1", -1},
		{"1.2_rc1", "1.2", -1},
		{"1.2.3_alpha1", "1.2.3", -1},
		{"1.2", "1.2-r0", -1},
		{"1.2-r0", "1.2-r1", -1},
		{"1.2-r1", "1.2-r2", -1},
		{"1.2-r9", "1.2-r10", -1},
		{"1.2", "1.2_p1", -1},
		{"1.2", "1.2_git", -1},
		{"1.2.3_alpha1-r1", "1.2.3-r1", -1},
		{"1.0b", "1.0c", -1},
		{"0.01", "0.1", -1},
		// Canonical apk-tools corner: when token TYPES differ the
		// ordering inverts (letter token ranks below a continuing
		// numeric component), so 1.2a sorts below 1.2.1 — exactly what
		// apk-tools and go-apk-version produce.
		{"1.2a", "1.2.1", -1},
		{"1.2.13-r1", "1.2.13-r2", -1},
		{"3.18.0", "3.18.1", -1},
	}
	for _, tc := range tests {
		if got := apkCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("apkCompare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	// Antisymmetry.
	for _, tc := range tests {
		if got := apkCompare(tc.b, tc.a); got != -tc.want {
			t.Errorf("apkCompare(%q, %q) = %d, want antisymmetric %d", tc.b, tc.a, got, -tc.want)
		}
	}
}
