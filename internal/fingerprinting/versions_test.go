package fingerprinting

import "testing"

// TestCompareTypedUserCase pins the exact scenario from the field report:
// a CVE says OpenSSH is affected below 10.4 (versionType "custom",
// version "0", lessThan "10.4"); the scanner observed "10.0p2 Debian 7".
// The observed version must parse clean and compare as less-than.
func TestCompareTypedUserCase(t *testing.T) {
	observed := CleanVersion("10.0p2 Debian 7")
	if observed != "10.0p2" {
		t.Fatalf("CleanVersion(10.0p2 Debian 7) = %q, want 10.0p2", observed)
	}
	if got := CompareTyped(observed, "10.4", "custom"); got != -1 {
		t.Fatalf("CompareTyped(10.0p2, 10.4, custom) = %d, want -1 (vulnerable)", got)
	}
	// And the fixed release must NOT match the range.
	if got := CompareTyped("10.4", "10.4", "custom"); got != 0 {
		t.Fatalf("CompareTyped(10.4, 10.4) = %d, want 0", got)
	}
	if got := CompareTyped("10.4p1 Debian 3", "10.4", "custom"); got != 1 {
		t.Fatalf("CompareTyped(10.4p1, 10.4) = %d, want 1 (not vulnerable)", got)
	}
}

func TestCleanVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0p2 Debian 7", "10.0p2"},
		{"9.6p1 Ubuntu 3", "9.6p1"},
		{"1.2.3 (Debian)", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{"Ver. 4.2", "4.2"},
		{"version 2.0", "2.0"},
		{" 9.6p1 ", "9.6p1"},
		{"1:7.4p1-5", "1:7.4p1-5"},
		{"2.0.0+deb12u1", "2.0.0+deb12u1"},
		{"10.4", "10.4"},
		{"2024.01.15", "2024.01.15"},
		{"1.2.3-4ubuntu1 amd64", "1.2.3-4ubuntu1"},
		{"OpenSSH_10.0p2", "10.0p2"}, // first digit-bearing token wins
		{"", ""},
		{"unknown", ""},
		{"tcpwrapped", ""},
	}
	for _, tc := range cases {
		if got := CleanVersion(tc.in); got != tc.want {
			t.Errorf("CleanVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCompareTypedCustom(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"9.9p1", "10.4", -1},
		{"10.0p2", "10.4", -1},
		{"10.3p1", "10.4", -1},
		{"10.4", "10.4", 0},
		{"10.4p1", "10.4", 1},
		{"10.5", "10.4", 1},
		{"1.0.2k", "1.0.2", 1},   // OpenSSL patch letter sorts after base
		{"1.0.2k", "1.0.2l", -1}, // letters order lexically
		{"1.0.2k", "1.0.3", -1},
		{"2.0rc1", "2.0", -1}, // pre-release word sorts before final
		{"2.0beta2", "2.0", -1},
		{"2.0", "2.0.0", 0}, // trailing zeros equal
		{"2.0.0.0", "2.0", 0},
		{"1.2.3-4ubuntu1", "1.2.3", 1}, // distro revision after upstream
		{"1.2.3-1", "1.2.3-1ubuntu1", -1},
		{"1.10", "1.9", 1}, // numeric, not lexical
		{"10.0p2", "10.0p1", 1},
		{"10.0p2", "10.0p10", -1}, // numeric patch level
		{"0", "0", 0},
		{"1.0.0", "0", 1},
		{"2024.01.15", "2024.01.14", 1},
		{"8.2.1", "8.2", 1},
		{"v1.2", "1.2.0", 0},
	}
	for _, tc := range cases {
		if got := CompareTyped(tc.a, tc.b, "custom"); got != tc.want {
			t.Errorf("CompareTyped(%q,%q,custom) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareTypedSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.10", "1.2.9", 1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, // numeric identifiers < alphanumeric
		{"1.0.0+build5", "1.0.0", 0},   // build metadata ignored
		{"v2.0.0", "2.0.0", 0},
	}
	for _, tc := range cases {
		if got := CompareTyped(tc.a, tc.b, "semver"); got != tc.want {
			t.Errorf("CompareTyped(%q,%q,semver) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareTypedDeb(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"1.0", "1.0-1", -1}, // no revision < any revision
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0~rc1", "1.0", -1},
		{"2:1.0", "1:9.9", 1}, // epoch dominates
		{"1:7.4p1-5", "1:7.4p1-4", 1},
		{"7.4p1-5+deb12u1", "7.4p1-5", 1},
		{"1.2.3", "1.10", -1},
	}
	for _, tc := range cases {
		if got := CompareTyped(tc.a, tc.b, "deb"); got != tc.want {
			t.Errorf("CompareTyped(%q,%q,deb) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareTypedRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-2", "1.0-1", 1},
		{"1.0", "1.0-1", -1},
		{"2.25.1-1", "2.25.1-1.el9", -1}, // shorter release sorts first
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "0:9.9", 1},
		{"1.19.5-3", "1.19.5-10", -1},
		{"2-1", "10-1", -1}, // numeric not lexical
	}
	for _, tc := range cases {
		if got := CompareTyped(tc.a, tc.b, "rpm"); got != tc.want {
			t.Errorf("CompareTyped(%q,%q,rpm) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareTypedPython(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.dev1", "1.0a1", -1},
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.9", "1.10", -1},
		{"2!1.0", "1!9.0", 1},
	}
	for _, tc := range cases {
		if got := CompareTyped(tc.a, tc.b, "python"); got != tc.want {
			t.Errorf("CompareTyped(%q,%q,python) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareTypedIncomparable(t *testing.T) {
	// No digits on either side: incomparable, callers must not match.
	if got := CompareTyped("unknown", "1.0", "custom"); got != 2 {
		t.Errorf("CompareTyped(unknown,1.0) = %d, want 2", got)
	}
	if got := CompareTyped("abc", "def", "custom"); got != 2 {
		t.Errorf("CompareTyped(abc,def) = %d, want 2", got)
	}
	if got := CompareTyped("", "", "custom"); got != 0 {
		t.Errorf("CompareTyped(empty,empty) = %d, want 0", got)
	}
}

func TestCompareEcosystem(t *testing.T) {
	if got := CompareEcosystem("1.0.0-rc.1", "1.0.0", "npm"); got != -1 {
		t.Errorf("npm prerelease: got %d, want -1", got)
	}
	if got := CompareEcosystem("1.0~rc1", "1.0", "Debian"); got != -1 {
		t.Errorf("Debian tilde: got %d, want -1", got)
	}
	if got := CompareEcosystem("1.0rc1", "1.0", "PyPI"); got != -1 {
		t.Errorf("PyPI rc: got %d, want -1", got)
	}
}
