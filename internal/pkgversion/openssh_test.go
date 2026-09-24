package pkgversion

import (
	"errors"
	"testing"
)

// The OpenSSH domain exists because CVE boundaries for OpenSSH are
// upstream releases ("affected < 10.5") while installed distro packages
// carry the same upstream release wrapped in distro packaging
// ("1:10.0p1-5ubuntu5.4"). These tests pin the structured grammar:
// parsing, hierarchical ordering and the domain routing guarantees.

func TestParseOpenSSHVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    OpenSSHVersion
		wantStr string // canonical String() form; "" = same as raw
	}{
		{name: "bare release", raw: "10.0", want: OpenSSHVersion{Major: 10, Minor: 0}},
		{name: "release with update", raw: "10.0p1", want: OpenSSHVersion{Major: 10, Minor: 0, Update: 1, HasUpdate: true}},
		{name: "update level two", raw: "10.0p2", want: OpenSSHVersion{Major: 10, Minor: 0, Update: 2, HasUpdate: true}},
		{name: "higher minor", raw: "10.5", want: OpenSSHVersion{Major: 10, Minor: 5}},
		{name: "previous generation", raw: "9.9p1", want: OpenSSHVersion{Major: 9, Minor: 9, Update: 1, HasUpdate: true}},
		{name: "explicit zero patch", raw: "10.0.0", want: OpenSSHVersion{Major: 10, Minor: 0, Patch: 0, HasPatch: true}},
		{name: "patch and update", raw: "10.0.1p3", want: OpenSSHVersion{Major: 10, Minor: 0, Patch: 1, HasPatch: true, Update: 3, HasUpdate: true}},
		{name: "user inventory upstream form", raw: "10.0p2", want: OpenSSHVersion{Major: 10, Minor: 0, Update: 2, HasUpdate: true}},
		// Single-component input parses; the canonical form renders the
		// two-component release shape OpenSSH actually uses.
		{name: "single component release", raw: "10", want: OpenSSHVersion{Major: 10}, wantStr: "10.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseOpenSSHVersion(tt.raw)
			if err != nil {
				t.Fatalf("ParseOpenSSHVersion(%q) = err %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("ParseOpenSSHVersion(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
			wantStr := tt.wantStr
			if wantStr == "" {
				wantStr = tt.raw
			}
			if got.String() != wantStr {
				t.Errorf("String() = %q, want %q", got.String(), wantStr)
			}
		})
	}
}

func TestParseOpenSSHVersionRejects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		err  error
	}{
		{name: "empty", raw: "", err: ErrEmptyOpenSSHVersion},
		// Distro packaging around the release ("1:10.0p1-5ubuntu5.4") is
		// rejected: the pN suffix scan hits "p1-5ubuntu..." first and the
		// update grammar refuses the hyphenated tail. Either way the full
		// package version must never parse here — the caller projects it
		// to the upstream part first.
		{name: "full Debian version must never parse", raw: "1:10.0p1-5ubuntu5.4", err: ErrOpenSSHUpdate},
		{name: "distro revision tail rejected", raw: "10.0p1-5ubuntu5.4", err: ErrOpenSSHUpdate},
		{name: "tilde pre-release rejected", raw: "10.0~rc1", err: ErrInvalidCharacter},
		{name: "uppercase P rejected", raw: "10.0P1", err: ErrInvalidCharacter},
		{name: "whitespace rejected", raw: "10.0p1 ", err: ErrInvalidCharacter},
		{name: "p without number", raw: "10.0p", err: ErrOpenSSHUpdate},
		{name: "p with garbage update", raw: "10.0p1x", err: ErrOpenSSHUpdate},
		{name: "four components", raw: "10.0.0.0", err: ErrOpenSSHComponent},
		{name: "empty component", raw: "10..0", err: ErrOpenSSHComponent},
		{name: "update only", raw: "p1", err: ErrOpenSSHComponent},
		{name: "component overflow", raw: "99999999999999999999.1", err: ErrOpenSSHComponent},
		{name: "update overflow", raw: "10.0p99999999999999999999", err: ErrOpenSSHUpdate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseOpenSSHVersion(tt.raw)
			if !errors.Is(err, tt.err) {
				t.Errorf("ParseOpenSSHVersion(%q) err = %v, want %v", tt.raw, err, tt.err)
			}
		})
	}
}

// TestCompareOpenSSHRelations pins every ordering relation the matching
// engine relies on, in both directions (antisymmetry).
func TestCompareOpenSSHRelations(t *testing.T) {
	less := []struct {
		a, b string
	}{
		// The CVE-boundary relations: base release decides before pN.
		{"10.0p1", "10.5"},
		{"10.0p2", "10.5"},
		{"10.1p1", "10.5"},
		{"10.4p2", "10.5"},
		// Update level inside one base release.
		{"10.0", "10.0p1"},
		{"10.0p1", "10.0p2"},
		{"10.0p2", "10.1"},
		// Cross-generation relations.
		{"9.9p1", "10.0"},
		{"9.9p2", "10.0"},
		{"9.9", "9.9p1"},
		{"10.5", "10.9"},
		{"10.5", "10.5p1"},
		{"10.5", "11.0"},
	}
	for _, c := range less {
		a, errA := ParseOpenSSHVersion(c.a)
		b, errB := ParseOpenSSHVersion(c.b)
		if errA != nil || errB != nil {
			t.Fatalf("parse %q/%q: %v/%v", c.a, c.b, errA, errB)
		}
		if got := CompareOpenSSH(a, b); got != -1 {
			t.Errorf("CompareOpenSSH(%s, %s) = %d, want -1", c.a, c.b, got)
		}
		if got := CompareOpenSSH(b, a); got != 1 {
			t.Errorf("CompareOpenSSH(%s, %s) = %d, want 1 (antisymmetry)", c.b, c.a, got)
		}
	}
	equal := [][2]string{
		{"10.5", "10.5"},
		{"10.0", "10.0.0"}, // absent patch == explicit zero patch
		{"9.9p1", "9.9p1"},
	}
	for _, c := range equal {
		a, _ := ParseOpenSSHVersion(c[0])
		b, _ := ParseOpenSSHVersion(c[1])
		if got := CompareOpenSSH(a, b); got != 0 {
			t.Errorf("CompareOpenSSH(%s, %s) = %d, want 0", c[0], c[1], got)
		}
	}
}

// TestOpenSSHRegistryWiring pins the ecosystem-registry backend: raw
// OpenSSH versions parse and compare; a full Debian package version is
// REJECTED so a distro version can never silently enter the upstream
// comparator — the caller must project it to the upstream part first.
func TestOpenSSHRegistryWiring(t *testing.T) {
	p, err := ParserFor(EcosystemOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	pv, err := p.Parse("10.0p1")
	if err != nil {
		t.Fatal(err)
	}
	if pv.Raw != "10.0p1" || pv.Upstream != "10.0p1" || pv.Epoch != 0 || pv.Revision != "" {
		t.Errorf("parser breakdown = %+v, want raw/upstream 10.0p1, no epoch/revision", pv)
	}
	if _, err := p.Parse("1:10.0p1-5ubuntu5.4"); err == nil {
		t.Error("full Debian version must not parse in the OpenSSH domain")
	}

	c, err := ComparatorFor(EcosystemOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Compare("10.0p1", "10.5"); err != nil || got != -1 {
		t.Errorf("Compare(10.0p1, 10.5) = %d, %v; want -1, nil", got, err)
	}
	if got, err := c.Compare("10.5p1", "10.5"); err != nil || got != 1 {
		t.Errorf("Compare(10.5p1, 10.5) = %d, %v; want 1, nil", got, err)
	}
	if _, err := c.Compare("1:10.0p1-5ubuntu5.4", "10.5"); err == nil {
		t.Error("comparing a Debian package version in the OpenSSH domain must error")
	}
}
