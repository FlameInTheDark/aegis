// OpenSSH upstream version backend: structured parsing and hierarchical
// comparison of Portable OpenSSH release versions.
//
// OpenSSH release versions have the form
//
//	<release>[p<update>]        e.g. "9.9p2", "10.0p1", "10.5"
//
// where the release is a two- (rarely three-) component dotted number and
// the "pN" suffix is the portable-release update level. NVD's CPE data
// confirms that "pN" is an explicit update component (OpenSSH 9.9 p1 is
// stored as version "9.9", update "p1"), not an arbitrary string tail.
//
// The reason this domain exists: CVE boundaries for OpenSSH are upstream
// release versions ("affected < 10.5") while installed distro packages
// carry Debian/rpm packaging around that same upstream release
// ("1:10.0p1-5ubuntu5.4" — epoch 1, upstream "10.0p1", revision
// "5ubuntu5.4"). Deciding "is 10.0p1 below 10.5" must run on structured
// upstream data:
//
//	10.0p1  ->  Major 10, Minor 0, Update 1
//	10.5    ->  Major 10, Minor 5
//	10 == 10, 0 < 5   =>   10.0p1 < 10.5
//
// and never on raw strings, generic SemVer, or a comparator that lets the
// distro epoch participate (epoch 1 would declare every upstream bound
// "older" and silently hide every vulnerability). The pN update level
// stays meaningful for equal base releases:
//
//	10.0 < 10.0p1 < 10.0p2 < 10.1
//
// This is NOT Debian ordering and must never see a full distro package
// version — the caller projects the installed package to its upstream
// component first (see fingerprinting.ComparePackageBound, which routes
// upstream-only CVE bounds into this domain and keeps distro-format
// bounds such as OVAL fixed-ins in the Debian domain).
package pkgversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// EcosystemOpenSSH names the Portable OpenSSH upstream release grammar in
// the ecosystem registry. It is an UPSTREAM grammar: feeds compare in it,
// installed distro versions must be projected to their upstream part
// before entering it.
const EcosystemOpenSSH Ecosystem = "openssh"

// Sentinel parse errors for the OpenSSH grammar. Test with errors.Is.
var (
	// ErrEmptyOpenSSHVersion is returned for an empty version string.
	ErrEmptyOpenSSHVersion = errors.New("empty openssh version")
	// ErrOpenSSHComponent is returned when a dotted release component is
	// empty, not purely numeric, or exceeds uint64.
	ErrOpenSSHComponent = errors.New("invalid openssh release component")
	// ErrOpenSSHUpdate is returned when the trailing update suffix is
	// malformed ("10.0p", "10.0p1x") — it must be exactly 'p' + digits.
	ErrOpenSSHUpdate = errors.New("invalid openssh update suffix")
)

// OpenSSHVersion is the structured form of a Portable OpenSSH release
// version. HasPatch/HasUpdate distinguish "component absent" from "zero":
// "10.0" has no patch component and no update, "10.0.0" has an explicit
// zero patch, "10.0p1" has update level 1. Absent components compare as
// zero for the release, and ABSENT for the update level (the update level
// is ordinal: a release with no pN sorts before any pN of the same
// release, because "10.0" < "10.0p1" — pN builds postdate the plain
// release).
type OpenSSHVersion struct {
	Major     uint64 `json:"major"`
	Minor     uint64 `json:"minor"`
	Patch     uint64 `json:"patch,omitempty"`
	HasPatch  bool   `json:"has_patch,omitempty"`
	Update    uint64 `json:"update,omitempty"`
	HasUpdate bool   `json:"has_update,omitempty"`
}

// String renders the canonical "major.minor[.patch][pN]" form.
func (v OpenSSHVersion) String() string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(v.Major, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(v.Minor, 10))
	if v.HasPatch {
		b.WriteByte('.')
		b.WriteString(strconv.FormatUint(v.Patch, 10))
	}
	if v.HasUpdate {
		b.WriteByte('p')
		b.WriteString(strconv.FormatUint(v.Update, 10))
	}
	return b.String()
}

// OpenSSHParser is the VersionParser backend for upstream OpenSSH
// versions. PackageVersion.Upstream carries the release ("10.0p1"), the
// Debian-style Revision stays empty, and Epoch is always 0 — OpenSSH has
// no epoch concept.
type OpenSSHParser struct{}

// Parse implements VersionParser.
func (OpenSSHParser) Parse(version string) (PackageVersion, error) {
	ov, err := ParseOpenSSHVersion(version)
	if err != nil {
		return PackageVersion{Raw: version}, err
	}
	return PackageVersion{Raw: version, Upstream: ov.String()}, nil
}

// OpenSSHComparator is the VersionComparator backend for upstream
// OpenSSH versions.
type OpenSSHComparator struct{}

// Compare implements VersionComparator.
func (OpenSSHComparator) Compare(a, b string) (int, error) {
	return CompareOpenSSHRaw(a, b)
}

func init() {
	RegisterParser(EcosystemOpenSSH, OpenSSHParser{})
	RegisterComparator(EcosystemOpenSSH, OpenSSHComparator{})
}

// ParseOpenSSHVersion parses a Portable OpenSSH release version
// "<release>[p<update>]" into its structured form. The release is one to
// three dot-separated purely numeric components (two in every real
// release to date: "10.0"; three accepted for safety); the optional
// update suffix is exactly a lowercase 'p' followed by digits, only at
// the very end of the string. Whitespace, uppercase 'P', hyphens, tildes
// and any other decoration are rejected — values shaped like distro
// package versions ("10.0p1-5ubuntu5.4") do NOT parse here, which is
// what keeps the domain routing honest: a full Debian version must be
// projected to its upstream part before it enters this comparator.
func ParseOpenSSHVersion(raw string) (OpenSSHVersion, error) {
	var v OpenSSHVersion
	if raw == "" {
		return v, fmt.Errorf("openssh version: %w", ErrEmptyOpenSSHVersion)
	}
	if i := strings.IndexFunc(raw, isASCIISpace); i >= 0 {
		return v, fmt.Errorf("openssh version %q: %w: whitespace at offset %d", raw, ErrInvalidCharacter, i)
	}

	base := raw
	if i := strings.LastIndexByte(raw, 'p'); i >= 0 {
		suffix := raw[i+1:]
		if suffix == "" {
			return v, fmt.Errorf("openssh version %q: %w: 'p' with no update number", raw, ErrOpenSSHUpdate)
		}
		for j := 0; j < len(suffix); j++ {
			if !isDebDigit(suffix[j]) {
				return v, fmt.Errorf("openssh version %q: %w: %q in update number", raw, ErrOpenSSHUpdate, string(suffix[j]))
			}
		}
		up, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil {
			return v, fmt.Errorf("openssh version %q: %w: update %q out of 64-bit unsigned range", raw, ErrOpenSSHUpdate, suffix)
		}
		v.Update, v.HasUpdate = up, true
		base = raw[:i]
	}

	// The base release may only contain digits and dots.
	for i := 0; i < len(base); i++ {
		if base[i] != '.' && !isDebDigit(base[i]) {
			return v, fmt.Errorf("openssh version %q: %w: %q at offset %d", raw, ErrInvalidCharacter, string(base[i]), i)
		}
	}
	parts := strings.Split(base, ".")
	if len(parts) > 3 {
		return v, fmt.Errorf("openssh version %q: %w: %d release components (max 3)", raw, ErrOpenSSHComponent, len(parts))
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return v, fmt.Errorf("openssh version %q: %w: empty component %d", raw, ErrOpenSSHComponent, i+1)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("openssh version %q: %w: component %d (%q) not a 64-bit unsigned number", raw, ErrOpenSSHComponent, i+1, p)
		}
		nums[i] = n
	}
	v.Major = nums[0]
	if len(nums) > 1 {
		v.Minor = nums[1]
	}
	if len(nums) > 2 {
		v.Patch, v.HasPatch = nums[2], true
	}
	return v, nil
}

// CompareOpenSSH orders two structured OpenSSH versions: Major, then
// Minor, then Patch (an absent patch component compares as zero, so
// "10.0" == "10.0.0"), and only for equal base releases the update
// level, where no update sorts before any update ("10.0" < "10.0p1" <
// "10.0p2").
func CompareOpenSSH(a, b OpenSSHVersion) int {
	if c := cmpU64(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpU64(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpU64(a.Patch, b.Patch); c != 0 {
		return c
	}
	switch {
	case a.HasUpdate && b.HasUpdate:
		return cmpU64(a.Update, b.Update)
	case a.HasUpdate:
		return 1 // "10.5p1" > "10.5"
	case b.HasUpdate:
		return -1 // "10.5" < "10.5p1"
	}
	return 0
}

// CompareOpenSSHRaw orders two OpenSSH version strings; both must parse.
func CompareOpenSSHRaw(a, b string) (int, error) {
	pa, err := ParseOpenSSHVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := ParseOpenSSHVersion(b)
	if err != nil {
		return 0, err
	}
	return CompareOpenSSH(pa, pb), nil
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
