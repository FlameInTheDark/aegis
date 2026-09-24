// Package pkgversion normalizes operating-system package versions into a
// structured representation that vulnerability matching can rely on.
//
// Installed software arrives from many package managers (dpkg, rpm, apk,
// pacman) whose version grammars and ordering rules differ fundamentally.
// A Debian version orders "1.0~rc1" before "1.0" while naive string,
// dotted-numeric or SemVer comparisons all get that backwards; Ubuntu
// security fixes frequently change only the Debian revision
// ("1:10.0p1-5ubuntu5.4" vs "1:10.0p1-5ubuntu5.5") even though the
// upstream version is identical. Comparing versions with the wrong
// grammar silently produces wrong vulnerability verdicts, so each
// ecosystem needs its own parse and ordering rules — behind one shared
// abstraction.
//
// This package provides:
//
//   - PackageVersion: the ecosystem-independent normalized form — the
//     raw input preserved verbatim plus structured epoch, upstream and
//     revision components;
//   - ParseDebVersion: a strict Debian-policy parser with explicit
//     validation errors (empty input, malformed epoch, invalid
//     characters, stray colons);
//   - CompareDebVersions / CompareDebParsed: dpkg-faithful ordering
//     ("1.0~rc1" < "1.0" < "1.0-1" < "1.0-1+b1" < "1.0-2ubuntu2" <
//     "1.0-2ubuntu10"), ported from dpkg's verrevcmp and free of integer
//     overflow even for absurdly long numeric components, because digit
//     runs are compared as strings exactly the way dpkg compares them;
//   - VersionParser and VersionComparator interfaces plus an ecosystem
//     registry, so the rest of the scanner depends on the abstraction
//     and rpm / apk / pacman / semver backends can be added later
//     without touching a single call site.
//
// The implementation is pure Go, deterministic and allocation-light: no
// shelling out to dpkg/rpm (the scanner must work inside containers
// where those tools may not exist), no third-party dependencies, no
// regular expressions on the hot path. It is built for security
// scanners doing millions of comparisons: parse a feed constraint or an
// installed version once, then compare the parsed forms repeatedly via
// CompareDebParsed.
//
// Vulnerability-matching usage:
//
//	parser, err := pkgversion.ParserFor(pkgversion.EcosystemDeb)
//	installed, err := parser.Parse("1:10.0p1-5ubuntu5.4")
//
//	cmp, err := pkgversion.CompareDebVersions(installed.Raw, fixedIn)
//	vulnerable := cmp < 0 // installed < fixed
//
// Range checks ("installed >= introduced && installed < fixed") are
// just comparisons against both bounds; revision information is never
// normalized away, so revision-only security fixes compare correctly.
package pkgversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// PackageVersion is the ecosystem-independent normalized form of a
// package version. The exact original string is always preserved in Raw;
// the structured fields are the backend's best-effort decomposition.
//
// For Debian-style versions the fields map 1:1 onto
// [epoch:]upstream[-revision]:
//
//	"1:10.0p1-5ubuntu5.4" -> Epoch 1, Upstream "10.0p1", Revision "5ubuntu5.4"
//	"1.83ubuntu2"         -> Epoch 0, Upstream "1.83ubuntu2", Revision ""
//
// Note that "ubuntu2" is part of the upstream version there: the Debian
// revision separator is a hyphen, and no revision exists without one.
type PackageVersion struct {
	// Raw is the input string exactly as received, byte for byte.
	Raw string
	// Epoch is the optional leading epoch ("2:1.0"), zero when absent.
	Epoch uint64
	// Upstream is the main upstream version component ("10.0p1").
	Upstream string
	// Revision is the optional trailing Debian/Ubuntu revision
	// ("5ubuntu5.4"), empty when the version carries no hyphen.
	Revision string
}

// String renders the canonical "[epoch:]upstream[-revision]" form. A
// zero epoch is omitted, so "0:1.0" canonicalizes to "1.0". Raw always
// preserves the original input verbatim; String is for logs and reports.
func (v PackageVersion) String() string {
	var b strings.Builder
	if v.Epoch > 0 {
		b.WriteString(strconv.FormatUint(v.Epoch, 10))
		b.WriteByte(':')
	}
	b.WriteString(v.Upstream)
	if v.Revision != "" {
		b.WriteByte('-')
		b.WriteString(v.Revision)
	}
	return b.String()
}

// Ecosystem names a package version grammar. The values mirror the
// package-manager families the scanner collects from; each gets its own
// parser/comparator backend registered below.
type Ecosystem string

const (
	// EcosystemDeb is the Debian/Ubuntu dpkg grammar:
	// [epoch:]upstream[-revision] with dpkg ordering.
	EcosystemDeb Ecosystem = "deb"
	// EcosystemRPM is the rpm grammar: [epoch:]version[-release] with
	// rpmvercmp ordering. Backend pending migration from fingerprinting.
	EcosystemRPM Ecosystem = "rpm"
	// EcosystemAPK is the Alpine apk-tools grammar. Backend pending
	// migration from fingerprinting.
	EcosystemAPK Ecosystem = "apk"
	// EcosystemPacman is the Arch Linux pacman grammar (vercmp). Backend
	// pending.
	EcosystemPacman Ecosystem = "pacman"
	// EcosystemSemver is Semantic Versioning 2.0.0 for language-package
	// inventories. Backend pending migration from fingerprinting.
	EcosystemSemver Ecosystem = "semver"
)

// ErrUnsupportedEcosystem is returned by ParserFor/ComparatorFor when no
// backend has been registered for the requested ecosystem.
var ErrUnsupportedEcosystem = errors.New("pkgversion: unsupported ecosystem")

// VersionParser parses a raw version string of one ecosystem into the
// normalized PackageVersion form. Implementations must validate strictly
// and return descriptive errors wrapping the Err* sentinels — a security
// scanner must surface data-quality problems, never guess.
type VersionParser interface {
	Parse(version string) (PackageVersion, error)
}

// VersionComparator orders two raw version strings of one ecosystem:
// -1 when a < b, 0 when a == b, 1 when a > b. Parsing and comparison are
// deliberately kept separate: hot paths parse once and compare the
// parsed forms.
type VersionComparator interface {
	Compare(a, b string) (int, error)
}

// Registry of per-ecosystem backends. init-time registration is the
// norm; Register* is exported so consumers (and tests) can extend or
// replace backends without editing this package. Later registrations
// win.
var (
	registryMu    sync.RWMutex
	parserReg     = map[Ecosystem]VersionParser{}
	comparatorReg = map[Ecosystem]VersionComparator{}
)

// RegisterParser installs a parser backend for an ecosystem, replacing
// any previous registration.
func RegisterParser(e Ecosystem, p VersionParser) {
	registryMu.Lock()
	defer registryMu.Unlock()
	parserReg[e] = p
}

// RegisterComparator installs a comparator backend for an ecosystem,
// replacing any previous registration.
func RegisterComparator(e Ecosystem, c VersionComparator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	comparatorReg[e] = c
}

// ParserFor returns the parser backend registered for the ecosystem.
func ParserFor(e Ecosystem) (VersionParser, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := parserReg[e]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEcosystem, e)
	}
	return p, nil
}

// ComparatorFor returns the comparator backend registered for the
// ecosystem.
func ComparatorFor(e Ecosystem) (VersionComparator, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	c, ok := comparatorReg[e]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEcosystem, e)
	}
	return c, nil
}
