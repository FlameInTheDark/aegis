// Debian package version backend: strict parsing per Debian Policy 5.6.12
// and ordering ported verbatim from dpkg's verrevcmp. No dpkg binary, no
// third-party modules, no integer overflow.
package pkgversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Sentinel parse errors. Callers should test with errors.Is so the
// detailed, input-quoting messages stay free to evolve.
var (
	// ErrEmptyVersion is returned for an empty version string.
	ErrEmptyVersion = errors.New("empty version string")
	// ErrInvalidEpoch is returned when the text before ':' is not a
	// plain non-negative decimal integer or exceeds uint64.
	ErrInvalidEpoch = errors.New("invalid epoch")
	// ErrInvalidCharacter is returned for bytes outside the Debian
	// version alphabet [0-9A-Za-z.+-:~], including any whitespace.
	ErrInvalidCharacter = errors.New("invalid character")
	// ErrEmptyUpstream is returned when the upstream part is missing
	// ("1:", "-1").
	ErrEmptyUpstream = errors.New("empty upstream version")
	// ErrEmptyRevision is returned when a hyphen is present but nothing
	// follows it ("1.0-").
	ErrEmptyRevision = errors.New("empty debian revision")
)

// DebParser is the VersionParser backend for Debian/Ubuntu dpkg versions.
type DebParser struct{}

// Parse implements VersionParser.
func (DebParser) Parse(version string) (PackageVersion, error) {
	return ParseDebVersion(version)
}

// DebComparator is the VersionComparator backend for Debian/Ubuntu dpkg
// versions.
type DebComparator struct{}

// Compare implements VersionComparator.
func (DebComparator) Compare(a, b string) (int, error) {
	return CompareDebVersions(a, b)
}

func init() {
	RegisterParser(EcosystemDeb, DebParser{})
	RegisterComparator(EcosystemDeb, DebComparator{})
}

// ParseDebVersion parses a Debian package version
// "[epoch:]upstream[-revision]" into the normalized form, validating
// strictly:
//
//   - the epoch (text before the first ':') must be a non-empty decimal
//     integer fitting uint64 — "a:1.0", ":1.0" and 65-bit epochs are
//     rejected with ErrInvalidEpoch;
//   - the Debian revision is everything after the LAST hyphen, so
//     upstream parts may contain hyphens ("1.0-alpha-1"); a trailing bare
//     hyphen ("1.0-") is ErrEmptyRevision;
//   - only [0-9A-Za-z.+-:~] may appear at all; any whitespace (including
//     leading/trailing, a common data-quality defect in feeds) or other
//     byte is ErrInvalidCharacter with the offending offset;
//   - a ':' anywhere other than the epoch separator is ErrInvalidCharacter
//     ("1:2:3", "1.0-2:3") — the epoch separator is unique and the
//     revision grammar has no colons;
//   - the upstream part must be non-empty ("1:", "-1" are rejected).
//
// The upstream part is NOT required to start with a digit (Debian Policy
// says "should", and dpkg does not enforce it either). Epochs with
// leading zeros ("007:1.0") parse like dpkg's strtoul: as 7.
//
// "1.83ubuntu2" stays a single upstream component: the revision separator
// is a hyphen, and Ubuntu appends distro patches either as
// "-<rev>ubuntu<N>" or directly inside the upstream string.
func ParseDebVersion(raw string) (PackageVersion, error) {
	v := PackageVersion{Raw: raw}
	if raw == "" {
		return v, fmt.Errorf("deb version: %w", ErrEmptyVersion)
	}
	// Whitespace gets its own message: it is the most common data-quality
	// defect in feed data and is trivially fixable by the caller.
	if i := strings.IndexFunc(raw, isASCIISpace); i >= 0 {
		return v, fmt.Errorf("deb version %q: %w: whitespace at offset %d (trim the input)",
			raw, ErrInvalidCharacter, i)
	}
	// Full alphabet check up front, so every later structural rule can
	// assume clean bytes and errors can name the exact offset.
	for i := 0; i < len(raw); i++ {
		if !isDebVersionByte(raw[i]) {
			return v, fmt.Errorf("deb version %q: %w: %q at offset %d",
				raw, ErrInvalidCharacter, string(raw[i]), i)
		}
	}

	// Split the Debian revision at the LAST hyphen.
	rest := raw
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		rev := rest[i+1:]
		if rev == "" {
			return v, fmt.Errorf("deb version %q: %w (hyphen with nothing after it)", raw, ErrEmptyRevision)
		}
		v.Revision = rev
		rest = rest[:i]
	}

	// Parse the epoch: text before the FIRST ':' must be a plain
	// non-negative decimal integer. upstreamStart tracks where the
	// upstream part begins inside raw, for precise error offsets.
	epochFound := false
	upstreamStart := 0
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		epochPart := rest[:i]
		if epochPart == "" {
			return v, fmt.Errorf("deb version %q: %w: empty epoch before ':'", raw, ErrInvalidEpoch)
		}
		epoch, err := strconv.ParseUint(epochPart, 10, 64)
		if err != nil {
			detail := "not a decimal number"
			if errors.Is(err, strconv.ErrRange) {
				detail = "out of 64-bit unsigned range"
			}
			return v, fmt.Errorf("deb version %q: %w: %q is %s", raw, ErrInvalidEpoch, epochPart, detail)
		}
		v.Epoch = epoch
		epochFound = true
		upstreamStart = i + 1
		rest = rest[i+1:]
	}

	if rest == "" {
		if epochFound {
			return v, fmt.Errorf("deb version %q: %w: nothing after epoch ':'", raw, ErrEmptyUpstream)
		}
		return v, fmt.Errorf("deb version %q: %w: nothing before the '-'", raw, ErrEmptyUpstream)
	}
	// A ':' outside the epoch is garbage: the epoch separator is unique
	// and the revision grammar has no colons at all.
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return v, fmt.Errorf("deb version %q: %w: ':' at offset %d (epoch separator is unique)",
			raw, ErrInvalidCharacter, upstreamStart+i)
	}
	if i := strings.IndexByte(v.Revision, ':'); i >= 0 {
		return v, fmt.Errorf("deb version %q: %w: ':' at offset %d (revisions carry no colons)",
			raw, ErrInvalidCharacter, len(raw)-len(v.Revision)+i)
	}
	v.Upstream = rest
	return v, nil
}

// CompareDebVersions orders two Debian version strings: -1 when a < b,
// 0 when a == b, 1 when a > b. Both sides are parsed first; a parse
// error on either side is returned (with the sentinel wrapped) rather
// than guessed around. For hot paths, parse once and use CompareDebParsed.
func CompareDebVersions(a, b string) (int, error) {
	pa, err := ParseDebVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := ParseDebVersion(b)
	if err != nil {
		return 0, err
	}
	return CompareDebParsed(pa, pb), nil
}

// CompareDebParsed orders two already-parsed Debian versions. This is
// the allocation-free hot path: parse each side once, compare many
// times. Epoch dominates, then the upstream version, then the revision —
// each of the latter two under dpkg's exact fragment algorithm.
func CompareDebParsed(a, b PackageVersion) int {
	if a.Epoch != b.Epoch {
		if a.Epoch < b.Epoch {
			return -1
		}
		return 1
	}
	if c := debVerRevCmp(a.Upstream, b.Upstream); c != 0 {
		return c
	}
	return debVerRevCmp(a.Revision, b.Revision)
}

// isASCIISpace reports whether r is an ASCII whitespace rune.
func isASCIISpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// isDebVersionByte reports whether c may appear in a Debian version at
// all. Structural rules (single epoch colon, revision split) are applied
// on top of this alphabet.
func isDebVersionByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	}
	switch c {
	case '.', '+', '-', ':', '~':
		return true
	}
	return false
}

func isDebDigit(c byte) bool { return c >= '0' && c <= '9' }

// debOrder is dpkg's order(): the weight of one byte during the
// non-digit comparison phase.
//
//	'~'         -> -1  (sorts before everything, even the end of string)
//	end-of-part ->  0  (the implicit trailing NUL in dpkg's C loops)
//	digits      ->  0  (digit runs are compared numerically, never here)
//	letters     ->  their ASCII value (letters sort before punctuation)
//	punctuation ->  ASCII value + 256 (sorts after all letters)
func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// debOrderAt is debOrder of the byte at s[i], with dpkg's end-of-string
// NUL semantics for i >= len(s).
func debOrderAt(s string, i int) int {
	if i >= len(s) {
		return debOrder(0)
	}
	return debOrder(s[i])
}

// debVerRevCmp is a faithful port of dpkg's verrevcmp (documented in
// Debian Policy 5.6.12): the strings are walked in lockstep,
// alternating between
//
//  1. a non-digit phase where each byte's weight (debOrder) decides,
//     including dpkg's subtlety that a digit on one side weighs 0 —
//     so digits sort after '~' and end-of-string but before letters
//     and punctuation, and
//  2. a numeric phase where leading zeros are stripped and digit runs
//     compare numerically: a run that still has digits left after the
//     other ran out is the larger number ("2ubuntu10" > "2ubuntu2"),
//     otherwise the first differing digit decides.
//
// Digit runs are never converted to integers, so numeric components of
// any length compare correctly without overflow, exactly like dpkg.
func debVerRevCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		// Non-digit phase: lockstep while either side sits on a
		// non-digit byte.
		for (i < len(a) && !isDebDigit(a[i])) || (j < len(b) && !isDebDigit(b[j])) {
			ac := debOrderAt(a, i)
			bc := debOrderAt(b, j)
			if ac != bc {
				return signInt(ac - bc)
			}
			i++
			j++
		}

		// Numeric phase: strip leading zeros, then walk both digit runs.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDebDigit(a[i]) && isDebDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		// A run that still has digits left is the longer (larger) number.
		if i < len(a) && isDebDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDebDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return signInt(firstDiff)
		}
	}
	return 0
}

func signInt(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
