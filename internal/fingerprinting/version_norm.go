// version_norm.go implements ingestion-time version normalization: the
// single pass every collected version goes through before it is stored
// and matched. Collection sources (SSH dpkg/rpm/apk/pacman sweeps,
// endpoint agents, connector scanners, nmap -sV fingerprints) hand over
// raw strings of wildly different quality; CVE matching must never run
// against banner noise or grammar-invalid versions, so the pipeline
// normalizes once at the choke point and keeps the raw value verbatim
// for evidence.
//
//	"1:10.0p1-5ubuntu5.4"  (os_debian) -> normalized "1:10.0p1-5ubuntu5.4", well-formed
//	"0:1.0-1"              (os_debian) -> normalized "1.0-1"          (zero epoch dropped)
//	"OpenSSH_10.0p2 Debian 7" (cpe)    -> normalized "10.0p2"          (noise stripped)
//	"v1.2.3"               (npm)       -> normalized "1.2.3"
//	"x:1.0"                (os_rpm)    -> normalized "1.0", well-formed=false (bad epoch)
//
// Normalization never invents ordering or repairs versions: a value
// that does not parse under its grammar is flagged (WellFormed=false)
// and still compared defensively at match time (incomparable -> never
// matches). It is a data-quality gate, not a guesser.
package fingerprinting

import (
	"strings"

	"github.com/FlameInTheDark/aegis/internal/pkgversion"
)

// VersionGrammar names the ordering grammar a version is normalized
// and compared under. It is the ecosystem label resolved to one of the
// comparator families CompareTyped/CompareEcosystem dispatch to.
type VersionGrammar string

const (
	GrammarDeb     VersionGrammar = "deb"     // Debian/Ubuntu dpkg: [epoch:]upstream[-revision]
	GrammarRPM     VersionGrammar = "rpm"     // rpm: [epoch:]version[-release]
	GrammarAPK     VersionGrammar = "apk"     // Alpine apk-tools
	GrammarSemver  VersionGrammar = "semver"  // SemVer 2.0.0 (npm, go, cargo, ...)
	GrammarPython  VersionGrammar = "python"  // PEP 440 (PyPI)
	GrammarGeneric VersionGrammar = "generic" // CNA custom/unknown; natural order
)

// NormalizedVersion is the result of normalizing one observed version
// string for one ecosystem. Raw preserves the input verbatim (audit
// evidence); Normalized is the clean, canonical form CVE matching uses;
// WellFormed reports whether the cleaned value parses under the
// ecosystem grammar (false = flagged data-quality problem).
type NormalizedVersion struct {
	Raw        string         `json:"raw"`
	Normalized string         `json:"normalized"`
	WellFormed bool           `json:"well_formed"`
	Grammar    VersionGrammar `json:"grammar"`
	// Structured breakdown, filled when the value parses under the
	// Debian grammar (empty otherwise): the exact parts CVE matching
	// compares, so UIs can render the epoch/upstream/revision triple
	// without re-parsing.
	Epoch    uint64 `json:"epoch,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// GrammarFor resolves an ecosystem label ("os_debian", "Debian:12",
// "npm", "Red Hat", "cpe", ...) onto the version grammar its values
// order under. Unknown labels fall back to the generic grammar — the
// same resolution CompareEcosystem applies at match time.
func GrammarFor(ecosystem string) VersionGrammar {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	switch {
	case ecoIs(eco, "npm", "go", "golang", "crates.io", "cargo", "rubygems", "hex", "packagist", "pub", "swifturl"):
		return GrammarSemver
	case ecoIs(eco, "pypi") || ecoHasPrefix(eco, "pypi"):
		return GrammarPython
	case ecoIs(eco, "alpine", PkgEcoAlpine) || ecoHasPrefix(eco, "alpine"):
		return GrammarAPK
	case ecoIs(eco, "debian", "ubuntu", "deb", "dpkg", "linux", PkgEcoDebian) || ecoHasPrefix(eco, "debian:", "ubuntu"):
		return GrammarDeb
	case ecoIs(eco, "rpm", "fedora", "centos", "suse", "opensuse", "rocky linux", "almalinux", PkgEcoRPM) || ecoHasPrefix(eco, "red hat", "rhel", "centos", "rocky", "almalinux", "alma", "suse", "opensuse", "sles"):
		return GrammarRPM
	default:
		return GrammarGeneric
	}
}

// NormalizeObservedVersion runs the ingestion normalization pass: strip
// scanner/banner noise, then validate and canonicalize under the
// ecosystem's grammar. The zero value case (nothing version-like in
// the input) returns Normalized "" with WellFormed false — callers
// must not feed such a value into ordering decisions.
func NormalizeObservedVersion(raw, ecosystem string) NormalizedVersion {
	g := GrammarFor(ecosystem)
	nv := NormalizedVersion{Raw: raw, Grammar: g}
	clean := CleanVersion(raw)
	if clean == "" {
		return nv // nothing version-like: never pretend
	}
	nv.Normalized = clean
	switch g {
	case GrammarDeb:
		// The pkgversion Debian backend is the single source of truth:
		// strict Debian Policy parsing plus dpkg's exact ordering. A
		// parseable version canonicalizes (zero epoch dropped, structure
		// validated); anything else is flagged, never improvised.
		if pv, err := pkgversion.ParseDebVersion(clean); err == nil {
			nv.WellFormed = true
			nv.Normalized = pv.String()
			nv.Epoch, nv.Upstream, nv.Revision = pv.Epoch, pv.Upstream, pv.Revision
		}
	case GrammarRPM:
		nv.WellFormed = rpmVersionValid(clean)
	case GrammarAPK:
		nv.WellFormed = apkVersionValid(clean)
	case GrammarSemver:
		nv.WellFormed = semverVersionValid(clean)
	case GrammarPython:
		nv.WellFormed = pythonVersionValid(clean)
	default:
		// generic/custom: CleanVersion already required a digit; there is
		// no stricter shared grammar to validate against.
		nv.WellFormed = true
	}
	return nv
}

// NormalizeServiceVersion normalizes a banner-derived service version —
// the shape nmap -sV reports, where the distro package revision rides
// along after the upstream version:
//
//	"10.0p2 Ubuntu 5ubuntu5.4" -> "10.0p2-5ubuntu5.4" (deb grammar)
//	"10.0p2 Ubuntu-5ubuntu5.4" -> "10.0p2-5ubuntu5.4" (deb grammar)
//	"OpenSSH_10.0p2 Debian 7"  -> "10.0p2"            (generic fallback)
//	"9.6p1"                    -> "9.6p1"             (generic fallback)
//
// The first whitespace token carrying a digit is the version core; the
// remaining tokens are distro decoration. When the decoration names a
// distro ("Ubuntu", "Debian", ...), the residue is the distro package
// revision and is re-attached with the deb revision separator; the
// composed value is validated under the Debian grammar and
// canonicalized (structured epoch/upstream/revision filled). Anything
// that does not compose or parse falls back to the generic cpe
// behavior (NormalizeObservedVersion). The returned Grammar always
// states the grammar the Normalized form actually validates under,
// and Raw stays verbatim in every branch.
func NormalizeServiceVersion(raw string) NormalizedVersion {
	fields := strings.Fields(raw)
	if len(fields) > 1 {
		core, tail := "", ""
		for i, tok := range fields {
			if strings.ContainsFunc(tok, isDigitRune) {
				core, tail = tok, strings.Join(fields[i+1:], "-")
				break
			}
		}
		if core != "" {
			// Banner-style product_version core ("OpenSSH_10.0p2"):
			// same rule as CleanVersion — the version lives after the
			// last underscore when the prefix is non-numeric.
			if i := strings.LastIndexByte(core, '_'); i > 0 {
				head, t := core[:i], core[i+1:]
				if strings.ContainsFunc(head, isAlphaRune) && t != "" && isDigitRune(rune(t[0])) {
					core = t
				}
			}
			if tail = stripDistroDecoration(tail); tail != "" {
				if pv, err := pkgversion.ParseDebVersion(core + "-" + tail); err == nil {
					return NormalizedVersion{
						Raw: raw, Normalized: pv.String(), WellFormed: true,
						Grammar: GrammarDeb, Epoch: pv.Epoch, Upstream: pv.Upstream, Revision: pv.Revision,
					}
				}
			}
		}
	}
	return NormalizeObservedVersion(raw, "cpe")
}

// stripDistroDecoration removes a leading distro name (and further
// decoration words like "linux") from a banner version tail:
// "Ubuntu-5ubuntu5.4" -> "5ubuntu5.4", "Debian-7" -> "7". The names
// carry no ordering meaning; the residue is the distro package
// revision. A tail that is already a pure revision ("5ubuntu5.4")
// passes through unchanged — it never starts with a distro name.
func stripDistroDecoration(tail string) string {
	for {
		tail = strings.TrimLeft(tail, "-_. ")
		if tail == "" {
			return ""
		}
		lower := strings.ToLower(tail)
		cut := ""
		for _, d := range []string{"ubuntu", "debian", "linux", "rhel", "redhat", "centos",
			"almalinux", "rocky", "fedora", "opensuse", "suse", "alpine", "mint", "kali", "amzn", "oracle"} {
			if strings.HasPrefix(lower, d) {
				cut = tail[:len(d)]
				break
			}
		}
		if cut == "" {
			return tail
		}
		tail = tail[len(cut):]
	}
}

// rpmVersionValid reports whether v is a well-formed rpm version under
// [epoch:]version[-release]: the epoch, when present, is all digits and
// version/release are non-empty and start alphanumeric. Punctuation
// inside ("1.0-1.fc40", "2:3.1.2-1.el9") stays allowed — rpmvercmp
// ignores separators when ordering.
func rpmVersionValid(v string) bool {
	rest := v
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch := v[:i]
		if epoch == "" {
			return false // "":1.0" — colon with an empty epoch
		}
		for j := 0; j < len(epoch); j++ {
			if !isDigitByte(epoch[j]) {
				return false // non-numeric epoch has no rpm meaning
			}
		}
		rest = v[i+1:]
	}
	if rest == "" {
		return false
	}
	ver, rel, _ := strings.Cut(rest, "-")
	if !startsWithAlnum(ver) {
		return false
	}
	return rel == "" || startsWithAlnum(rel)
}

func startsWithAlnum(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return isDigitByte(c) || isAlphaByte(c)
}

// apkVersionValid reports whether v is a well-formed apk-tools version
// ("number{.number}...{letter}{_suffix{number}}...{-rN}"): it must
// start with a number and its token walk must reach the end without
// hitting an invalid token (the same walk apkCompare performs on both
// sides before ordering).
func apkVersionValid(v string) bool {
	if v == "" || !isDigitByte(v[0]) {
		return false // apk versions start with a number
	}
	r := newApkReader(v)
	t := apkTokDigit           // the initial token state apkCompare starts from
	for i := 0; i < 512; i++ { // hard bound: every step consumes input
		_, nt := r.apkGetToken(t)
		switch nt {
		case apkTokInvalid:
			return false
		case apkTokEnd:
			return true
		}
		t = nt
	}
	return false
}

// semverVersionValid reports whether v looks like a SemVer 2.0.0
// version: numeric dot-separated core, optional -prerelease and
// the spec (single/double component cores like "1.2" are accepted —
// real-world npm inventories carry them and compare fine).
func semverVersionValid(v string) bool {
	core, rest, _ := strings.Cut(v, "+")
	core, pre, _ := strings.Cut(core, "-")
	if pre != "" && !semverIdentOK(pre) {
		return false
	}
	if core == "" || !isDigitByte(core[0]) {
		return false
	}
	for _, part := range strings.Split(core, ".") {
		if part == "" || !allDigits(part) {
			return false
		}
	}
	return rest == "" || semverIdentOK(rest)
}

func semverIdentOK(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigitByte(c) && !isAlphaByte(c) && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigitByte(s[i]) {
			return false
		}
	}
	return true
}

// pythonVersionValid reports whether v is shape-valid PEP 440: an
// optional "N!" epoch, then a release starting with a digit. The
// ordering comparator (pythonCompare) tolerates the rest of the
// alphabet soup pragmatically; validity here means "has a numeric
// release the release comparison can anchor on".
func pythonVersionValid(v string) bool {
	rest := v
	if i := strings.IndexByte(v, '!'); i >= 0 {
		if i == 0 || !allDigits(v[:i]) {
			return false
		}
		rest = v[i+1:]
	}
	return rest != "" && isDigitByte(rest[0])
}
