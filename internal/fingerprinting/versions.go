// versions.go implements version-aware comparison for CVE applicability
// (spec §32/§33). CVE List v5 "affected" entries carry a versionType
// (custom, semver, rpm, deb, python, maven, generic, …) and observed
// versions come from scanners/banners ("10.0p2 Debian 7"), so matching
// needs more than dotted-numeric equality:
//
//   - observed junk is stripped first ("10.0p2 Debian 7" -> "10.0p2")
//   - each versionType gets its own ordering rules
//   - the custom ordering understands patch letters (1.0.2k), OpenSSH
//     patch levels (10.0p2), and pre-release words (2.0rc1 < 2.0)
//
// The result is never guessed: a pair without any ordering signal is
// reported incomparable and callers must not match it.
package fingerprinting

import (
	"strconv"
	"strings"
)

// versionType constants mirror the versionType values used by CVE List v5
// affected.versions entries (and the practical synonyms seen in the wild).
const (
	VersionTypeCustom  = "custom"
	VersionTypeSemver  = "semver"
	VersionTypeRPM     = "rpm"
	VersionTypeDeb     = "deb"
	VersionTypePython  = "python"
	VersionTypeMaven   = "maven"
	VersionTypeGeneric = "generic"
)

// CompareTyped compares two version strings under versionType ordering.
// Returns -1 (a < b), 0 (a == b), 1 (a > b), or 2 (incomparable — no
// ordering signal; callers must not pretend one).
func CompareTyped(a, b, versionType string) int {
	if a == b {
		return 0 // identical raw strings (including both empty)
	}
	a, b = CleanVersion(a), CleanVersion(b)
	if a == "" || b == "" {
		return 2 // nothing version-like on one side: incomparable
	}
	switch strings.ToLower(strings.TrimSpace(versionType)) {
	case VersionTypeSemver:
		return semverCompare(a, b)
	case VersionTypeDeb, "dpkg":
		return debCompare(a, b)
	case VersionTypeRPM:
		return rpmCompare(a, b)
	case VersionTypePython, "pep440":
		return pythonCompare(a, b)
	default:
		// custom, generic, maven, unknown schemes — the natural-order
		// comparator handles all of them acceptably.
		return customCompare(a, b)
	}
}

// CompareEcosystem compares two package versions using the OSV ecosystem
// name ("npm", "PyPI", "Debian", "Alpine v3.x", "Red Hat", …) to pick
// ordering rules. Used by the OSV package path.
func CompareEcosystem(a, b, ecosystem string) int {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "go", "golang", "crates.io", "cargo", "rubygems", "hex", "packagist", "pub", "swifturl":
		return semverCompare(CleanVersion(a), CleanVersion(b))
	case "pypi":
		return pythonCompare(CleanVersion(a), CleanVersion(b))
	case "debian", "ubuntu", "alpine", "deb", "linux":
		return debCompare(CleanVersion(a), CleanVersion(b))
	case "rpm", "red hat", "fedora", "centos", "suse", "opensuse", "rocky linux", "almalinux":
		return rpmCompare(CleanVersion(a), CleanVersion(b))
	default:
		return customCompare(CleanVersion(a), CleanVersion(b))
	}
}

// CleanVersion normalizes an observed version string: it drops
// scanner/environment noise around the version itself.
//
//	"10.0p2 Debian 7" -> "10.0p2"        "v1.2.3"        -> "1.2.3"
//	"1.2.3 (Debian)"  -> "1.2.3"         " 9.6p1 "       -> "9.6p1"
//	"1:7.4p1-5"       -> "1:7.4p1-5"     "2.0.0+deb12u1" -> "2.0.0+deb12u1"
//
// The rule: pick the first whitespace-separated token that contains a
// digit (versions always carry digits; decoration rarely does), strip a
// leading "v"/"ver." prefix and surrounding punctuation. Returns "" when
// nothing version-like remains.
func CleanVersion(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	// First whitespace token that carries a digit is the version proper.
	for _, tok := range strings.Fields(v) {
		if strings.ContainsFunc(tok, isDigitRune) {
			v = tok
			break
		}
	}
	v = strings.Trim(v, "()[]{}\"',;")
	// Banner-style "product_version" ("OpenSSH_10.0p2"): the version lives
	// after the last underscore when the prefix is non-numeric. Underscores
	// never occur inside deb/rpm version grammar, so this is safe.
	if i := strings.LastIndexByte(v, '_'); i > 0 {
		head, tail := v[:i], v[i+1:]
		if strings.ContainsFunc(head, isAlphaRune) && tail != "" && isDigitRune(rune(tail[0])) {
			v = tail
		}
	}
	// Strip a v/ver/version prefix when a digit follows ("v1.2.3").
	lower := strings.ToLower(v)
	for _, p := range []string{"version", "ver.", "ver", "v"} {
		if strings.HasPrefix(lower, p) && len(v) > len(p) {
			rest := v[len(p):]
			if rest[0] >= '0' && rest[0] <= '9' {
				v = rest
			}
			break
		}
	}
	v = strings.Trim(v, "()[]{}\"',;")
	if !strings.ContainsFunc(v, isDigitRune) {
		return "" // not a version — never pretend (§33)
	}
	return v
}

func isDigitRune(r rune) bool { return r >= '0' && r <= '9' }
func isAlphaRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }
func isAlphaByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ---------------------------------------------------------------------------
// custom ordering (versionType "custom"/"generic"/"maven"/unknown)
// ---------------------------------------------------------------------------

// vToken is one version component: a run of digits or a run of letters.
type vToken struct {
	num   int
	alpha string
	isNum bool
}

// prereleaseWords sort BEFORE the plain release at the same position
// ("2.0rc1" < "2.0"). Deliberately word-level only: OpenSSL/OpenSSH-style
// single letters ("1.0.2k", "10.0p2") are patch levels that sort AFTER
// the base release and must never be treated as pre-releases.
var prereleaseWords = map[string]bool{
	"alpha": true, "beta": true, "rc": true, "pre": true, "preview": true,
	"dev": true, "snapshot": true, "nightly": true, "trunk": true,
	"milestone": true, "ea": true, "draft": true,
}

// tokenizeVersion splits a version into digit/letter runs. Separators
// (., -, _, +, /, :, ~) act as boundaries. "10.0p2" -> [10, 0, "p", 2].
func tokenizeVersion(s string) []vToken {
	var out []vToken
	s = strings.ToLower(s)
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isDigitByte(c):
			j := i
			for j < len(s) && isDigitByte(s[j]) {
				j++
			}
			n, _ := strconv.Atoi(s[i:j])
			out = append(out, vToken{num: n, isNum: true})
			i = j
		case isAlphaByte(c):
			j := i
			for j < len(s) && isAlphaByte(s[j]) {
				j++
			}
			out = append(out, vToken{alpha: s[i:j]})
			i = j
		default: // separators and noise
			i++
		}
	}
	return out
}

// tailAllZero reports whether the extra tail of a version adds nothing
// numeric ("2.0" vs "2.0.0" are equal).
func tailAllZero(ts []vToken) bool {
	for _, t := range ts {
		if !t.isNum || t.num != 0 {
			return false
		}
	}
	return true
}

func firstIsPrerelease(ts []vToken) bool {
	return len(ts) > 0 && !ts[0].isNum && prereleaseWords[ts[0].alpha]
}

// customCompare orders versions the way most CNA "custom" schemes behave:
// numeric runs compare numerically, letter runs lexically, and an extra
// tail sorts after the base release unless it is a pre-release word
// ("10.4p1" > "10.4", "2.0rc1" < "2.0", "2.0" == "2.0.0").
func customCompare(a, b string) int {
	ta, tb := tokenizeVersion(a), tokenizeVersion(b)
	n := len(ta)
	if len(tb) < n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		xa, xb := ta[i], tb[i]
		switch {
		case xa.isNum && xb.isNum:
			if xa.num != xb.num {
				return cmpInt(xa.num, xb.num)
			}
		case !xa.isNum && !xb.isNum:
			if xa.alpha != xb.alpha {
				return cmpStrings(xa.alpha, xb.alpha)
			}
		case xa.isNum:
			// Numeric slot beats a letter at the same position; a
			// pre-release letter would lose to the final release anyway.
			return 1
		default:
			return -1
		}
	}
	// Equal prefix: the longer tail decides.
	switch {
	case len(ta) == len(tb):
		return 0
	case len(ta) > len(tb):
		tail := ta[len(tb):]
		if tailAllZero(tail) {
			return 0
		}
		if firstIsPrerelease(tail) {
			return -1
		}
		return 1
	default:
		tail := tb[len(ta):]
		if tailAllZero(tail) {
			return 0
		}
		if firstIsPrerelease(tail) {
			return 1
		}
		return -1
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// semver (semantic versioning 2.0.0)
// ---------------------------------------------------------------------------

func semverCompare(a, b string) int {
	ca, pa := splitSemver(a)
	cb, pb := splitSemver(b)
	if r := compareNumericDots(ca, cb); r != 0 {
		return r
	}
	// Pre-release: absent > present (1.0.0 > 1.0.0-rc.1).
	if pa == "" && pb == "" {
		return 0
	}
	if pa == "" {
		return 1
	}
	if pb == "" {
		return -1
	}
	ida, idb := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(ida) || i < len(idb); i++ {
		var x, y string
		if i < len(ida) {
			x = ida[i]
		}
		if i < len(idb) {
			y = idb[i]
		}
		if x == y {
			continue
		}
		if x == "" {
			return -1 // shorter prerelease list sorts first
		}
		if y == "" {
			return 1
		}
		xn, xe := strconv.Atoi(x)
		yn, ye := strconv.Atoi(y)
		switch {
		case xe == nil && ye == nil:
			if xn != yn {
				return cmpInt(xn, yn)
			}
		case xe == nil:
			return -1 // numeric identifiers < alphanumeric
		case ye == nil:
			return 1
		default:
			return cmpStrings(x, y)
		}
	}
	return 0
}

// splitSemver separates "1.2.3-rc.1+build" into ("1.2.3", "rc.1"); build
// metadata is ignored per semver §10.
func splitSemver(v string) (string, string) {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// compareNumericDots compares dot-separated numeric cores ("1.2.3").
// Returns 2 when either side has no leading digit (garbage).
func compareNumericDots(a, b string) int {
	pa, pb := VersionParts(a), VersionParts(b)
	if len(pa) == 0 || len(pb) == 0 {
		if a == b {
			return 0
		}
		return 2
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return cmpInt(x, y)
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// dpkg (deb) ordering: [epoch:]upstream[-revision], '~' sorts first
// ---------------------------------------------------------------------------

func debCompare(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if r := cmpInt(ea, eb); r != 0 {
		return r
	}
	ua, va := splitDebRevision(ra)
	ub, vb := splitDebRevision(rb)
	if r := debFragment(ua, ub); r != 0 {
		return r
	}
	return debFragment(va, vb)
}

// splitEpoch handles the shared "[N:]..." epoch syntax of deb/rpm.
func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(strings.TrimSpace(v[:i])); err == nil {
			return e, v[i+1:]
		}
	}
	return 0, v
}

func splitDebRevision(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// debChar is the dpkg character weight: '~' < end-of-string < alphanumerics
// < punctuation. Digits never reach here (the outer loop splits them off).
func debChar(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0: // end-of-string sentinel
		return 0
	case isAlphaByte(c) || isDigitByte(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

// debFragment implements the dpkg comparison algorithm verbatim: compare
// non-digit runs by character weight, then digit runs numerically.
func debFragment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit prefixes first.
		for (i < len(a) && !isDigitByte(a[i])) || (j < len(b) && !isDigitByte(b[j])) {
			ca, cb := 0, 0
			if i < len(a) {
				ca = debChar(a[i])
			}
			if j < len(b) {
				cb = debChar(b[j])
			}
			if ca != cb {
				return cmpInt(ca, cb)
			}
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}
		if i >= len(a) && j >= len(b) {
			return 0
		}
		// Digit runs compare numerically (missing run = 0).
		if (i < len(a) && isDigitByte(a[i])) || (j < len(b) && isDigitByte(b[j])) {
			ni, nj := i, j
			for ni < len(a) && isDigitByte(a[ni]) {
				ni++
			}
			for nj < len(b) && isDigitByte(b[nj]) {
				nj++
			}
			xa, xb := 0, 0
			if ni > i {
				xa, _ = strconv.Atoi(a[i:ni])
			}
			if nj > j {
				xb, _ = strconv.Atoi(b[j:nj])
			}
			if xa != xb {
				return cmpInt(xa, xb)
			}
			i, j = ni, nj
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// rpm ordering: [epoch:]version[-release], rpmvercmp with '~' support
// ---------------------------------------------------------------------------

func rpmCompare(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if r := cmpInt(ea, eb); r != 0 {
		return r
	}
	// '~' pre-release marker: "1.0~rc1" < "1.0" (same convention as deb).
	ta, taTilde := cutTilde(ra)
	tb, tbTilde := cutTilde(rb)
	if r := rpmVerCmp(ta, tb); r != 0 {
		return r
	}
	switch {
	case taTilde && tbTilde:
		return 0
	case taTilde:
		return -1
	case tbTilde:
		return 1
	}
	return 0
}

func cutTilde(v string) (string, bool) {
	if i := strings.IndexByte(v, '~'); i >= 0 {
		return v[:i], true
	}
	return v, false
}

// rpmVerCmp is the classic rpmvercmp: alternating alpha/numeric segments,
// numeric segments compare numerically and always beat alpha at the same
// position, longer segment list wins on equal prefix, punctuation ignored.
func rpmVerCmp(a, b string) int {
	segs := func(s string) []string {
		var out []string
		for i := 0; i < len(s); {
			c := s[i]
			j := i
			switch {
			case isDigitByte(c):
				for j < len(s) && isDigitByte(s[j]) {
					j++
				}
			case isAlphaByte(c):
				for j < len(s) && isAlphaByte(s[j]) {
					j++
				}
			default:
				i++
				continue
			}
			out = append(out, s[i:j])
			i = j
		}
		return out
	}
	sa, sb := segs(a), segs(b)
	n := len(sa)
	if len(sb) < n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		x, y := sa[i], sb[i]
		xd, yd := isDigitByte(x[0]), isDigitByte(y[0])
		switch {
		case xd && yd:
			xn, _ := strconv.ParseInt(strings.TrimLeft(x, "0"), 10, 64)
			yn, _ := strconv.ParseInt(strings.TrimLeft(y, "0"), 10, 64)
			if xn != yn {
				return cmpInt64(xn, yn)
			}
		case xd && !yd:
			return 1 // numeric segments are newer than alpha
		case !xd && yd:
			return -1
		default:
			if x != y {
				return cmpStrings(x, y)
			}
		}
	}
	switch {
	case len(sa) == len(sb):
		return 0
	case len(sa) > len(sb):
		return 1
	default:
		return -1
	}
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// python (PEP 440, pragmatic subset)
// ---------------------------------------------------------------------------

// pythonCompare orders the PEP 440 shapes that appear in vulnerability
// feeds: "1.0.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1".
func pythonCompare(a, b string) int {
	pa, pb := parsePEP440(a), parsePEP440(b)
	if pa.epoch != pb.epoch {
		return cmpInt(pa.epoch, pb.epoch)
	}
	if r := compareNumericDots(dots(pa.release), dots(pb.release)); r != 0 {
		return r
	}
	if pa.rank() != pb.rank() {
		return cmpInt(pa.rank(), pb.rank())
	}
	return cmpInt(pa.phaseNum, pb.phaseNum)
}

func dots(ns []int) string {
	strs := make([]string, len(ns))
	for i, n := range ns {
		strs[i] = strconv.Itoa(n)
	}
	return strings.Join(strs, ".")
}

type pep440 struct {
	epoch    int
	release  []int
	phase    string // dev|alpha|beta|rc|final|post
	phaseNum int
}

func (p pep440) rank() int {
	switch p.phase {
	case "dev":
		return 0
	case "alpha":
		return 1
	case "beta":
		return 2
	case "rc":
		return 3
	case "post":
		return 5
	default:
		return 4 // final
	}
}

// parsePEP440 walks digit/letter tokens: the leading numeric run is the
// release, the first recognized letter word sets the phase.
func parsePEP440(v string) pep440 {
	out := pep440{phase: "final"}
	if i := strings.IndexByte(v, '!'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			out.epoch = e
		}
		v = v[i+1:]
	}
	toks := tokenizeVersion(v)
	i := 0
	for ; i < len(toks) && toks[i].isNum; i++ {
		out.release = append(out.release, toks[i].num)
	}
	if i < len(toks) && !toks[i].isNum {
		word := toks[i].alpha
		next := 0
		if i+1 < len(toks) && toks[i+1].isNum {
			next = toks[i+1].num
		}
		switch {
		case word == "dev":
			out.phase, out.phaseNum = "dev", next
		case word == "a":
			out.phase, out.phaseNum = "alpha", next
		case word == "b":
			out.phase, out.phaseNum = "beta", next
		case word == "rc" || word == "pre" || word == "preview" || word == "c" || word == "sp":
			out.phase, out.phaseNum = "rc", next
		case word == "post" || word == "rev" || word == "r":
			out.phase, out.phaseNum = "post", next
		default:
			// Unknown letter suffix ("1.0pl1", "1.0u1"): patch level — ranks
			// like a post-release of the same version.
			out.phase, out.phaseNum = "post", next
		}
	}
	return out
}
