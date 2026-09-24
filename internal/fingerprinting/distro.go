// Distro segment resolution.
//
// Advisory matching needs a canonical (family, release) pair plus the
// package ecosystem the release uses — exactly what vuls' dispatch layer
// derives from /etc/os-release before choosing a scanner. Aegis assets may
// carry that info from several sources of different quality:
//
//   - endpoint agents report os_family/os_name/os_version directly
//   - the network scanner writes best-effort strings ("Ubuntu 22.04",
//     "Debian GNU/Linux 12 (bookworm)", "Alpine Linux 3.18")
//
// DistroOf returns the canonical segment when the asset carries enough
// signal, and ok=false when it does not — callers must never guess a distro
// (uncertain evidence must never be presented as fact). Matching an
// advisory against the wrong release would produce false findings, so the
// resolver is deliberately strict about the release component.
package fingerprinting

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Canonical distro families. These keys are the advisory data plane's
// family values (os_advisories.family) — new feed sources must use them.
const (
	DistroDebian   = "debian"
	DistroUbuntu   = "ubuntu"
	DistroAlpine   = "alpine"
	DistroRHEL     = "rhel"
	DistroRocky    = "rocky"
	DistroAlma     = "alma"
	DistroCentOS   = "centos"
	DistroAmazon   = "amazon"
	DistroFedora   = "fedora"
	DistroSUSE     = "suse"
	DistroOpenSUSE = "opensuse"
)

// PkgEcosystem names the software-inventory ecosystem a distro's packages
// are recorded under (domain.Software.Ecosystem values).
const (
	PkgEcoDebian = "os_debian"
	PkgEcoRPM    = "os_rpm"
	PkgEcoAlpine = "os_alpine"
)

// familyAliases maps raw os-release ID values (and common scanner string
// fragments) onto canonical family keys.
var familyAliases = map[string]string{
	"debian":                   DistroDebian,
	"ubuntu":                   DistroUbuntu,
	"alpine":                   DistroAlpine,
	"rhel":                     DistroRHEL,
	"redhat":                   DistroRHEL,
	"red hat":                  DistroRHEL,
	"red hat enterprise":       DistroRHEL,
	"red hat enterprise linux": DistroRHEL,
	"rocky":                    DistroRocky,
	"rocky linux":              DistroRocky,
	"alma":                     DistroAlma,
	"almalinux":                DistroAlma,
	"alma linux":               DistroAlma,
	"centos":                   DistroCentOS,
	"amazon":                   DistroAmazon,
	"amzn":                     DistroAmazon,
	"fedora":                   DistroFedora,
	"sles":                     DistroSUSE,
	"suse":                     DistroSUSE,
	"opensuse":                 DistroOpenSUSE,
	"opensuse-leap":            DistroOpenSUSE,
	"opensuse-tumbleweed":      DistroOpenSUSE,
}

// familyPkgEcosystem maps canonical families to their package ecosystem.
var familyPkgEcosystem = map[string]string{
	DistroDebian:   PkgEcoDebian,
	DistroUbuntu:   PkgEcoDebian,
	DistroAlpine:   PkgEcoAlpine,
	DistroRHEL:     PkgEcoRPM,
	DistroRocky:    PkgEcoRPM,
	DistroAlma:     PkgEcoRPM,
	DistroCentOS:   PkgEcoRPM,
	DistroAmazon:   PkgEcoRPM,
	DistroFedora:   PkgEcoRPM,
	DistroSUSE:     PkgEcoRPM,
	DistroOpenSUSE: PkgEcoRPM,
}

// DistroSegment is the resolved advisory-matching scope for one asset.
type DistroSegment struct {
	Family  string // canonical family key (Distro*)
	Release string // release as the advisory data keys it ("12", "22.04", "9", "3.18")
	// PkgEcosystem is the software-inventory ecosystem to match against
	// (os_debian / os_rpm / os_alpine).
	PkgEcosystem string
}

// DistroOf resolves an asset's distro segment from its recorded OS fields.
//
// Precedence (highest quality first):
//  1. OSFamily already canonical (agent-reported) + OSVersion as release
//  2. OSFamily alias (e.g. "ubuntu", "rhel") + OSVersion
//  3. OSName string mining ("Ubuntu 22.04", "Debian GNU/Linux 12",
//     "Alpine Linux v3.18", "Red Hat Enterprise Linux 9.3")
//
// The release must be present and version-like; family alone is not enough
// (an advisory for ubuntu 22.04 must never match a 24.04 asset).
func DistroOf(osFamily, osName, osVersion string) (DistroSegment, bool) {
	// 1+2: an explicit family field.
	if fam := canonicalFamily(osFamily); fam != "" {
		rel := releaseKeyOf(fam, osVersion)
		if eco, ok := familyPkgEcosystem[fam]; ok && rel != "" {
			return DistroSegment{Family: fam, Release: rel, PkgEcosystem: eco}, true
		}
	}
	// 3: mine the OS name string, optionally aided by OSVersion.
	name := strings.TrimSpace(osName)
	if name == "" {
		return DistroSegment{}, false
	}
	fam, rest := familyFromName(name)
	if fam == "" {
		return DistroSegment{}, false
	}
	rel := releaseFromName(rest)
	if rel == "" {
		rel = releaseKeyOf(fam, osVersion)
	}
	rel = releaseKeyOf(fam, rel)
	if eco, ok := familyPkgEcosystem[fam]; ok && rel != "" {
		return DistroSegment{Family: fam, Release: rel, PkgEcosystem: eco}, true
	}
	return DistroSegment{}, false
}

// releaseKeyOf cleans a raw release string then projects it onto the
// family's advisory key. Empty when nothing version-like remains.
func releaseKeyOf(family, raw string) string {
	rel := normalizeRelease(raw)
	if rel == "" {
		return ""
	}
	return releaseKey(family, rel)
}

// canonicalFamily resolves a raw family field through the alias table.
func canonicalFamily(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return ""
	}
	if fam, ok := familyAliases[v]; ok {
		return fam
	}
	// Family fields sometimes carry a display name; mine it the same way.
	fam, _ := familyFromName(v)
	return fam
}

// familyFromName finds the distro family mentioned anywhere in a free-form
// OS string and returns the remainder for release mining. Longest alias
// wins so "Red Hat Enterprise Linux" beats "Red Hat". Matching is
// word-boundary aware in BOTH directions ("pfSense" must never match
// "suse", "openSUSE" must not re-match plain "suse"), and all index math
// stays in the original string (the padded search copy shifted indexes by
// one and crashed on short names - caught by e2e section 20's demo assets).
func familyFromName(name string) (family, rest string) {
	lower := " " + strings.ToLower(name) + " "
	best, bestStart := "", -1
	for alias := range familyAliases {
		if len(alias) <= len(best) {
			continue
		}
		needle := " " + alias
		for i := 0; i+len(needle) <= len(lower); i++ {
			if lower[i:i+len(needle)] != needle {
				continue
			}
			after := i + len(needle)
			if after < len(lower) {
				r, _ := utf8.DecodeRuneInString(lower[after:])
				if unicode.IsLetter(r) {
					continue // "pfsense" must not match "suse"
				}
			}
			best, bestStart = alias, i
			break
		}
	}
	if best == "" || bestStart < 0 {
		return "", name
	}
	// lower[j+1] == name[j]: the alias starts at name[bestStart].
	end := bestStart + len(best)
	if end > len(name) {
		end = len(name)
	}
	return familyAliases[best], strings.TrimSpace(name[end:])
}

// releaseFromName extracts the leading version-like token from a name
// remainder ("22.04 LTS", "GNU/Linux 12 (bookworm)", "v3.18", "9.3").
func releaseFromName(rest string) string {
	for _, tok := range strings.Fields(rest) {
		tok = strings.Trim(tok, "(),:;vV")
		if tok == "" || !strings.ContainsFunc(tok, isDigitRune) {
			continue
		}
		return normalizeRelease(tok)
	}
	return ""
}

// normalizeRelease canonicalizes a release token: lowercased, drops
// decorations ("22.04 LTS" → "22.04", "v3.18" → "3.18", "12 (bookworm)" →
// "12"). Advisory data keys releases by the plain os-release VERSION_ID, so
// the canonical form is the numeric identifier itself.
func normalizeRelease(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return ""
	}
	// Keep the leading numeric identifier ("22.04", "12", "9", "3.18").
	out := make([]rune, 0, len(v))
	started := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9' || r == '.' && started:
			out = append(out, r)
			started = true
		case !started:
			continue // skip leading decoration (v, leap, …)
		default:
			goto done
		}
	}
done:
	s := strings.Trim(string(out), ".")
	if s == "" || !strings.ContainsFunc(s, isDigitRune) {
		return ""
	}
	return s
}

// releaseKey projects a cleaned release onto the key the advisory data
// plane uses for the family. Distro feeds branch per major release
// (Debian "12", RHEL "9") or per major.minor service level (Ubuntu
// "22.04", Alpine "3.18", SLES "15.5") - the projection must match the
// feed keys exactly or lookups silently miss.
//
//	major-only:  debian, rhel, rocky, alma, centos, fedora, amazon
//	major.minor: ubuntu, alpine, suse, opensuse
func releaseKey(family, release string) string {
	comps := strings.Split(release, ".")
	take := 2
	switch family {
	case DistroDebian, DistroRHEL, DistroRocky, DistroAlma, DistroCentOS, DistroFedora, DistroAmazon:
		take = 1
	}
	if len(comps) < take {
		take = len(comps)
	}
	return strings.Join(comps[:take], ".")
}

// ParseOSRelease resolves a distro segment from /etc/os-release content
// (captured by an endpoint agent or an SSH collection run). Returns
// ok=false when the ID is unknown or VERSION_ID is missing — the release is
// mandatory (see DistroOf).
func ParseOSRelease(stdout string) (DistroSegment, bool) {
	fields := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		fields[strings.ToUpper(strings.TrimSpace(k))] = v
	}
	fam := canonicalFamily(fields["ID"])
	if fam == "" {
		return DistroSegment{}, false
	}
	rel := releaseKeyOf(fam, fields["VERSION_ID"])
	eco, ok := familyPkgEcosystem[fam]
	if !ok || rel == "" {
		return DistroSegment{}, false
	}
	return DistroSegment{Family: fam, Release: rel, PkgEcosystem: eco}, true
}
