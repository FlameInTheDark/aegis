package domain

import "strings"

// VersionDomain names the comparison grammar a version verdict is made
// in. A CVE boundary and an installed package version frequently live
// in DIFFERENT domains: the installed Ubuntu package reports
// "1:10.0p1-5ubuntu5.4" (Debian grammar: epoch 1, upstream "10.0p1",
// revision "5ubuntu5.4") while the CVE for the same product speaks
// upstream releases ("affected < 10.5"). Ordering one with the other's
// comparator silently lies — the epoch makes every upstream bound sort
// older (every vulnerability hidden), and raw-string or SemVer
// comparison mangles both grammars. Every version decision therefore
// names the domain it was made in.
type VersionDomain string

const (
	// DomainDebian is full Debian/Ubuntu package ordering
	// ([epoch:]upstream[-revision], dpkg's verrevcmp).
	DomainDebian VersionDomain = "debian"
	// DomainRPM is full rpm package ordering ([epoch:]version[-release]).
	DomainRPM VersionDomain = "rpm"
	// DomainAPK is full Alpine apk-tools package ordering.
	DomainAPK VersionDomain = "apk"
	// DomainOpenSSH is structured Portable OpenSSH release ordering:
	// major, then minor, then patch, then — only for equal base
	// releases — the pN portable-update level:
	//
	//	10.0 < 10.0p1 < 10.0p2 < 10.1   (update level inside one base)
	//	10.0p1 < 10.5                   (base release 10.0 < 10.5)
	//	10.5 < 10.5p1 < 10.6 < 11.0
	DomainOpenSSH VersionDomain = "openssh"
	// DomainUpstream is dpkg upstream ordering applied to projected
	// upstream components (epoch/revision stripped): the general
	// fallback for upstream-only feed bounds that are not OpenSSH
	// releases — OpenSSL-style letter patch levels ("1.0.2k") and
	// tilde pre-releases ("2.0~rc1").
	DomainUpstream VersionDomain = "upstream"
	// DomainSemVer is SemVer 2.0.0 (npm, go, cargo, ...).
	DomainSemVer VersionDomain = "semver"
	// DomainPython is PEP 440 (PyPI).
	DomainPython VersionDomain = "python"
	// DomainGeneric is unknown/custom version schemes with
	// natural-order comparison.
	DomainGeneric VersionDomain = "generic"
)

// VersionDomainForType maps a CVE List v5 / NVD versionType label onto
// its comparison domain. "maven" has its own ordering that the platform
// approximates with the generic natural-order comparator, so it — like
// every unknown label — maps to DomainGeneric.
func VersionDomainForType(versionType string) VersionDomain {
	switch strings.ToLower(strings.TrimSpace(versionType)) {
	case "deb", "dpkg":
		return DomainDebian
	case "rpm":
		return DomainRPM
	case "apk", "alpine":
		return DomainAPK
	case "openssh":
		return DomainOpenSSH
	case "semver":
		return DomainSemVer
	case "python", "pep440":
		return DomainPython
	default:
		return DomainGeneric
	}
}

// VersionConstraint is a domain-tagged version applicability statement:
// the machine-readable form of "this product is affected in this version
// window, compared under this grammar":
//
//	OpenSSH CVE:          {Domain: openssh, LessThan: "10.5"}
//	Ubuntu OVAL advisory: {Domain: debian,  Fixed: "1:10.0p1-5ubuntu5.5"}
//	npm advisory:         {Domain: semver,  Introduced: "1.0.0", Fixed: "1.2.3"}
//
// The fields mirror the OSV event model (introduced / fixed /
// last_affected) plus the two NVD/CPE upper bounds (LessThan =
// versionEndExcl, LessThanOrEqual = versionEndIncl). The CPE-only
// versionStartExcl has no OSV-shaped slot here and is evaluated by the
// matcher as a separate exclusive greater-than bound. Bound semantics,
// all evaluated in Domain:
//
//	Introduced       installed >= Introduced       (range start, inclusive)
//	Fixed            installed <  Fixed            (first version without the flaw)
//	LessThan         installed <  LessThan         (NVD spelling of Fixed)
//	LessThanOrEqual  installed <= LessThanOrEqual  (last affected version)
type VersionConstraint struct {
	Domain          VersionDomain `json:"domain,omitempty"`
	Introduced      string        `json:"introduced,omitempty"`
	Fixed           string        `json:"fixed,omitempty"`
	LessThan        string        `json:"less_than,omitempty"`
	LessThanOrEqual string        `json:"less_than_or_equal,omitempty"`
}

// Constraint materializes an OSV version range as a domain-tagged
// constraint. The domain is supplied by the caller: it is resolved from
// the advisory's ecosystem label, which lives next to the range rather
// than inside it. OSV's "0" introduced event (affected since the
// beginning) carries no orderable bound and is dropped, matching the
// matcher's handling.
func (r VersionRange) Constraint(d VersionDomain) VersionConstraint {
	c := VersionConstraint{Domain: d}
	for _, e := range r.Events {
		if e.Introduced != "" && e.Introduced != "0" {
			c.Introduced = e.Introduced
		}
		if e.Fixed != "" {
			c.Fixed = e.Fixed
		}
		if e.LastAffected != "" {
			c.LessThanOrEqual = e.LastAffected
		}
	}
	return c
}

// Constraint materializes a CPE/NVD range match as a domain-tagged
// constraint: versionStartIncl maps to Introduced, versionEndExcl to
// LessThan and versionEndIncl to LessThanOrEqual, and the declared
// versionType resolves the comparison domain. versionStartExcl has no
// slot in this OSV-shaped struct; the matcher evaluates it as a separate
// exclusive greater-than bound. CPE ranges carry no fixed-version
// concept, so Fixed stays empty.
func (cm CPEMatch) Constraint() VersionConstraint {
	return VersionConstraint{
		Domain:          VersionDomainForType(cm.VersionType),
		Introduced:      cm.VersionStartIncl,
		LessThan:        cm.VersionEndExcl,
		LessThanOrEqual: cm.VersionEndIncl,
	}
}
