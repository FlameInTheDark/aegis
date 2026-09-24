// version_domain.go implements domain-aware comparison of an installed
// OS package version against a vulnerability-feed version bound.
//
// A CVE boundary and an installed distro package version live in
// DIFFERENT comparison domains, and judging one with the other's
// comparator produces silent, systematic lies:
//
//	installed Ubuntu package:  1:10.0p1-5ubuntu5.4   (epoch 1, upstream "10.0p1", revision "5ubuntu5.4")
//	OpenSSH CVE boundary:      10.5                  (upstream release, NVD/CVE List v5)
//
// Full Debian ordering answers "1:10.0p1-5ubuntu5.4 > 10.5" because the
// epoch (1) dominates — every CVE bound without an epoch would sort
// below every epoch-carrying package and EVERY vulnerability would be
// hidden. The reverse error is just as real: feeding the raw package
// string into a generic comparator mangles the grammar.
//
// The routing rules, per bound:
//
//   - A DISTRO-FORMAT bound (Debian epoch or revision present — Ubuntu
//     OVAL fixed-ins "1:10.0p1-5ubuntu5.5", OSV Debian ranges
//     "3.0.2-0ubuntu1.16", rpm releases "8.0p1-6.el8") compares FULLY
//     under the distro grammar. Distro revision-only security uploads
//     must stay distinguishable; this is where they are.
//
//   - An UPSTREAM-ONLY bound ("10.5", "3.0.5" — no epoch, no distro
//     revision) is compared against the installed version's UPSTREAM
//     component: the epoch and distro revision are packaging artifacts
//     the CVE boundary must never see. When both upstream parts parse
//     as structured OpenSSH releases, the verdict is made in the
//     OpenSSH domain (10.0p1 < 10.5 because 10.0 < 10.5, and
//     10.0p1 < 10.0p2 because the base releases are equal and 1 < 2).
//     Everything else orders the projected upstream parts with dpkg's
//     upstream algorithm, which handles '~' pre-releases, letter patch
//     levels ("1.0.2k") and arbitrarily long numeric runs correctly.
//
// Incomparable inputs return Compare 2 — callers must never guess
// (package-wide "never pretend" rule).
package fingerprinting

import (
	"strconv"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/pkgversion"
)

// VersionDomain names the comparison domain a version verdict was made
// in. The canonical type and values live in internal/domain so feed
// records, match evidence and UI share one vocabulary; this alias keeps
// the fingerprinting call sites readable.
type VersionDomain = domain.VersionDomain

const (
	// DomainDebian: full Debian/Ubuntu package ordering
	// ([epoch:]upstream[-revision], dpkg's verrevcmp).
	DomainDebian = domain.DomainDebian
	// DomainRPM: full rpm package ordering ([epoch:]version[-release]).
	DomainRPM = domain.DomainRPM
	// DomainAPK: full Alpine apk-tools package ordering.
	DomainAPK = domain.DomainAPK
	// DomainOpenSSH: structured Portable OpenSSH release ordering
	// (major.minor[.patch] then the pN update level) — used for
	// upstream-only CVE bounds against OpenSSH-shaped upstream parts.
	DomainOpenSSH = domain.DomainOpenSSH
	// DomainUpstream: dpkg ordering applied to projected upstream
	// components (epoch/revision stripped) — the general fallback for
	// upstream-only bounds.
	DomainUpstream = domain.DomainUpstream
	// DomainSemver: SemVer 2.0.0 (npm, go, cargo, …).
	DomainSemver = domain.DomainSemVer
	// DomainPython: PEP 440 (PyPI).
	DomainPython = domain.DomainPython
	// DomainGeneric: unknown/custom scheme, natural-order comparison.
	DomainGeneric = domain.DomainGeneric
)

// DomainForEcosystem resolves a package/ecosystem label ("os_debian",
// "Debian:12", "Ubuntu:25.10", "npm", ...) onto the VersionDomain its
// versions order under — the match-time counterpart of GrammarFor.
func DomainForEcosystem(ecosystem string) VersionDomain {
	return domainOfGrammar(GrammarFor(ecosystem))
}

// BoundVerdict is the outcome of one installed-vs-bound comparison.
type BoundVerdict struct {
	// Compare is -1 (installed < bound), 0 (equal), 1 (installed > bound)
	// or 2 (incomparable — no trustworthy ordering; never guess).
	Compare int
	// Domain names the comparator that produced the verdict.
	Domain VersionDomain
	// Projected is the installed-side value actually compared when the
	// package version was projected to its upstream component
	// ("10.0p1" from "1:10.0p1-5ubuntu5.4"); empty when the full package
	// value was compared as-is. Evidence carries it so the projection is
	// auditable.
	Projected string
}

// ComparePackageBound compares an installed package version against a
// feed version bound (OSV range event, CPE range end, distro advisory
// fixed-in), resolving the comparison domain per the routing rules in
// this file's header. The grammar is resolved from the installed
// package's ecosystem label (GrammarFor).
func ComparePackageBound(installed, bound, pkgEcosystem string) BoundVerdict {
	return compareBound(installed, bound, GrammarFor(pkgEcosystem))
}

// compareBound is ComparePackageBound over an explicit grammar (CPE
// ranges declare their versionType directly).
func compareBound(installed, bound string, g VersionGrammar) BoundVerdict {
	installed, bound = CleanVersion(installed), CleanVersion(bound)
	if installed == "" || bound == "" {
		return BoundVerdict{Compare: 2, Domain: domainOfGrammar(g)}
	}
	switch g {
	case GrammarDeb:
		return compareDebBound(installed, bound)
	case GrammarRPM:
		return compareRPMBound(installed, bound)
	case GrammarAPK:
		return compareAPKBound(installed, bound)
	default:
		// Language-package grammars share one ordering per ecosystem; no
		// projection applies (no epoch/revision packaging layer).
		return BoundVerdict{CompareEcosystem(installed, bound, string(g)), domainOfGrammar(g), ""}
	}
}

func domainOfGrammar(g VersionGrammar) VersionDomain {
	switch g {
	case GrammarDeb:
		return DomainDebian
	case GrammarRPM:
		return DomainRPM
	case GrammarAPK:
		return DomainAPK
	case GrammarSemver:
		return DomainSemver
	case GrammarPython:
		return DomainPython
	default:
		return DomainGeneric
	}
}

// grammarForVersionType maps a CPE match's declared versionType back
// onto the grammar its bounds order under; the generic grammar marks
// the custom/generic/unknown labels the CPE path handles specially.
func grammarForVersionType(versionType string) VersionGrammar {
	switch domain.VersionDomainForType(versionType) {
	case DomainDebian:
		return GrammarDeb
	case DomainRPM:
		return GrammarRPM
	case DomainAPK:
		return GrammarAPK
	case DomainSemver:
		return GrammarSemver
	case DomainPython:
		return GrammarPython
	default:
		return GrammarGeneric
	}
}

// CompareCPEBound compares an observed product version against a
// CVE/NVD version bound under a CPE match's declared versionType.
// Distro versionTypes (deb/rpm/apk) route through the package-bound
// rules: a distro-format bound orders fully, an upstream-only bound is
// projected to the installed version's upstream component. The
// custom/generic/unknown labels — what NVD declares for OpenSSH — make
// the verdict in the structured OpenSSH domain when both sides are
// OpenSSH releases ("affected < 10.5" against an observed "10.0p2"), or
// in the generic natural-order domain otherwise. Semver/python bounds
// order under their own grammars. The returned BoundVerdict names the
// domain the verdict was made in and the projected upstream part when
// one was used.
func CompareCPEBound(installed, bound, versionType string) BoundVerdict {
	g := grammarForVersionType(versionType)
	if g == GrammarGeneric {
		installed, bound = CleanVersion(installed), CleanVersion(bound)
		if installed == "" || bound == "" {
			return BoundVerdict{Compare: 2, Domain: DomainGeneric}
		}
		return compareCustomBound(installed, bound)
	}
	return compareBound(installed, bound, g)
}

// compareCustomBound decides a custom/generic versionType bound. When
// the bound is a structured OpenSSH release ("10.5"), the installed
// side is projected to its upstream OpenSSH release — directly
// ("10.0p2") or out of a distro-packaged form ("10.0p2-5ubuntu5.4",
// the banner-normalized shape services carry) — and the verdict is made
// in the OpenSSH domain. Every other pair orders with the generic
// natural-order comparator (pre-release words, patch letters, ...).
func compareCustomBound(installed, bound string) BoundVerdict {
	if b, errB := pkgversion.ParseOpenSSHVersion(bound); errB == nil {
		if a, errA := pkgversion.ParseOpenSSHVersion(installed); errA == nil {
			return BoundVerdict{pkgversion.CompareOpenSSH(a, b), DomainOpenSSH, ""}
		}
		if pv, err := pkgversion.ParseDebVersion(installed); err == nil {
			if a, err := pkgversion.ParseOpenSSHVersion(pv.Upstream); err == nil {
				return BoundVerdict{pkgversion.CompareOpenSSH(a, b), DomainOpenSSH, pv.Upstream}
			}
		}
	}
	return BoundVerdict{customCompare(installed, bound), DomainGeneric, ""}
}

// compareDebBound routes one Debian package version against one bound.
func compareDebBound(installed, bound string) BoundVerdict {
	pv, err := pkgversion.ParseDebVersion(installed)
	if err != nil {
		return BoundVerdict{Compare: 2, Domain: DomainDebian} // malformed installed: never judge
	}
	bv, err := pkgversion.ParseDebVersion(bound)
	if err != nil {
		return BoundVerdict{Compare: 2, Domain: DomainDebian}
	}
	if bv.Epoch > 0 || bv.Revision != "" {
		// Distro-format bound: full Debian ordering, revisions decisive.
		return BoundVerdict{pkgversion.CompareDebParsed(pv, bv), DomainDebian, ""}
	}
	// Upstream-only bound ("10.5"): the epoch and distro revision of the
	// installed package are packaging artifacts the CVE bound must not
	// see. A zero-epoch prefix ("0:1.0") is packaging decoration too.
	return compareUpstreamBound(pv.Upstream, bv.Upstream)
}

// compareRPMBound routes one rpm package version against one bound. rpm
// mirrors the Debian shape ([epoch:]version[-release]); upstream-only
// bounds project to the rpm version component (epoch and release
// stripped).
func compareRPMBound(installed, bound string) BoundVerdict {
	iv, _ := rpmEpoch(installed)
	bv, bhadEpoch := rpmEpoch(bound)
	if bhadEpoch || strings.Contains(bv, "-") {
		// Distro-format bound (release and/or epoch): full rpm ordering.
		return BoundVerdict{rpmCompare(installed, bound), DomainRPM, ""}
	}
	// Upstream-only: strip the installed epoch and release.
	v := iv
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return BoundVerdict{Compare: 2, Domain: DomainRPM}
	}
	return compareUpstreamBound(v, bv)
}

// compareAPKBound routes one Alpine package version against one bound.
// apk versions are "[epoch:]ver[-rN]"; upstream-only bounds project to
// the version with the "-rN" build suffix removed. Alpine spellings of
// OpenSSH patch levels ("9.7_p1") do not parse in the OpenSSH grammar,
// so apk upstream bounds order under apk rules; distro-format bounds
// (which is what Alpine security data publishes) compare fully.
func compareAPKBound(installed, bound string) BoundVerdict {
	_, bhadEpoch := rpmEpoch(bound) // apk shares the "N:" epoch syntax
	if bhadEpoch || hasApkRelease(bound) {
		return BoundVerdict{apkCompare(installed, bound), DomainAPK, ""}
	}
	v := installed
	if i := strings.LastIndexByte(v, '-'); i >= 0 && isApkRelease(v[i+1:]) {
		v = v[:i]
	}
	if v == "" {
		return BoundVerdict{Compare: 2, Domain: DomainAPK}
	}
	return BoundVerdict{apkCompare(v, bound), DomainAPK, v}
}

// compareUpstreamBound decides an upstream-only bound against an
// upstream component: structured OpenSSH ordering when both sides are
// OpenSSH releases (the pN update level is the one grammar element dpkg
// upstream ordering has no concept of), dpkg upstream ordering
// otherwise. Both grammars agree on purely numeric dotted pairs, so the
// structured route is strictly more precise, never conflicting.
func compareUpstreamBound(installedUpstream, boundUpstream string) BoundVerdict {
	if a, errA := pkgversion.ParseOpenSSHVersion(installedUpstream); errA == nil {
		if b, errB := pkgversion.ParseOpenSSHVersion(boundUpstream); errB == nil {
			return BoundVerdict{pkgversion.CompareOpenSSH(a, b), DomainOpenSSH, installedUpstream}
		}
	}
	up := pkgversion.PackageVersion{Raw: installedUpstream, Upstream: installedUpstream}
	bu := pkgversion.PackageVersion{Raw: boundUpstream, Upstream: boundUpstream}
	return BoundVerdict{pkgversion.CompareDebParsed(up, bu), DomainUpstream, installedUpstream}
}

// rpmEpoch splits the optional "N:" epoch, reporting whether one was
// actually present (a bare colon or non-numeric epoch is not one).
func rpmEpoch(v string) (string, bool) {
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return v, false
	}
	if _, err := strconv.ParseUint(v[:i], 10, 64); err != nil {
		return v, false
	}
	return v[i+1:], true
}

// hasApkRelease reports whether v ends with an apk build-release suffix.
func hasApkRelease(v string) bool {
	i := strings.LastIndexByte(v, '-')
	return i >= 0 && isApkRelease(v[i+1:])
}

// isApkRelease reports whether s is an apk build-release suffix:
// "r<digits>" optionally followed by ".c<digits>" / ".<digits>"
// continuations ("r2", "r2.c1").
func isApkRelease(s string) bool {
	if len(s) < 2 || s[0] != 'r' {
		return false
	}
	s = s[1:]
	for {
		n := 0
		for n < len(s) && isDigitByte(s[n]) {
			n++
		}
		if n == 0 {
			return false // every segment needs at least one digit
		}
		s = s[n:]
		if s == "" {
			return true
		}
		if strings.HasPrefix(s, ".c") && len(s) > 2 {
			s = s[2:]
			continue
		}
		if strings.HasPrefix(s, ".") && len(s) > 1 {
			s = s[1:]
			continue
		}
		return false
	}
}
