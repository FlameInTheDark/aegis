// Package vulnerabilities implements the vulnerability matching engine
// (spec §32) — one of the most important parts of the product. It turns
// observed services/packages into candidate CVEs with explicit match type,
// confidence and evidence. Heuristic matches are never presented as
// confirmed vulnerabilities.
package vulnerabilities

import (
	"context"
	"fmt"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// MatchInput is one observed product identity to match against the index.
type MatchInput struct {
	AssetID     string
	ServiceID   string
	SoftwareID  string
	Vendor      string
	Product     string
	Version     string // may be empty
	CPEs        []string
	Ecosystem   string // for packages: npm, pypi, go, os_debian...
	PackageName string
	PackageURL  string
	OS          string
}

// Match is one candidate vulnerability.
type Match struct {
	CVEID      string
	OSVID      string
	MatchType  domain.MatchType
	Confidence domain.Confidence
	Reason     string
	Evidence   map[string]any
}

// Index is the read-side view over the local vulnerability store. The
// matching engine depends on this interface only, keeping it unit-testable.
type Index interface {
	// CandidateCVEsByProduct returns CVE ids possibly affecting vendor/product.
	CandidateCVEsByProduct(ctx context.Context, vendor, product string, limit int) ([]string, error)
	// CVE loads a full record including CPE matches.
	CVE(ctx context.Context, cveID string) (*domain.Vulnerability, error)
	// EPSSForCVEs returns latest EPSS per CVE.
	EPSSForCVEs(ctx context.Context, cveIDs []string) (map[string]float64, error)
	// KEVSet returns the set of known-exploited CVE ids.
	KEVSet(ctx context.Context) (map[string]bool, error)
	// OSVForPackage returns ecosystem advisories for a package.
	OSVForPackage(ctx context.Context, ecosystem, name string) ([]domain.OSVRecord, error)
}

// Matcher evaluates inputs against the index.
type Matcher struct {
	Index      Index
	MaxPerItem int
}

// Match evaluates one input and returns explainable candidates.
func (m *Matcher) Match(ctx context.Context, in MatchInput) ([]Match, error) {
	if m.Index == nil {
		return nil, fmt.Errorf("matcher: nil index")
	}
	max := m.MaxPerItem
	if max <= 0 {
		max = 50
	}

	// Package ecosystems use OSV-aware matching (spec §34).
	if in.Ecosystem != "" && in.PackageName != "" {
		return m.matchPackage(ctx, in, max)
	}
	return m.matchService(ctx, in, max)
}

func (m *Matcher) matchPackage(ctx context.Context, in MatchInput, max int) ([]Match, error) {
	advs, err := m.Index.OSVForPackage(ctx, in.Ecosystem, in.PackageName)
	if err != nil {
		return nil, err
	}
	out := make([]Match, 0, len(advs))
	for _, adv := range advs {
		affected, mt, conf, reason := osvAffects(adv, in.PackageName, in.Version)
		if !affected {
			continue
		}
		for _, cve := range adv.CVEIDs {
			out = append(out, Match{
				CVEID: cve, OSVID: adv.ID, MatchType: mt, Confidence: conf,
				Reason:   reason,
				Evidence: map[string]any{"osv_id": adv.ID, "ecosystem": in.Ecosystem, "package": in.PackageName, "version": in.Version},
			})
		}
		if len(adv.CVEIDs) == 0 {
			out = append(out, Match{OSVID: adv.ID, MatchType: mt, Confidence: conf, Reason: reason,
				Evidence: map[string]any{"osv_id": adv.ID, "ecosystem": in.Ecosystem, "package": in.PackageName}})
		}
		if len(out) >= max {
			break
		}
	}
	return out, nil
}

// osvAffects decides whether a version is inside an OSV advisory's ranges.
func osvAffects(adv domain.OSVRecord, pkg, version string) (bool, domain.MatchType, domain.Confidence, string) {
	if version == "" {
		// Version unknown: potential only. Do not claim confirmed.
		return true, domain.MatchHeuristic, 0.3, "Package " + pkg + " matches advisory without a version pin (potential, not confirmed)"
	}
	if len(adv.AffectedRanges) == 0 {
		return true, domain.MatchHeuristic, 0.4, "Advisory lists package without machine-readable ranges (potential)"
	}
	evaluated := false
	for _, r := range adv.AffectedRanges {
		if strings.EqualFold(r.Type, "GIT") {
			continue // commit ranges carry no version ordering to evaluate
		}
		evaluated = true
		if inRange(r, version, adv.Ecosystem) {
			return true, domain.MatchPackageVersion, 0.9, "Version " + version + " falls inside affected range of " + adv.ID
		}
	}
	if !evaluated {
		return true, domain.MatchHeuristic, 0.4, "Advisory only lists commit ranges; version " + version + " cannot be evaluated (potential)"
	}
	return false, "", 0, ""
}

// inRange evaluates introduced/fixed/last_affected events against a version,
// using the OSV ecosystem's ordering rules (semver for npm, dpkg for Debian,
// rpmvercmp for Red Hat families, PEP 440 for PyPI, …).
func inRange(r domain.VersionRange, version, ecosystem string) bool {
	var introduced, fixed, lastAffected string
	for _, e := range r.Events {
		if e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" {
			fixed = e.Fixed
		}
		if e.LastAffected != "" {
			lastAffected = e.LastAffected
		}
	}
	if introduced == "0" {
		introduced = ""
	}
	cmpIntro, cmpFixed := 0, 0
	if introduced != "" {
		cmpIntro = fingerprinting.CompareEcosystem(version, introduced, ecosystem)
		if cmpIntro == 2 {
			return false
		} // incomparable: never guess
		if cmpIntro < 0 {
			return false
		}
	}
	if fixed != "" {
		cmpFixed = fingerprinting.CompareEcosystem(version, fixed, ecosystem)
		if cmpFixed == 2 {
			return false
		}
		if cmpFixed >= 0 {
			return false
		}
	}
	if lastAffected != "" {
		cmpLA := fingerprinting.CompareEcosystem(version, lastAffected, ecosystem)
		if cmpLA == 2 {
			return false
		}
		if cmpLA > 0 {
			return false
		}
	}
	return introduced != "" || fixed != "" || lastAffected != ""
}

func (m *Matcher) matchService(ctx context.Context, in MatchInput, max int) ([]Match, error) {
	// Build CPE candidate set: explicit CPEs first, then synthesized ones.
	cpes := append([]string{}, in.CPEs...)
	cpes = append(cpes, fingerprinting.ServiceToCPE(in.Vendor, in.Product, in.Version)...)

	seen := map[string]bool{}
	// rangeMiss records CVEs whose version bounds already rejected the
	// observed version while evaluating the version-carrying CPE candidate.
	// The versionless candidate (a deliberately weaker identity) must not
	// resurrect them as "potential" — the vendor declared version bounds and
	// the known observed version does not fit.
	rangeMiss := map[string]bool{}
	var out []Match
	for _, cpeStr := range cpes {
		c, ok := fingerprinting.ParseCPE(cpeStr)
		if !ok {
			continue
		}
		ids, err := m.Index.CandidateCVEsByProduct(ctx, c.Vendor, c.Product, max)
		if err != nil {
			return out, err
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			if rangeMiss[id] && in.Version != "" {
				seen[id] = true
				continue
			}
			seen[id] = true
			vuln, err := m.Index.CVE(ctx, id)
			if err != nil || vuln == nil || vuln.State == domain.CVEStateRejected {
				continue
			}
			mt, conf, reason, ev := evaluateCPE(vuln, c, in)
			if mt == "" {
				if in.Version != "" && vulnHasVersionBounds(vuln) {
					rangeMiss[id] = true
				}
				continue
			}
			out = append(out, Match{CVEID: id, MatchType: mt, Confidence: conf, Reason: reason, Evidence: ev})
			if len(out) >= max {
				return out, nil
			}
		}
	}
	return out, nil
}

// vulnHasVersionBounds reports whether any CPE match of the CVE pins or
// ranges versions (i.e. the vendor made a version statement at all).
func vulnHasVersionBounds(vuln *domain.Vulnerability) bool {
	for _, cm := range vuln.CPEMatches {
		if cm.Version != "" && cm.Version != "*" && cm.Version != "-" {
			return true
		}
		if hasRange(cm) {
			return true
		}
	}
	return false
}

// evaluateCPE compares one CVE's CPE expressions with the observed identity.
func evaluateCPE(vuln *domain.Vulnerability, observed fingerprinting.CPE, in MatchInput) (domain.MatchType, domain.Confidence, string, map[string]any) {
	for _, cm := range vuln.CPEMatches {
		cmCPE, ok := fingerprinting.ParseCPE(cm.CPE)
		if !ok {
			continue
		}
		if cmCPE.Product != observed.Product || cmCPE.Vendor != observed.Vendor {
			continue
		}
		ev := map[string]any{"cve": vuln.CVEID, "cpe": cm.CPE, "observed_product": observed.Product, "observed_version": observed.Version}

		// Exact pinned version in the CPE match. Observed scanner noise
		// ("10.0p2 Debian 7") is stripped before comparing with the pin.
		if cm.Version != "" && cm.Version != "*" && cm.Version != "-" {
			if observed.Version == "" {
				continue
			}
			if versionsEquivalent(cm.Version, observed.Version) {
				return domain.MatchExactCPE, 0.95, "Exact CPE match " + cm.CPE, ev
			}
			continue
		}

		// Range expression (start/end bounds from NVD configuration or the
		// CVE List v5 affected statement; bounds compare under the match's
		// declared versionType).
		if hasRange(cm) {
			if observed.Version == "" {
				return domain.MatchHeuristic, 0.35, "Product in affected range expression but version unknown (potential)", ev
			}
			if versionInRange(cm, observed.Version) {
				reason := "Version " + observed.Version + " inside affected range " + rangeString(cm)
				if cm.VersionType != "" {
					reason += " (" + cm.VersionType + " ordering)"
				}
				return domain.MatchCPERange, 0.9, reason, ev
			}
			continue
		}

		// No version info at all in the match: versionless identity match.
		if observed.Version != "" {
			return domain.MatchServiceVersion, 0.6, "Product identity matches; CVE does not pin versions (potential)", ev
		}
		return domain.MatchHeuristic, 0.3, "Product identity matches but neither side has a version (potential)", ev
	}
	return "", 0, "", nil
}

// versionsEquivalent reports whether an observed version string equals a
// pinned CPE version once scanner noise is stripped ("10.0p2 Debian 7"
// vs pin "10.0p2"), or is the pinned upstream version plus a distro
// packaging suffix ("1.24.0-1ubuntu3" vs "1.24.0"). Patch-level suffixes
// ("10.0p2" vs pin "10.0") are NOT equivalent — different releases.
func versionsEquivalent(pinned, observed string) bool {
	p, o := fingerprinting.CleanVersion(pinned), fingerprinting.CleanVersion(observed)
	if p == "" || o == "" {
		return false
	}
	if o == p {
		return true
	}
	return len(o) > len(p) && strings.HasPrefix(o, p) && (o[len(p)] == '-' || o[len(p)] == '+')
}

func hasRange(cm domain.CPEMatch) bool {
	return cm.VersionStartIncl != "" || cm.VersionStartExcl != "" || cm.VersionEndIncl != "" || cm.VersionEndExcl != ""
}

func rangeString(cm domain.CPEMatch) string {
	var parts []string
	if cm.VersionStartIncl != "" {
		parts = append(parts, ">="+cm.VersionStartIncl)
	}
	if cm.VersionStartExcl != "" {
		parts = append(parts, ">"+cm.VersionStartExcl)
	}
	if cm.VersionEndIncl != "" {
		parts = append(parts, "<="+cm.VersionEndIncl)
	}
	if cm.VersionEndExcl != "" {
		parts = append(parts, "<"+cm.VersionEndExcl)
	}
	return strings.Join(parts, ", ")
}

// versionInRange evaluates NVD/CVE-v5 range boundaries under the match's
// versionType ordering. Both sides are cleaned first, so banner noise
// ("10.0p2 Debian 7") compares correctly against feed bounds ("10.4").
func versionInRange(cm domain.CPEMatch, v string) bool {
	ok := true
	vt := cm.VersionType
	if cm.VersionStartIncl != "" {
		c := fingerprinting.CompareTyped(v, cm.VersionStartIncl, vt)
		ok = ok && c != 2 && c >= 0
	}
	if cm.VersionStartExcl != "" {
		c := fingerprinting.CompareTyped(v, cm.VersionStartExcl, vt)
		ok = ok && c != 2 && c > 0
	}
	if cm.VersionEndIncl != "" {
		c := fingerprinting.CompareTyped(v, cm.VersionEndIncl, vt)
		ok = ok && c != 2 && c <= 0
	}
	if cm.VersionEndExcl != "" {
		c := fingerprinting.CompareTyped(v, cm.VersionEndExcl, vt)
		ok = ok && c != 2 && c < 0
	}
	return ok
}

// BestSeverity picks the most authoritative CVSS for display: v3.1 > v3.0 > v4 > v2.
// (Ordering note: v4 is newer but many environments standardize on v3.1;
// we prefer v3.x for continuity and expose all raw scores alongside.)
func BestSeverity(v *domain.Vulnerability) (float64, string) {
	if v == nil {
		return 0, ""
	}
	if v.CVSSv3 != nil && v.CVSSv3.Score > 0 {
		return v.CVSSv3.Score, v.CVSSv3.Vector
	}
	if v.CVSSv4 != nil && v.CVSSv4.Score > 0 {
		return v.CVSSv4.Score, v.CVSSv4.Vector
	}
	if v.CVSSv2 != nil && v.CVSSv2.Score > 0 {
		return v.CVSSv2.Score, v.CVSSv2.Vector
	}
	return 0, ""
}
