// Package vulnerabilities implements the vulnerability matching engine
// — one of the most important parts of the product. It turns
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
	Version     string // may be empty; the normalized form when the caller normalized at ingestion
	RawVersion  string // the version exactly as collected, for evidence; empty when equal to Version
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
	// Remediation overrides the generic remediation text when the match
	// knows the exact fix (e.g. "Upgrade openssl to 3.0.2-0ubuntu1.16
	// (USN-6800-1)").
	Remediation string
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

	// Package ecosystems use OSV-aware matching.
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
		affected, mt, conf, reason, boundEv := osvAffects(adv, in.PackageName, in.Version)
		if !affected {
			continue
		}
		for _, cve := range adv.CVEIDs {
			ev := map[string]any{"osv_id": adv.ID, "ecosystem": in.Ecosystem, "package": in.PackageName, "version": in.Version}
			if in.RawVersion != "" && in.RawVersion != in.Version {
				ev["version_raw"] = in.RawVersion
			}
			for k, v := range boundEv {
				ev[k] = v
			}
			out = append(out, Match{
				CVEID: cve, OSVID: adv.ID, MatchType: mt, Confidence: conf,
				Reason:   reason,
				Evidence: ev,
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
func osvAffects(adv domain.OSVRecord, pkg, version string) (bool, domain.MatchType, domain.Confidence, string, map[string]any) {
	if version == "" {
		// Version unknown: potential only. Do not claim confirmed.
		return true, domain.MatchHeuristic, 0.3, "Package " + pkg + " matches advisory without a version pin (potential, not confirmed)", nil
	}
	if len(adv.AffectedRanges) == 0 {
		return true, domain.MatchHeuristic, 0.4, "Advisory lists package without machine-readable ranges (potential)", nil
	}
	evaluated := false
	for _, r := range adv.AffectedRanges {
		if strings.EqualFold(r.Type, "GIT") {
			continue // commit ranges carry no version ordering to evaluate
		}
		evaluated = true
		if in, verdict, constraint := inRange(r, version, adv.Ecosystem); in {
			reason := "Version " + version + " falls inside affected range of " + adv.ID
			ev := map[string]any{}
			if constraint != nil {
				ev["constraint"] = *constraint
			}
			if verdict != nil {
				ev["bound_domain"] = string(verdict.Domain)
				reason += " (" + string(verdict.Domain) + " ordering)"
				if verdict.Projected != "" {
					ev["projected_version"] = verdict.Projected
				}
			}
			return true, domain.MatchPackageVersion, 0.9, reason, ev
		}
	}
	if !evaluated {
		return true, domain.MatchHeuristic, 0.4, "Advisory only lists commit ranges; version " + version + " cannot be evaluated (potential)", nil
	}
	return false, "", 0, "", nil
}

// inRange evaluates the domain-tagged VersionConstraint of one OSV range
// against the version under judgment. The constraint is built per the OSV
// event model (introduced/fixed/last_affected, "0" dropped) and every bound
// is compared through ComparePackageBound, which resolves the comparison
// domain per bound: a distro-format bound ("1:10.0p1-5ubuntu5.5") orders
// fully under the distro grammar, while an upstream-only bound — the
// "affected < 10.5" shape of OpenSSH CVEs — is projected to the installed
// package's upstream component first and decided in the structured OpenSSH
// domain when both sides are OpenSSH releases. Incomparable bounds never
// match (never guess). Returns whether the version falls inside, the
// deciding bound's verdict (nil when the range carries no version bounds)
// and the constraint for evidence.
func inRange(r domain.VersionRange, version, ecosystem string) (bool, *fingerprinting.BoundVerdict, *domain.VersionConstraint) {
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
	if introduced == "" && fixed == "" && lastAffected == "" {
		return false, nil, nil
	}
	constraint := domain.VersionConstraint{
		// The ecosystem label resolves the DEFAULT domain; the deciding
		// bound's verdict overwrites it below, so the constraint names the
		// domain the applicability call was actually made in (an Ubuntu
		// OSV record with an upstream-only OpenSSH bound reports
		// {Domain: openssh, Fixed: "10.5"}).
		Domain:          fingerprinting.DomainForEcosystem(ecosystem),
		Introduced:      introduced,
		Fixed:           fixed,
		LessThanOrEqual: lastAffected,
	}
	var deciding *fingerprinting.BoundVerdict
	evaluate := func(bound string, inside func(c int) bool) bool {
		v := fingerprinting.ComparePackageBound(version, bound, ecosystem)
		deciding = &v
		constraint.Domain = v.Domain
		return v.Compare != 2 && inside(v.Compare)
	}
	if introduced != "" {
		if !evaluate(introduced, func(c int) bool { return c >= 0 }) {
			return false, deciding, &constraint
		}
	}
	if fixed != "" {
		if !evaluate(fixed, func(c int) bool { return c < 0 }) {
			return false, deciding, &constraint
		}
	}
	if lastAffected != "" {
		if !evaluate(lastAffected, func(c int) bool { return c <= 0 }) {
			return false, deciding, &constraint
		}
	}
	return true, deciding, &constraint
}

func (m *Matcher) matchService(ctx context.Context, in MatchInput, max int) ([]Match, error) {
	// Build CPE candidate set. When a version is under judgment, the
	// synthesized CPE carrying it (the caller's normalized input version)
	// is evaluated FIRST — it is the authoritative observed version; an
	// explicit scanner CPE may carry only the upstream part ("10.0p2") or
	// a differently formatted string. Explicit CPEs follow, and the
	// versionless synthesized fallback is last: it can only produce
	// "potential" verdicts and must never preempt versioned ones. Without
	// a version under judgment the original order holds (explicit CPEs,
	// whose own version may pin or range, then the versionless fallback).
	synth := fingerprinting.ServiceToCPE(in.Vendor, in.Product, in.Version)
	var cpes []string
	if in.Version != "" && len(synth) > 0 {
		cpes = append(cpes, synth[0])
		cpes = append(cpes, in.CPEs...)
		cpes = append(cpes, synth[1:]...)
	} else {
		cpes = append(cpes, in.CPEs...)
		cpes = append(cpes, synth...)
	}

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
			// A versionless candidate must not resurrect a CVE that a
			// versioned candidate already range-rejected. A versioned
			// candidate with a DIFFERENT version string (the synthesized
			// CPE carries the normalized input version; an explicit CPE
			// may carry nmap's upstream-only one) is judged on its own
			// version — a miss by one candidate version is not a miss by
			// every candidate version.
			if rangeMiss[id] && c.Version == "" {
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
			if in, verdict := versionInRange(cm, observed.Version); in {
				reason := "Version " + observed.Version + " inside affected range " + rangeString(cm)
				if cm.VersionType != "" {
					reason += " (" + cm.VersionType + " ordering)"
				}
				ev["constraint"] = cm.Constraint()
				if verdict != nil {
					ev["bound_domain"] = string(verdict.Domain)
					if verdict.Projected != "" {
						ev["projected_version"] = verdict.Projected
						reason += " — installed compared as upstream " + verdict.Projected
					}
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

// versionInRange evaluates NVD/CVE-v5 range boundaries, routing every
// bound through CompareCPEBound under the match's declared versionType.
// Distro versionTypes order distro-format bounds fully and project
// upstream-only bounds to the installed version's upstream component;
// custom/unknown versionTypes — what NVD declares for OpenSSH — decide in
// the structured OpenSSH domain when both sides are OpenSSH releases and
// fall back to the generic natural-order comparator otherwise. Both sides
// are cleaned first, so banner noise ("10.0p2 Debian 7") and
// distro-normalized forms ("10.0p2-5ubuntu5.4") compare correctly against
// feed bounds ("10.5"). Incomparable bounds never match (never guess).
// Returns whether the version is inside the range plus the verdict of the
// bound that decided (nil when the range has no bounds).
func versionInRange(cm domain.CPEMatch, v string) (bool, *fingerprinting.BoundVerdict) {
	var last *fingerprinting.BoundVerdict // the final bound that confirmed "inside"
	decide := func(bound string, inside func(c int) bool) (bool, *fingerprinting.BoundVerdict) {
		verdict := fingerprinting.CompareCPEBound(v, bound, cm.VersionType)
		if verdict.Compare == 2 {
			return false, &verdict // incomparable: never guess
		}
		return inside(verdict.Compare), &verdict
	}
	if cm.VersionStartIncl != "" {
		in, vd := decide(cm.VersionStartIncl, func(c int) bool { return c >= 0 })
		last = vd
		if !in {
			return false, vd
		}
	}
	if cm.VersionStartExcl != "" {
		in, vd := decide(cm.VersionStartExcl, func(c int) bool { return c > 0 })
		last = vd
		if !in {
			return false, vd
		}
	}
	if cm.VersionEndIncl != "" {
		in, vd := decide(cm.VersionEndIncl, func(c int) bool { return c <= 0 })
		last = vd
		if !in {
			return false, vd
		}
	}
	if cm.VersionEndExcl != "" {
		in, vd := decide(cm.VersionEndExcl, func(c int) bool { return c < 0 })
		last = vd
		if !in {
			return false, vd
		}
	}
	return true, last
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
