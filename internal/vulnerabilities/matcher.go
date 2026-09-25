// Package vulnerabilities implements the vulnerability matching engine
// — one of the most important parts of the product. It turns
// observed services/packages into candidate CVEs with explicit match type,
// confidence and evidence. Heuristic matches are never presented as
// confirmed vulnerabilities.
package vulnerabilities

import (
	"context"
	"fmt"
	"sort"
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
	// CVEs batch-loads full records including CPE matches. The matcher
	// evaluates a candidate set per observation; loading them one round
	// trip per CVE made candidate evaluation N+1.
	CVEs(ctx context.Context, cveIDs []string) (map[string]*domain.Vulnerability, error)
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

// Match evaluates one input and returns explainable candidates. The
// second return value reports whether the caller cap hid results — a
// truncated match list is a fact the UI/API must surface, never silently
// swallow.
func (m *Matcher) Match(ctx context.Context, in MatchInput) ([]Match, bool, error) {
	if m.Index == nil {
		return nil, false, fmt.Errorf("matcher: nil index")
	}
	max := m.MaxPerItem
	if max <= 0 {
		max = 50
	}

	// Package ecosystems use OSV-aware matching.
	if in.Ecosystem != "" && in.PackageName != "" {
		ms, err := m.matchPackage(ctx, in, max)
		return ms, false, err
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

// candidateScanLimit is the per-identity candidate fetch bound. It must be
// generous: the caller cap is applied AFTER all identities are evaluated and
// results ranked, so a definitive match deeper in a product's candidate list
// is never starved by earlier heuristics (the old per-identity cap of `max`
// cut exactly there).
const candidateScanLimit = 500

func (m *Matcher) matchService(ctx context.Context, in MatchInput, max int) ([]Match, bool, error) {
	// Build CPE candidate identities. When a version is under judgment, the
	// synthesized CPE carrying it (the caller's normalized input version) is
	// evaluated FIRST — it is the authoritative observed version; an explicit
	// scanner CPE may carry only the upstream part ("10.0p2") or a differently
	// formatted string. Without a version under judgment the original order
	// holds (explicit CPEs, whose own version may pin or range, then the
	// versionless fallback).
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

	// Dedupe parsed identities (order preserved). Every distinct identity is
	// evaluated against every candidate CVE — the per-CVE best verdict wins,
	// never the first identity that happened to see the CVE.
	// identity pairs a parsed CPE with its version authority: the
	// identity carrying the caller's normalized version (the synthesized
	// CPE) outranks explicit scanner CPEs, which may carry a stale
	// upstream version — their pin verdicts must not outrank the
	// authoritative version's verdict.
	type identity struct {
		cpe       fingerprinting.CPE
		authority int
	}
	var identities []identity
	seenIdentity := map[string]bool{}
	for idx, cpeStr := range cpes {
		c, ok := fingerprinting.ParseCPE(cpeStr)
		if !ok {
			continue
		}
		k := c.Vendor + "|" + c.Product + "|" + c.Version
		if seenIdentity[k] {
			continue
		}
		seenIdentity[k] = true
		auth := 0
		if in.Version != "" && idx == 0 && len(synth) > 0 {
			auth = 1 // the synthesized CPE carrying the observed version
		}
		identities = append(identities, identity{cpe: c, authority: auth})
	}
	if len(identities) == 0 {
		return nil, false, nil
	}

	// Candidate scan: union over all identities.
	candSet := map[string]bool{}
	var cands []string
	for _, ident := range identities {
		ids, err := m.Index.CandidateCVEsByProduct(ctx, ident.cpe.Vendor, ident.cpe.Product, candidateScanLimit)
		if err != nil {
			return nil, false, err
		}
		for _, id := range ids {
			if !candSet[id] {
				candSet[id] = true
				cands = append(cands, id)
			}
		}
	}
	if len(cands) == 0 {
		return nil, false, nil
	}

	// Batch-load candidate records — one round-trip set per chunk, not an
	// N+1 CVE+CPES query pair per candidate.
	vulns, err := m.Index.CVEs(ctx, cands)
	if err != nil {
		return nil, false, err
	}

	out := make([]Match, 0, len(cands))
	for _, id := range cands {
		vuln := vulns[id]
		if vuln == nil || vuln.State == domain.CVEStateRejected {
			continue
		}
		// Per-CVE best evaluation: every identity is judged; the strongest
		// verdict wins (exact > range > potential). A versioned identity
		// whose version statements rejected the observed version marks the
		// CVE range-rejected: potential-grade verdicts from weaker
		// (versionless) identities must not resurrect it — the vendor made
		// a version statement and the known observed version does not fit.
		best := Match{CVEID: id}
		bestRank, bestAuth := 0, 0
		versionRejected := false
		for _, ident := range identities {
			mt, conf, reason, ev, rejected := evaluateCPE(vuln, ident.cpe, in)
			if mt == "" {
				if rejected {
					versionRejected = true
				}
				continue
			}
			r := matchRank(mt)
			if ident.authority > bestAuth ||
				(ident.authority == bestAuth && (r > bestRank || (r == bestRank && conf > best.Confidence))) {
				best = Match{CVEID: id, MatchType: mt, Confidence: conf, Reason: reason, Evidence: ev}
				bestRank, bestAuth = r, ident.authority
			}
		}
		if bestRank == 0 {
			continue
		}
		if versionRejected && bestRank <= matchRank(domain.MatchServiceVersion) {
			continue // potential-only evidence after a version rejection
		}
		out = append(out, best)
	}

	// Rank globally and only then apply the caller cap.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	truncated := false
	if len(out) > max {
		out = out[:max]
		truncated = true
	}
	return out, truncated, nil
}

// matchRank orders verdict strengths: definitive CPE evidence beats
// potential-grade identity matches.
func matchRank(mt domain.MatchType) int {
	switch mt {
	case domain.MatchExactCPE:
		return 4
	case domain.MatchCPERange:
		return 3
	case domain.MatchServiceVersion:
		return 2
	default:
		return 1 // heuristic / package-level potentials
	}
}

// evaluateCPE compares one CVE's CPE expressions with the observed identity.
// Every expression sharing the observed vendor/product is judged and the
// STRONGEST verdict wins — an expression-order-dependent first verdict used
// to let a versionless "potential" shadow both a pin/range rejection of the
// same product and a stronger match in a later expression. The final return
// value reports that a versioned expression (pin or range) shared the
// identity and rejected the observed version: callers use it to suppress
// potential-grade verdicts, never definitive ones.
func evaluateCPE(vuln *domain.Vulnerability, observed fingerprinting.CPE, in MatchInput) (domain.MatchType, domain.Confidence, string, map[string]any, bool) {
	best := Match{Confidence: 0}
	bestRank := 0
	versionRejected := false
	for _, cm := range vuln.CPEMatches {
		cmCPE, ok := fingerprinting.ParseCPE(cm.CPE)
		if !ok {
			continue
		}
		if cmCPE.Product != observed.Product || cmCPE.Vendor != observed.Vendor {
			continue
		}
		ev := map[string]any{"cve": vuln.CVEID, "cpe": cm.CPE, "observed_product": observed.Product, "observed_version": observed.Version}

		var mt domain.MatchType
		var conf domain.Confidence
		var reason string

		// Exact pinned version in the CPE match. Observed scanner noise
		// ("10.0p2 Debian 7") is stripped before comparing with the pin.
		if cm.Version != "" && cm.Version != "*" && cm.Version != "-" {
			if observed.Version == "" {
				continue
			}
			if versionsEquivalent(cm.Version, observed.Version) {
				mt, conf, reason = domain.MatchExactCPE, 0.95, "Exact CPE match "+cm.CPE
			} else {
				// The vendor pinned a version and the observed one is not it.
				versionRejected = true
				continue
			}
		} else if hasRange(cm) {
			// Range expression (start/end bounds from NVD configuration or
			// the CVE List v5 affected statement; bounds compare under the
			// match's declared versionType).
			if observed.Version == "" {
				mt, conf, reason = domain.MatchHeuristic, 0.35, "Product in affected range expression but version unknown (potential)"
			} else if inRange, verdict := versionInRange(cm, observed.Version); inRange {
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
				mt, conf = domain.MatchCPERange, 0.9
			} else {
				// The vendor ranged versions and the observed one is outside.
				versionRejected = true
				continue
			}
		} else if observed.Version != "" {
			// No version info at all in the match: versionless identity match.
			mt, conf, reason = domain.MatchServiceVersion, 0.6, "Product identity matches; CVE does not pin versions (potential)"
		} else {
			mt, conf, reason = domain.MatchHeuristic, 0.3, "Product identity matches but neither side has a version (potential)"
		}

		if r := matchRank(mt); r > bestRank || (r == bestRank && conf > best.Confidence) {
			best = Match{MatchType: mt, Confidence: conf, Reason: reason, Evidence: ev}
			bestRank = r
		}
	}
	if bestRank == 0 {
		return "", 0, "", nil, versionRejected
	}
	return best.MatchType, best.Confidence, best.Reason, best.Evidence, versionRejected
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
