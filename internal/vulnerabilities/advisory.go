// Advisory-backed OS-package correlation.
//
// This is aegis' equivalent of vuls' OVAL/gost detection plane: an installed
// distro package is vulnerable iff a distro advisory for the asset's exact
// (family, release) lists the package with a fixed version the installed
// version sorts below, under the distro's own version grammar. Such matches
// are deterministic — Confidence 1.0 — and carry the advisory id and the
// fixed-in version as first-class evidence, like vuls' OvalMatch /
// DebianSecurityTrackerMatch rank.
package vulnerabilities

import (
	"context"
	"fmt"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// AdvisorySource supplies distro advisories for one (family, release,
// package). Implemented by pg.AdvisoryRepo; faked in tests.
type AdvisorySource interface {
	ForPackage(ctx context.Context, family, release, pkg string) ([]domain.OSAdvisory, error)
}

// DistroResolver resolves an asset's advisory scope (family, release, package
// ecosystem). Defaults to fingerprinting.DistroOf over the asset's OS fields;
// overridable in tests.
type DistroResolver func(asset *domain.Asset) (fingerprinting.DistroSegment, bool)

// DefaultDistroResolver resolves from OSFamily/OSName/OSVersion.
func DefaultDistroResolver(asset *domain.Asset) (fingerprinting.DistroSegment, bool) {
	return fingerprinting.DistroOf(asset.OSFamily, asset.OSName, asset.OSVersion)
}

// isOSPackageEcosystem reports whether the software row is an OS package
// recorded by the endpoint agent or an SSH collection run.
func isOSPackageEcosystem(eco string) bool {
	switch eco {
	case fingerprinting.PkgEcoDebian, fingerprinting.PkgEcoRPM, fingerprinting.PkgEcoAlpine:
		return true
	}
	return false
}

// CorrelateOSPackage correlates one installed OS package against the distro
// advisory plane. Returns (findings, handled, error): handled=true means the
// distro release IS covered by advisory data (even when nothing matched) and
// the caller must NOT fall back to rougher matching for the same package —
// falling through would re-report already-adjudicated packages with low
// confidence.
func (c *Correlator) CorrelateOSPackage(ctx context.Context, orgID string, asset *domain.Asset, sw *domain.Software) (int, bool, error) {
	if c.Advisories == nil || sw == nil || sw.Name == "" || sw.Version == "" {
		return 0, false, nil
	}
	resolve := c.DistroResolver
	if resolve == nil {
		resolve = DefaultDistroResolver
	}
	seg, ok := resolve(asset)
	if !ok {
		return 0, false, nil
	}
	// A package recorded under a different package manager than the asset's
	// distro is data corruption; never judge across ecosystems.
	if sw.Ecosystem != seg.PkgEcosystem {
		return 0, false, nil
	}
	advs, err := c.Advisories.ForPackage(ctx, seg.Family, seg.Release, sw.Name)
	if err != nil {
		return 0, false, err
	}
	if len(advs) == 0 {
		return 0, false, nil // no advisory coverage for this release → caller falls back
	}
	// Compare the normalized installed version: advisory fixed-in bounds
	// carry exact distro revision semantics, so the verdict must come
	// from the grammar-canonical form, never banner noise. Each bound is
	// compared through ComparePackageBound: a distro-format fixed-in
	// ("1:10.0p1-5ubuntu5.5") orders fully under the distro grammar, an
	// upstream-only fixed-in ("10.5") is projected to the installed
	// package's upstream component first — the epoch and distro revision
	// are packaging artifacts the fix boundary must never see.
	installed := matchVersion(sw)
	n := 0
	for i := range advs {
		adv := &advs[i]
		if !adv.VulnerableUnder(installed, func(a, b string) int {
			return fingerprinting.ComparePackageBound(a, b, seg.PkgEcosystem).Compare
		}) {
			continue
		}
		bv := fingerprinting.ComparePackageBound(installed, adv.FixedVersion, seg.PkgEcosystem)
		m := Match{
			CVEID:      adv.CVEID,
			MatchType:  domain.MatchOSPackage,
			Confidence: 1.0,
			Reason: fmt.Sprintf("%s package %s %s on %s %s is affected by %s (%s)",
				pkgManagerLabel(seg.PkgEcosystem), sw.Name, sw.Version, seg.Family, seg.Release,
				adv.CVEID, adv.AdvisoryID),
			Evidence: map[string]any{
				"advisory":       adv.AdvisoryID,
				"advisory_url":   adv.AdvisoryURL,
				"cve":            adv.CVEID,
				"distro":         seg.Family,
				"release":        seg.Release,
				"package":        sw.Name,
				"installed":      sw.Version,
				"installed_norm": installed,
				"fixed_in":       adv.FixedVersion,
				"not_fixed_yet":  adv.NotFixedYet,
				"source":         adv.Source,
				"compare_domain": string(bv.Domain),
			},
		}
		if bv.Projected != "" {
			m.Evidence["projected_version"] = bv.Projected
		}
		if adv.NotFixedYet {
			m.Remediation = fmt.Sprintf("No fixed package is available yet for %s %s (%s tracks %s). Follow %s and upgrade as soon as the distro publishes a fix.",
				seg.Family, seg.Release, adv.AdvisoryID, adv.CVEID, advisoryRef(adv))
		} else {
			m.Remediation = fmt.Sprintf("Upgrade %s to %s (%s).",
				sw.Name, adv.FixedVersion, advisoryRef(adv))
		}
		var vuln *domain.Vulnerability
		if adv.CVEID != "" && c.Index != nil {
			vuln, _ = c.Index.CVE(ctx, adv.CVEID) // enrichment is best-effort
		}
		created, err := c.upsertFinding(ctx, orgID, asset, nil, &sw.ID, m, vuln, nil)
		if err != nil {
			if c.Log != nil {
				c.Log.Warn("advisory finding upsert failed", "err", err, "cve", adv.CVEID)
			}
			continue
		}
		if created {
			n++
		}
	}
	return n, true, nil
}

func advisoryRef(adv *domain.OSAdvisory) string {
	if adv.AdvisoryID != "" {
		return adv.AdvisoryID
	}
	return adv.Source
}

func pkgManagerLabel(pkgEcosystem string) string {
	switch pkgEcosystem {
	case fingerprinting.PkgEcoDebian:
		return "dpkg"
	case fingerprinting.PkgEcoRPM:
		return "rpm"
	case fingerprinting.PkgEcoAlpine:
		return "apk"
	}
	return "package"
}
