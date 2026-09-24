package vulnerabilities

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/risk"
)

// FindingStore persists findings (implemented by *pg.FindingRepo).
type FindingStore interface {
	Upsert(ctx context.Context, f *domain.Finding) error
}

// EvidenceStore persists evidence records (implemented by *pg.EvidenceRepo).
type EvidenceStore interface {
	Insert(ctx context.Context, e *domain.Evidence) error
}

// Correlator runs the full pipeline :
// service -> fingerprint -> normalize -> CPE candidates -> local index
// -> KEV/EPSS/CVSS -> environmental risk -> finding + evidence.
type Correlator struct {
	Index Index
	// Findings/Evidence are store interfaces so the correlator is unit-
	// testable; *pg.FindingRepo/*pg.EvidenceRepo implement them.
	Findings FindingStore
	Evidence EvidenceStore
	Assets   *pg.AssetRepo
	Services *pg.ServiceRepo  // optional: enables SweepOrg/SweepAsset
	Software *pg.SoftwareRepo // optional: enables software-row correlation
	Matcher  *Matcher
	Log      *slog.Logger
	// Advisories is the distro advisory plane; optional.
	// When nil, os_* packages fall through to the OSV path as before.
	Advisories AdvisorySource
	// DistroResolver overrides how an asset's distro segment is resolved
	// (tests). Defaults to fingerprinting.DistroOf.
	DistroResolver DistroResolver
	// Now is overridable in tests.
	Now func() time.Time
}

// CorrelateService correlates one observed service against the index and
// upserts findings. Returns number of findings created.
func (c *Correlator) CorrelateService(ctx context.Context, orgID string, asset *domain.Asset, svc *domain.Service) (int, error) {
	if c.Matcher == nil {
		c.Matcher = &Matcher{Index: c.Index}
	}
	// CVE matching runs on the normalized service version when present:
	// the raw banner string ("10.0p2 Ubuntu 5ubuntu5.4") is provenance,
	// not an ordering input — version_norm is the grammar-canonical
	// form the version ranges understand. Raw stays on the evidence
	// chain via RawVersion.
	in := MatchInput{
		AssetID:    asset.ID,
		ServiceID:  svc.ID,
		Vendor:     svc.Vendor,
		Product:    svc.Product,
		Version:    serviceMatchVersion(svc),
		RawVersion: svc.DetectedVersion,
		CPEs:       svc.CPEs,
	}
	if in.Product == "" {
		in.Product = svc.ServiceName // weak, becomes heuristic-only
	}
	if in.Product == "" {
		return 0, nil
	}
	matches, err := c.Matcher.Match(ctx, in)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range matches {
		if m.CVEID == "" {
			continue
		}
		vuln, err := c.Index.CVE(ctx, m.CVEID)
		if err != nil || vuln == nil {
			continue
		}
		created, err := c.upsertFinding(ctx, orgID, asset, &svc.ID, nil, m, vuln, svc)
		if err != nil {
			c.Log.Warn("finding upsert failed", "err", err, "cve", m.CVEID)
			continue
		}
		if created {
			n++
		}
	}
	return n, nil
}

// matchVersion returns the version CVE matching compares for a
// software row: the ingestion-normalized form when present (scanner
// noise stripped, canonical under the package grammar), the raw
// collected string otherwise. Raw is never rewritten, so every source
// keeps its exact dpkg/rpm/apk revision semantics on the row while
// ordering decisions run on the normalized value.
func matchVersion(sw *domain.Software) string {
	if sw.VersionNorm != "" {
		return sw.VersionNorm
	}
	return sw.Version
}

// serviceMatchVersion returns the version CVE matching compares for a
// service row: the banner-normalized form when present ("10.0p2
// Ubuntu 5ubuntu5.4" -> "10.0p2-5ubuntu5.4"), the raw detected
// version otherwise. Same contract as matchVersion for software
// rows: matching is normalized-first, evidence keeps the raw.
func serviceMatchVersion(svc *domain.Service) string {
	if svc.VersionNorm != "" {
		return svc.VersionNorm
	}
	return svc.DetectedVersion
}

// CorrelatePackage correlates one agent-reported software package (endpoint path: package -> ecosystem -> OSV/CVE -> finding).
func (c *Correlator) CorrelatePackage(ctx context.Context, orgID string, asset *domain.Asset, sw *domain.Software) (int, error) {
	if sw.Ecosystem == "" || sw.Name == "" {
		return 0, nil
	}
	if c.Matcher == nil {
		c.Matcher = &Matcher{Index: c.Index}
	}
	in := MatchInput{AssetID: asset.ID, SoftwareID: sw.ID, Ecosystem: sw.Ecosystem, PackageName: sw.Name, Version: matchVersion(sw), RawVersion: sw.Version}
	matches, err := c.Matcher.Match(ctx, in)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range matches {
		var vuln *domain.Vulnerability
		if m.CVEID != "" {
			vuln, _ = c.Index.CVE(ctx, m.CVEID)
		}
		created, err := c.upsertFinding(ctx, orgID, asset, nil, &sw.ID, m, vuln, nil)
		if err != nil {
			continue
		}
		if created {
			n++
		}
	}
	return n, nil
}

// CorrelateSoftware correlates one software-inventory row that carries a
// product identity (vendor/product/version/CPEs — network fingerprints
// recorded by the scanner) against the CPE index. OS packages route through
// the distro advisory plane first (deterministic, confidence 1.0) and fall
// back to the OSV path only when no advisory data covers the asset's
// release; other ecosystems go to CorrelatePackage/OSV directly.
func (c *Correlator) CorrelateSoftware(ctx context.Context, orgID string, asset *domain.Asset, sw *domain.Software) (int, error) {
	if sw.Name == "" {
		return 0, nil
	}
	if sw.Ecosystem != "" {
		if isOSPackageEcosystem(sw.Ecosystem) && c.Advisories != nil {
			n, handled, err := c.CorrelateOSPackage(ctx, orgID, asset, sw)
			if err != nil {
				c.Log.Warn("advisory correlation failed", "software", sw.ID, "err", err)
			}
			if handled {
				return n, nil
			}
		}
		return c.CorrelatePackage(ctx, orgID, asset, sw)
	}
	if c.Matcher == nil {
		c.Matcher = &Matcher{Index: c.Index}
	}
	in := MatchInput{AssetID: asset.ID, SoftwareID: sw.ID, Vendor: sw.Vendor, Product: sw.Name, Version: matchVersion(sw), RawVersion: sw.Version, CPEs: sw.CPEs}
	matches, err := c.Matcher.Match(ctx, in)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range matches {
		if m.CVEID == "" {
			continue
		}
		vuln, err := c.Index.CVE(ctx, m.CVEID)
		if err != nil || vuln == nil {
			continue
		}
		created, err := c.upsertFinding(ctx, orgID, asset, nil, &sw.ID, m, vuln, nil)
		if err != nil {
			c.Log.Warn("software finding upsert failed", "err", err, "cve", m.CVEID)
			continue
		}
		if created {
			n++
		}
	}
	return n, nil
}

func (c *Correlator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// sweepableService reports whether a service carries enough identity to
// produce meaningful matches. CorrelateService downgrades service_name to a
// heuristic candidate; "unknown" would only generate noise.
func sweepableService(svc *domain.Service) bool {
	norm := strings.ToLower(svc.ServiceName)
	return svc.Product != "" || len(svc.CPEs) > 0 || (norm != "" && norm != "unknown" && norm != "tcpwrapped")
}

// SweepOrg re-correlates every identifiable service and software row of an
// organization against the current index. Called after scan completion
// (scan.result event) and via POST /vulnerabilities/correlate — e.g. right
// after a feed sync brought in new CVE data. Returns the number of findings
// created.
func (c *Correlator) SweepOrg(ctx context.Context, orgID string) (int, error) {
	if c.Services == nil {
		return 0, fmt.Errorf("correlator: services repo not configured")
	}
	svcs, err := c.Services.ListForCorrelation(ctx, orgID, 5000)
	if err != nil {
		return 0, err
	}
	created := 0
	for i := range svcs {
		svc := svcs[i]
		if !sweepableService(&svc) {
			continue
		}
		asset, err := c.Assets.ByID(ctx, orgID, svc.AssetID)
		if err != nil || asset == nil {
			continue
		}
		n, err := c.CorrelateService(ctx, orgID, asset, &svc)
		if err != nil {
			c.Log.Warn("sweep service correlation failed", "service", svc.ID, "err", err)
			continue
		}
		created += n
	}
	created += c.sweepOrgSoftware(ctx, orgID)
	return created, nil
}

// SweepAsset re-correlates every service and software row of ONE asset —
// the "Rediscover" action (POST /assets/:id/rediscover), for when new CVEs
// arrived after the asset's last scan and its discovered software was never
// matched against them. Returns the number of findings created/refreshed.
func (c *Correlator) SweepAsset(ctx context.Context, orgID, assetID string) (int, error) {
	if c.Services == nil {
		return 0, fmt.Errorf("correlator: services repo not configured")
	}
	asset, err := c.Assets.ByID(ctx, orgID, assetID)
	if err != nil || asset == nil {
		return 0, fmt.Errorf("correlator: asset not found in organization")
	}
	created := 0
	svcs, err := c.Services.ListForAsset(ctx, assetID)
	if err != nil {
		return 0, err
	}
	for i := range svcs {
		svc := svcs[i]
		if !sweepableService(&svc) {
			continue
		}
		n, err := c.CorrelateService(ctx, orgID, asset, &svc)
		if err != nil {
			c.Log.Warn("asset sweep service correlation failed", "service", svc.ID, "err", err)
			continue
		}
		created += n
	}
	if c.Software != nil {
		sws, err := c.Software.ListForAsset(ctx, assetID)
		if err != nil {
			c.Log.Warn("asset sweep software load failed", "asset", assetID, "err", err)
			return created, nil
		}
		for i := range sws {
			n, err := c.CorrelateSoftware(ctx, orgID, asset, &sws[i])
			if err != nil {
				c.Log.Warn("asset sweep software correlation failed", "software", sws[i].ID, "err", err)
				continue
			}
			created += n
		}
	}
	return created, nil
}

// sweepOrgSoftware correlates software-inventory rows org-wide (bounded).
func (c *Correlator) sweepOrgSoftware(ctx context.Context, orgID string) int {
	if c.Software == nil {
		return 0
	}
	sws, err := c.Software.AllPackages(ctx, orgID)
	if err != nil {
		c.Log.Warn("sweep software load failed", "org", orgID, "err", err)
		return 0
	}
	created := 0
	for i := range sws {
		sw := sws[i]
		if sw.Name == "" {
			continue
		}
		asset, err := c.Assets.ByID(ctx, orgID, sw.AssetID)
		if err != nil || asset == nil {
			continue
		}
		n, err := c.CorrelateSoftware(ctx, orgID, asset, &sw)
		if err != nil {
			c.Log.Warn("sweep software correlation failed", "software", sw.ID, "err", err)
			continue
		}
		created += n
	}
	return created
}

func (c *Correlator) upsertFinding(ctx context.Context, orgID string, asset *domain.Asset, serviceID, softwareID *string, m Match, vuln *domain.Vulnerability, svc *domain.Service) (bool, error) {
	cveID := m.CVEID
	osvID := m.OSVID
	title := titleFor(m, vuln)

	score, _ := BestSeverity(vuln)
	var epssVal float64
	kev := false
	if vuln != nil {
		if vuln.EPSS != nil {
			epssVal = vuln.EPSS.EPSS
		}
		if vuln.KnownExploited != nil {
			kev = vuln.KnownExploited.KnownExploited
		}
	}

	assetRisk := asset.RiskScore
	internet := asset.Exposure == domain.ExposurePublic
	adminSvc := svc != nil && containsAny(svc.Flags, "admin_exposed", "unexpected_port")
	unenc := svc != nil && containsAny(svc.Flags, "unencrypted")
	if svc != nil && isCommonAdminPort(svc.Port) {
		adminSvc = true
	}

	rin := risk.Inputs{
		CVSSScore: score, HasCVSS: score > 0,
		EPSS: epssVal, KnownExploited: kev,
		InternetExposed: internet, AdminService: adminSvc, Unencrypted: unenc,
		Criticality: asset.Criticality, AssetRisk: assetRisk,
	}
	w := risk.Default()
	rr := risk.Evaluate(rin, w)

	sev := domain.Severity(rr.Severity)
	if sev == domain.SeverityInfo && score > 0 {
		sev = severityFromCVSS(score)
	}

	f := &domain.Finding{
		ID: ids.New(), OrganizationID: orgID,
		AssetID: asset.ID, ServiceID: serviceID, SoftwareID: softwareID,
		CVEID: cveID, OSVID: osvID, Title: title,
		MatchType: m.MatchType, Confidence: m.Confidence,
		RiskScore: rr.Score, Severity: sev, Status: domain.FindingOpen,
		Remediation: firstNonEmptyStr(m.Remediation, remediationFor(vuln, svc)),
		FirstSeen:   c.now(), LastSeen: c.now(),
		CreatedAt: c.now(), UpdatedAt: c.now(),
	}
	if err := c.Findings.Upsert(ctx, f); err != nil {
		return false, err
	}

	// Evidence chain: structured, not just a sentence.
	evs := []domain.Evidence{{
		ID: ids.New(), FindingID: f.ID, Kind: evidenceKind(m.MatchType),
		Statement: m.Reason, Detail: m.Evidence, Source: domain.SourceHeuristic, CreatedAt: c.now(),
	}}
	if vuln != nil && len(vuln.CPEMatches) > 0 {
		evs = append(evs, domain.Evidence{ID: ids.New(), FindingID: f.ID, Kind: "cpe_match",
			Statement: "CPE matched " + vuln.CPEMatches[0].CPE, Source: domain.SourceFeed, CreatedAt: c.now()})
	}
	if svc != nil && svc.Banner != "" {
		evs = append(evs, domain.Evidence{ID: ids.New(), FindingID: f.ID, Kind: "banner",
			Statement: "Service banner observed (redacted)", Detail: map[string]any{"banner": redactSecrets(svc.Banner)}, Source: domain.SourceBanner, CreatedAt: c.now()})
	}
	for _, ev := range evs {
		_ = c.Evidence.Insert(ctx, &ev)
	}

	// Explanation requirement: store a transparent reason on the asset
	// risk roll-up happens in the worker; here we log for ops.
	c.Log.Debug("finding scored", "cve", cveID, "risk", rr.Score, "explain", risk.Explain(rr))
	return true, nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func titleFor(m Match, vuln *domain.Vulnerability) string {
	if vuln != nil && vuln.Description != "" {
		d := vuln.Description
		if len(d) > 140 {
			d = d[:140] + "…"
		}
		return d
	}
	if m.CVEID != "" {
		return "Potential vulnerability " + m.CVEID
	}
	return "Advisory match " + m.OSVID
}

func remediationFor(vuln *domain.Vulnerability, svc *domain.Service) string {
	if vuln == nil {
		return ""
	}
	var b strings.Builder
	if len(vuln.References) > 0 {
		fmt.Fprintf(&b, "Review advisory: %s", vuln.References[0])
	}
	if svc != nil && svc.DetectedVersion != "" {
		fmt.Fprintf(&b, " Detected version %s — upgrade to a fixed release once identified; do not rely on banner-derived versions alone.", svc.DetectedVersion)
	}
	return b.String()
}

func evidenceKind(mt domain.MatchType) string {
	switch mt {
	case domain.MatchExactCPE, domain.MatchCPERange:
		return "cpe_match"
	case domain.MatchPackageVersion:
		return "agent_package"
	case domain.MatchOSPackage:
		return "os_advisory"
	case domain.MatchServiceVersion:
		return "nmap_service"
	default:
		return "heuristic"
	}
}

func severityFromCVSS(s float64) domain.Severity {
	switch {
	case s >= 9:
		return domain.SeverityCritical
	case s >= 7:
		return domain.SeverityHigh
	case s >= 4:
		return domain.SeverityMedium
	case s > 0:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}

func isCommonAdminPort(p int) bool {
	switch p {
	case 22, 23, 3389, 5900, 5901, 8443, 9090, 10000, 8080, 8006, 4444, 5985, 5986:
		return true
	}
	return false
}

func containsAny(xs []string, want ...string) bool {
	for _, x := range xs {
		for _, w := range want {
			if x == w {
				return true
			}
		}
	}
	return false
}

// redactSecrets strips obvious credential-looking values from banner text
// before storage/display.
func redactSecrets(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		l := strings.ToLower(f)
		if strings.HasPrefix(l, "password=") || strings.HasPrefix(l, "token=") || strings.HasPrefix(l, "authorization:") || strings.HasPrefix(l, "api_key=") {
			fields[i] = f[:strings.IndexByte(f, '=')+1] + "[REDACTED]"
		}
	}
	return strings.Join(fields, " ")
}
