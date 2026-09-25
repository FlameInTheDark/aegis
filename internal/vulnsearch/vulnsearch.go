// Package vulnsearch implements tenant-configurable local vulnerability
// search actions: declarative plans over the synchronized local indexes
// (NVD/CVE List CPE data, OSV, OVAL). An action can never call an external
// provider, mutate feed data directly or execute anything — it selects
// targets by field matching, runs the standard local matcher and records
// per-match provenance. Sources are an allowlist; any URL, command or SQL
// construct is rejected at validation time.
package vulnsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
)

// Bounds for the selector DSL.
const (
	maxConditions = 10
	maxValues     = 50
	maxValueLen   = 120
	targetCap     = 500 // hard cap per run/preview
)

// Selector condition fields and operators (deliberately narrower than the
// alert condition DSL: these match inventory rows, not events).
var allowedFields = map[string]bool{
	"name": true, "vendor": true, "product": true,
	"ecosystem": true, "version": true, "source": true,
}
var allowedOps = map[string]bool{"eq": true, "in": true, "not_in": true, "contains": true, "starts_with": true}
var allowedSources = map[string]bool{
	domain.VulnSourceCPE: true, domain.VulnSourceCVEAffected: true,
	domain.VulnSourceOSV: true, domain.VulnSourceOVAL: true,
}

// SelectorCond is one field condition.
type SelectorCond struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// Selector is the target selector tree.
type Selector struct {
	All []SelectorCond `json:"all"`
	Any []SelectorCond `json:"any"`
}

// Query is one declared local source query in the action document. The
// executor runs the standard matcher over the target identity; the query
// list documents intent and constrains provenance attribution.
type Query struct {
	Source      string `json:"source"`
	Part        string `json:"part,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Product     string `json:"product,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	PackageName string `json:"package_name,omitempty"`
}

// Document is the canonical action definition (mirrors the stored action).
type Document struct {
	Selector      Selector `json:"selector"`
	Queries       []Query  `json:"queries,omitempty"`
	VersionPolicy struct {
		Input      string `json:"input,omitempty"`
		Projection string `json:"projection,omitempty"`
	} `json:"version_policy,omitempty"`
}

// Service executes previews and runs for search actions.
type Service struct {
	DB       *pg.DB
	Actions  *pg.VulnSearchRepo
	Index    vulnerabilities.Index
	Matcher  *vulnerabilities.Matcher
	Findings vulnerabilities.FindingStore
	Services *pg.ServiceRepo
	Software *pg.SoftwareRepo
}

// ParseSelector decodes and validates the selector JSON.
func ParseSelector(raw json.RawMessage) (*Selector, error) {
	var s Selector
	if len(raw) == 0 {
		return nil, fmt.Errorf("selector is required")
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("selector: invalid JSON")
	}
	if err := validateConds(s.All); err != nil {
		return nil, err
	}
	if err := validateConds(s.Any); err != nil {
		return nil, err
	}
	if len(s.All) == 0 && len(s.Any) == 0 {
		return nil, fmt.Errorf("selector needs at least one condition")
	}
	return &s, nil
}

func validateConds(conds []SelectorCond) error {
	if len(conds) > maxConditions {
		return fmt.Errorf("selector: more than %d conditions", maxConditions)
	}
	for _, c := range conds {
		if !allowedFields[c.Field] {
			return fmt.Errorf("selector: unknown field %q", c.Field)
		}
		if !allowedOps[c.Op] {
			return fmt.Errorf("selector: unknown operator %q", c.Op)
		}
		if len(c.Values) == 0 || len(c.Values) > maxValues {
			return fmt.Errorf("selector: %s needs 1-%d values", c.Op, maxValues)
		}
		for _, v := range c.Values {
			if len(v) > maxValueLen {
				return fmt.Errorf("selector: value longer than %d characters", maxValueLen)
			}
		}
	}
	return nil
}

// ValidateAction validates the full action document.
func ValidateAction(a *domain.VulnSearchAction) error {
	if a.Name == "" || len(a.Name) > 120 {
		return fmt.Errorf("name must be 1-120 characters")
	}
	if a.TargetKind != "software" && a.TargetKind != "service" {
		return fmt.Errorf("target_kind must be software or service")
	}
	switch a.Mode {
	case domain.VulnActionModeShadow, domain.VulnActionModeAugment, domain.VulnActionModeFallbackOnly:
	default:
		return fmt.Errorf("mode must be shadow, augment or fallback_only")
	}
	if a.ConfidenceCap < 0 || a.ConfidenceCap > 1 {
		return fmt.Errorf("confidence_cap must be between 0 and 1")
	}
	if a.Priority < 0 || a.Priority > 1000 {
		return fmt.Errorf("priority must be between 0 and 1000")
	}
	if _, err := ParseSelector(a.Selector); err != nil {
		return err
	}
	// Query sources are an allowlist; anything URL-, command- or SQL-shaped
	// fails simply because it is not one of four local source types.
	var doc Document
	if len(a.Selector) > 0 {
		_ = json.Unmarshal(a.Selector, &doc)
	}
	for _, q := range doc.Queries {
		if !allowedSources[q.Source] {
			return fmt.Errorf("queries: source %q is not an allowed local source (cpe, cve_affected, osv, oval)", q.Source)
		}
	}
	return nil
}

// Target is one inventory row selected by the action.
type Target struct {
	Type      string // service | software
	ID        string
	AssetID   string
	Vendor    string
	Product   string
	Name      string
	Version   string
	Ecosystem string
}

// Matches reports whether the target satisfies the selector.
func (s *Selector) Matches(t Target) bool {
	// `all` over a service OR `any` over a service: field lookup is shared.
	matchList := func(conds []SelectorCond, requireAll bool) bool {
		for _, c := range conds {
			val := fieldOf(t, c.Field)
			ok := condMatches(c, val)
			if requireAll && !ok {
				return false
			}
			if !requireAll && ok {
				return true
			}
		}
		return requireAll
	}
	if len(s.All) > 0 && !matchList(s.All, true) {
		return false
	}
	if len(s.Any) > 0 && !matchList(s.Any, false) {
		return false
	}
	return true
}

func fieldOf(t Target, field string) string {
	switch field {
	case "name":
		return t.Name
	case "vendor":
		return t.Vendor
	case "product":
		return t.Product
	case "ecosystem":
		return t.Ecosystem
	case "version":
		return t.Version
	case "source":
		return ""
	}
	return ""
}

func condMatches(c SelectorCond, val string) bool {
	switch c.Op {
	case "eq":
		return strings.EqualFold(val, c.Values[0])
	case "in":
		for _, v := range c.Values {
			if strings.EqualFold(val, v) {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range c.Values {
			if strings.EqualFold(val, v) {
				return false
			}
		}
		return true
	case "contains":
		for _, v := range c.Values {
			if strings.Contains(strings.ToLower(val), strings.ToLower(v)) {
				return true
			}
		}
		return false
	case "starts_with":
		for _, v := range c.Values {
			if strings.HasPrefix(strings.ToLower(val), strings.ToLower(v)) {
				return true
			}
		}
		return false
	}
	return false
}

// ResolveTargets selects the inventory rows the action applies to.
func (s *Service) ResolveTargets(ctx context.Context, orgID string, a *domain.VulnSearchAction) ([]Target, error) {
	sel, err := ParseSelector(a.Selector)
	if err != nil {
		return nil, err
	}
	var out []Target
	switch a.TargetKind {
	case "software":
		pkgs, err := s.Software.AllPackages(ctx, orgID)
		if err != nil {
			return nil, err
		}
		for _, sw := range pkgs {
			t := Target{Type: "software", ID: sw.ID, AssetID: sw.AssetID, Vendor: sw.Vendor,
				Product: sw.Vendor, Name: sw.Name, Version: sw.Version, Ecosystem: sw.Ecosystem}
			if sel.Matches(t) {
				out = append(out, t)
				if len(out) >= targetCap {
					break
				}
			}
		}
	case "service":
		svcs, err := s.Services.ListForCorrelation(ctx, orgID, targetCap)
		if err != nil {
			return nil, err
		}
		for i := range svcs {
			svc := svcs[i]
			name := svc.Product
			if name == "" {
				name = svc.ServiceName
			}
			t := Target{Type: "service", ID: svc.ID, AssetID: svc.AssetID, Vendor: svc.Vendor,
				Product: svc.Product, Name: name, Version: svc.VersionNorm, Ecosystem: "cpe"}
			if sel.Matches(t) {
				out = append(out, t)
				if len(out) >= targetCap {
					break
				}
			}
		}
	}
	return out, nil
}

// PreviewResult summarizes a preview/run without exposing more than needed.
type PreviewResult struct {
	Targets   int        `json:"targets"`
	Truncated bool       `json:"truncated"`
	Matches   int        `json:"matches"`
	Rows      []MatchRow `json:"rows,omitempty"`
}

// MatchRow is one explainable match.
type MatchRow struct {
	Target     Target  `json:"target"`
	CVEID      string  `json:"cve_id"`
	MatchType  string  `json:"match_type"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// Preview evaluates the action read-only: no findings, no provenance.
func (s *Service) Preview(ctx context.Context, orgID string, a *domain.VulnSearchAction) (*PreviewResult, error) {
	targets, err := s.ResolveTargets(ctx, orgID, a)
	if err != nil {
		return nil, err
	}
	res := &PreviewResult{Targets: len(targets), Truncated: len(targets) >= targetCap}
	if s.Matcher == nil {
		s.Matcher = &vulnerabilities.Matcher{Index: s.Index}
	}
	for _, t := range targets {
		in := matchInputFor(t)
		matches, _, err := s.Matcher.Match(ctx, in)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if m.CVEID == "" {
				continue
			}
			if float64(m.Confidence) > a.ConfidenceCap && a.ConfidenceCap > 0 {
				continue
			}
			res.Matches++
			if len(res.Rows) < 50 {
				res.Rows = append(res.Rows, MatchRow{
					Target: t, CVEID: m.CVEID, MatchType: string(m.MatchType),
					Confidence: float64(m.Confidence), Reason: m.Reason,
				})
			}
		}
	}
	return res, nil
}

// Run executes a durable run: shadow mode records nothing beyond the run
// counters; augment/fallback_only upsert findings and per-match provenance.
// Returns (findings created, matches, targets evaluated).
func (s *Service) Run(ctx context.Context, orgID string, a *domain.VulnSearchAction, run *domain.VulnSearchRun) (int, int, int, error) {
	targets, err := s.ResolveTargets(ctx, orgID, a)
	if err != nil {
		return 0, 0, 0, err
	}
	if s.Matcher == nil {
		s.Matcher = &vulnerabilities.Matcher{Index: s.Index}
	}
	created := 0
	matches := 0
	for _, t := range targets {
		in := matchInputFor(t)
		found, _, err := s.Matcher.Match(ctx, in)
		if err != nil {
			continue
		}
		for _, m := range found {
			if m.CVEID == "" {
				continue
			}
			if float64(m.Confidence) > a.ConfidenceCap && a.ConfidenceCap > 0 {
				continue
			}
			matches++
			if a.Mode == domain.VulnActionModeShadow {
				continue
			}
			f, err := s.upsertFinding(ctx, orgID, a, run, t, m)
			if err != nil {
				continue
			}
			if f != "" {
				created++
				prov := &domain.VulnMatchProvenance{
					OrgID: orgID, FindingID: f, ActionID: a.ID, Revision: a.Revision, RunID: run.ID,
					TargetType: t.Type, TargetID: t.ID, Origin: "configured",
					Source: sourceFor(m), CPEKey: cpeKeyFor(in), MatchType: string(m.MatchType),
					Confidence: float64(m.Confidence), Reason: m.Reason,
				}
				obs, _ := json.Marshal(t)
				prov.ObservedIdentity = obs
				_ = s.Actions.InsertProvenance(ctx, prov)
			}
		}
	}
	return created, matches, len(targets), nil
}

// upsertFinding writes the finding row for one configured match and
// returns the finding id ("" when refreshed).
func (s *Service) upsertFinding(ctx context.Context, orgID string, a *domain.VulnSearchAction, run *domain.VulnSearchRun, t Target, m vulnerabilities.Match) (string, error) {
	vuln, err := s.Index.CVE(ctx, m.CVEID)
	if err != nil || vuln == nil {
		return "", err
	}
	assetID := t.AssetID
	if assetID == "" {
		return "", nil
	}
	var svcID, swID *string
	if t.Type == "service" {
		id := t.ID
		svcID = &id
	} else {
		id := t.ID
		swID = &id
	}
	f := &domain.Finding{
		OrganizationID: orgID, AssetID: assetID,
		ServiceID: svcID, SoftwareID: swID,
		CVEID: m.CVEID, Title: titleFor(m, vuln), MatchType: m.MatchType, Confidence: m.Confidence,
		Severity: severityFor(vuln), Status: domain.FindingOpen,
		Remediation: m.Remediation,
	}
	created, err := s.Findings.Upsert(ctx, f)
	if err != nil {
		return "", err
	}
	if !created {
		return "", nil
	}
	return f.ID, nil
}

func matchInputFor(t Target) vulnerabilities.MatchInput {
	in := vulnerabilities.MatchInput{
		AssetID:     t.AssetID,
		ServiceID:   orEmpty(t.Type == "service", t.ID),
		SoftwareID:  orEmpty(t.Type == "software", t.ID),
		Vendor:      t.Vendor,
		Product:     t.Product,
		Version:     t.Version,
		Ecosystem:   t.Ecosystem,
		PackageName: t.Name,
	}
	if in.Product == "" {
		in.Product = t.Name
	}
	return in
}

func orEmpty(cond bool, v string) string {
	if cond {
		return v
	}
	return ""
}

func sourceFor(m vulnerabilities.Match) string {
	switch m.MatchType {
	case domain.MatchExactCPE, domain.MatchCPERange:
		return domain.VulnSourceCPE
	case domain.MatchOSPackage, domain.MatchPackageVersion, domain.MatchServiceVersion:
		return domain.VulnSourceCVEAffected
	default:
		return domain.VulnSourceCVEAffected
	}
}

func cpeKeyFor(in vulnerabilities.MatchInput) string {
	if in.CPEs != nil || in.Vendor == "" {
		return ""
	}
	return "cpe:2.3:a:" + strings.ToLower(in.Vendor) + ":" + strings.ToLower(in.Product) + ":*:*:*:*:*:*:*:*"
}

func titleFor(m vulnerabilities.Match, vuln *domain.Vulnerability) string {
	if vuln != nil && vuln.Description != "" {
		runes := []rune(vuln.Description)
		if len(runes) > 120 {
			return m.CVEID + ": " + string(runes[:120]) + "..."
		}
		return m.CVEID + ": " + vuln.Description
	}
	return m.CVEID
}

func severityFor(vuln *domain.Vulnerability) domain.Severity {
	if vuln == nil {
		return domain.SeverityMedium
	}
	score := 0.0
	for _, c := range []*domain.CVSS{vuln.CVSSv3, vuln.CVSSv4, vuln.CVSSv2} {
		if c != nil && c.Score > score {
			score = c.Score
		}
	}
	switch {
	case score >= 9:
		return domain.SeverityCritical
	case score >= 7:
		return domain.SeverityHigh
	case score >= 4:
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

// MatchInputOf builds a matcher input from an ad-hoc observed identity
// (the workbench's match/search endpoint).
func MatchInputOf(vendor, product, name, version, rawVersion, ecosystem string, cpes []string) vulnerabilities.MatchInput {
	in := vulnerabilities.MatchInput{
		Vendor:     vendor,
		Product:    product,
		Version:    version,
		RawVersion: rawVersion,
		Ecosystem:  ecosystem,
		CPEs:       cpes,
	}
	if in.Product == "" {
		in.Product = name
	}
	if in.PackageName == "" {
		in.PackageName = name
	}
	return in
}

// Match evaluates one identity and maps the results to explainable rows.
func (s *Service) Match(ctx context.Context, orgID string, in vulnerabilities.MatchInput) ([]MatchRow, bool, error) {
	if s.Matcher == nil {
		s.Matcher = &vulnerabilities.Matcher{Index: s.Index}
	}
	found, truncated, err := s.Matcher.Match(ctx, in)
	if err != nil {
		return nil, false, err
	}
	rows := make([]MatchRow, 0, len(found))
	for _, m := range found {
		if m.CVEID == "" {
			continue
		}
		rows = append(rows, MatchRow{
			CVEID: m.CVEID, MatchType: string(m.MatchType),
			Confidence: float64(m.Confidence), Reason: m.Reason,
		})
	}
	return rows, truncated, nil
}
