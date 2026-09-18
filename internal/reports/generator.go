// Package reports implements report generation (spec §50/§138): report
// definitions are separate from jobs; artifacts are stored in object
// storage and served via presigned URLs. Formats: PDF (print-ready HTML
// rendered to PDF by the UI/browser or wkhtml-like path), HTML, CSV, JSON.
package reports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service generates reports.
type Service struct {
	Reports  *pg.ReportRepo
	Findings *pg.FindingRepo
	Assets   *pg.AssetRepo
	Sites    *pg.SiteRepo
	Orgs     *pg.OrgRepo
	Services *pg.ServiceRepo
	Scans    *pg.ScanRepo
	Vulns    *pg.VulnRepo
	Store    *platform.ObjectStore
	Log      *slog.Logger
	Details  DetailSource
}

// Types of reports (§50) — aliases over the domain enum.
const (
	TypeExecutive      = domain.ReportExecutive
	TypeTechnical      = domain.ReportTechnical
	TypeInventory      = domain.ReportInventory
	TypeScanComparison = domain.ReportScanDiff
	TypeEventSummary   = domain.ReportSecurityEvts
)

// RunJob executes one report job: gather → render → store.
func (s *Service) RunJob(ctx context.Context, orgID, jobID string) {
	job, err := s.Reports.Job(ctx, orgID, jobID)
	if err != nil {
		s.Log.Error("report job not found", "job", jobID, "err", err)
		return
	}
	def, err := s.Reports.Definition(ctx, orgID, job.Definition)
	if err != nil {
		s.fail(ctx, job, "report definition missing")
		return
	}
	job.State = "running"
	job.Progress = 10
	_ = s.Reports.UpdateJob(ctx, job)

	data, err := s.gather(ctx, orgID, def)
	if err != nil {
		s.fail(ctx, job, "data gathering failed: "+err.Error())
		return
	}
	job.Progress = 50
	_ = s.Reports.UpdateJob(ctx, job)

	var (
		artifact []byte
		ctype    string
	)
	switch def.Format {
	case domain.ReportCSV:
		artifact, ctype, err = renderCSV(data)
	case domain.ReportJSON:
		artifact, ctype, err = renderJSON(data)
	case domain.ReportPDF:
		artifact, ctype, err = renderPDF(data)
	case domain.ReportHTML:
		artifact, ctype, err = renderHTML(data)
	default:
		err = fmt.Errorf("unsupported format %q", def.Format)
	}
	if err != nil {
		s.fail(ctx, job, "render failed: "+err.Error())
		return
	}

	key := fmt.Sprintf("reports/%s/%s.%s", orgID, job.ID, strings.ToLower(string(def.Format)))
	if s.Store == nil {
		// Never mark a job completed when its artifact cannot be stored —
		// the download endpoint would 500 on a missing object. Fail the
		// job with an honest, actionable message instead.
		s.fail(ctx, job, "report artifact storage is not configured (AEGIS_S3_ENDPOINT); ask your administrator to enable object storage for report exports")
		return
	}
	if err := s.Store.Put(ctx, key, artifact, ctype); err != nil {
		s.fail(ctx, job, "artifact store failed: "+err.Error())
		return
	}
	job.State = "completed"
	job.Progress = 100
	job.ArtifactKey = key
	job.SizeBytes = int64(len(artifact))
	now := time.Now().UTC()
	job.FinishedAt = &now
	_ = s.Reports.UpdateJob(ctx, job)
	s.Log.Info("report generated", "job", job.ID, "type", def.Type, "format", def.Format, "bytes", len(artifact))
}

func (s *Service) fail(ctx context.Context, job *domain.ReportJob, msg string) {
	job.State = "failed"
	job.Error = msg
	_ = s.Reports.UpdateJob(ctx, job)
	s.Log.Error("report job failed", "job", job.ID, "err", msg)
}

// reportData is the intermediate model shared by renderers.
type reportData struct {
	Title            string           `json:"title"`
	Type             string           `json:"type"`
	OrgID            string           `json:"organization_id"`
	SiteID           string           `json:"site_id,omitempty"`
	GeneratedAt      time.Time        `json:"generated_at"`
	Scope            string           `json:"scope"`
	OrgLabel         string           `json:"organization_name"`
	SiteLabel        string           `json:"site_name,omitempty"`
	OpenPortsByAsset map[string]int   `json:"open_ports_by_asset"`
	Summary          map[string]any   `json:"summary"`
	Findings         []domain.Finding `json:"findings"`
	Assets           []domain.Asset   `json:"assets,omitempty"`
	Scans            []domain.Scan    `json:"scans,omitempty"`
	Recommendations  []string         `json:"recommendations,omitempty"`
	AssetID          string           `json:"asset_id,omitempty"`
	Details          *ReportDetails   `json:"details,omitempty"`
}

func (s *Service) gather(ctx context.Context, orgID string, def *domain.ReportDefinition) (*reportData, error) {
	if def.Type == domain.ReportSiteDetail || def.Type == domain.ReportDeviceDetail {
		return s.gatherDetail(ctx, orgID, def)
	}
	data := &reportData{
		Title:       titleFor(def),
		Type:        string(def.Type),
		OrgID:       orgID,
		SiteID:      def.SiteID,
		GeneratedAt: time.Now().UTC(),
		Summary:     map[string]any{},
	}
	if s.Orgs == nil || s.Services == nil {
		return nil, fmt.Errorf("report organization/service repositories are not configured")
	}
	org, err := s.Orgs.ByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("load report organization: %w", err)
	}
	data.OrgLabel = org.Name
	if def.SiteID != "" {
		site, err := s.Sites.ByID(ctx, orgID, def.SiteID)
		if err != nil {
			return nil, fmt.Errorf("load report site: %w", err)
		}
		data.SiteLabel = site.Name
	}
	fFilter := pg.FindingFilter{OrgID: orgID, SiteID: def.SiteID, Limit: 500}
	if def.MinSeverity != "" {
		fFilter.Severity = string(def.MinSeverity)
	}
	findings, total, err := s.Findings.List(ctx, fFilter)
	if err != nil {
		return nil, err
	}
	data.Findings = findings
	data.Summary["total_findings"] = total
	bySev := map[string]int{}
	kev := 0
	for _, f := range findings {
		bySev[string(f.Severity)]++
		if f.CVEID != "" && isKEV(ctx, s, f.CVEID) {
			kev++
		}
	}
	data.Summary["by_severity"] = bySev
	data.Summary["kev"] = kev

	if def.Type == TypeInventory || def.Type == TypeExecutive {
		assets, err := s.Assets.Inventory(ctx, orgID, def.SiteID)
		if err != nil {
			return nil, fmt.Errorf("load report inventory: %w", err)
		}
		counts, err := s.Services.OpenPortCounts(ctx, orgID, def.SiteID)
		if err != nil {
			return nil, fmt.Errorf("load report port counts: %w", err)
		}
		data.Assets = assets
		data.OpenPortsByAsset = counts
		data.Summary["assets"] = len(assets)
		totalPorts := 0
		for _, a := range assets {
			totalPorts += counts[a.ID]
		}
		data.Summary["open_ports"] = totalPorts
	}
	if def.Type == TypeScanComparison && def.ScanID != "" {
		scan, err := s.Scans.ByID(ctx, orgID, def.ScanID)
		if err == nil {
			data.Scans = append(data.Scans, *scan)
		}
	}
	data.Recommendations = recommendations(data)
	return data, nil
}

func isKEV(ctx context.Context, s *Service, cve string) bool {
	if cve == "" || s.Vulns == nil {
		return false
	}
	kevSet, err := s.Vulns.KEVSet(ctx)
	if err != nil {
		return false
	}
	return kevSet[cve]
}

func titleFor(def *domain.ReportDefinition) string {
	switch def.Type {
	case TypeExecutive:
		return "Executive Security Report"
	case TypeTechnical:
		return "Technical Vulnerability Report"
	case TypeInventory:
		return "Network Inventory Report"
	case TypeScanComparison:
		return "Scan Comparison Report"
	case TypeEventSummary:
		return "Security Event Report"
	case domain.ReportSiteDetail:
		return "Site Detail Report"
	case domain.ReportDeviceDetail:
		return "Device Detail Report"
	default:
		return "Security Report"
	}
}

// recommendations derives plain, evidence-based recommendations (§50).
func recommendations(d *reportData) []string {
	var out []string
	crit := d.Summary["by_severity"].(map[string]int)
	if crit["critical"] > 0 {
		out = append(out, fmt.Sprintf("Remediate %d critical finding(s) first; %d are listed as known exploited.", crit["critical"], d.Summary["kev"]))
	}
	if crit["high"] > 0 {
		out = append(out, fmt.Sprintf("Schedule remediation for %d high-severity finding(s) within the next maintenance window.", crit["high"]))
	}
	if n, ok := d.Summary["assets"].(int); ok && n > 0 {
		unagented := 0
		for _, a := range d.Assets {
			if !a.HasAgent {
				unagented++
			}
		}
		if unagented > 0 {
			out = append(out, fmt.Sprintf("%d of %d assets lack endpoint visibility — deploy agents to close blind spots.", unagented, n))
		}
	}
	if len(out) == 0 {
		out = append(out, "No critical findings in the selected scope; continue scheduled scans and feed syncs to maintain coverage.")
	}
	return out
}

// ---------------------------------------------------------------------------
// Renderers

func renderJSON(d *reportData) ([]byte, string, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	return b, "application/json", err
}

func renderCSV(d *reportData) ([]byte, string, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if d.Type == string(TypeInventory) {
		_ = w.Write([]string{"asset_id", "hostname", "device_type", "os", "exposure", "criticality", "risk", "last_seen"})
		for _, a := range d.Assets {
			_ = w.Write([]string{a.ID, a.Hostname, string(a.DeviceType), a.OSName, string(a.Exposure), string(a.Criticality), fmt.Sprintf("%.0f", a.RiskScore), a.LastSeen.Format(time.RFC3339)})
		}
	} else {
		_ = w.Write([]string{"finding_id", "asset_id", "cve", "title", "severity", "risk", "status", "first_seen", "last_seen"})
		for _, f := range d.Findings {
			_ = w.Write([]string{f.ID, f.AssetID, f.CVEID, sanitizeCSV(f.Title), string(f.Severity), fmt.Sprintf("%.0f", f.RiskScore), string(f.Status), f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339)})
		}
	}
	w.Flush()
	return []byte(b.String()), "text/csv", w.Error()
}

// sanitizeCSV prevents formula injection in spreadsheet consumers (§146).
func sanitizeCSV(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' {
		return "'" + s
	}
	return s
}

var reportTmpl = template.Must(template.New("report").Parse(reportHTML))

func renderHTML(d *reportData) ([]byte, string, error) {
	// Sort findings by risk desc for readability.
	sort.SliceStable(d.Findings, func(i, j int) bool { return d.Findings[i].RiskScore > d.Findings[j].RiskScore })
	var b strings.Builder
	if err := reportTmpl.Execute(&b, d); err != nil {
		return nil, "", err
	}
	return []byte(b.String()), "text/html; charset=utf-8", nil
}

const reportHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:40px;color:#1a1d21;max-width:900px}
 h1{font-size:22px;margin-bottom:4px} h2{font-size:16px;margin-top:28px;border-bottom:1px solid #e5e7eb;padding-bottom:6px}
 .meta{color:#6b7280;font-size:12px;margin-bottom:24px}
 table{border-collapse:collapse;width:100%;font-size:12px}
 th{background:#f3f4f6;text-align:left;padding:6px 8px;border:1px solid #e5e7eb}
 td{padding:6px 8px;border:1px solid #e5e7eb}
 .kpi{display:inline-block;margin-right:24px}.kpi b{font-size:20px}
 .crit{color:#b91c1c;font-weight:600}.high{color:#c2410c;font-weight:600}.med{color:#a16207}
 ul{margin:8px 0}li{margin:4px 0;font-size:13px}
 footer{margin-top:36px;color:#9ca3af;font-size:11px}
</style></head>
<body>
<h1>{{.Title}}</h1>
<div class="meta">Generated {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}} · Organization {{.OrgLabel}}{{if .SiteLabel}} · Site {{.SiteLabel}}{{end}}</div>

<h2>Summary</h2>
<div class="kpi"><b>{{index .Summary "total_findings"}}</b><br>findings</div>
<div class="kpi"><b class="crit">{{index .Summary "kev"}}</b><br>known exploited</div>
{{with $s := .Summary}}{{$sev := index $s "by_severity"}}
<div class="kpi"><b class="crit">{{index $sev "critical"}}</b><br>critical</div>
<div class="kpi"><b class="high">{{index $sev "high"}}</b><br>high</div>
<div class="kpi"><b class="med">{{index $sev "medium"}}</b><br>medium</div>{{end}}
{{if index .Summary "assets"}}<div class="kpi"><b>{{index .Summary "assets"}}</b><br>assets</div>{{end}}

<h2>Recommendations</h2>
<ul>{{range .Recommendations}}<li>{{.}}</li>{{end}}</ul>

{{if .Findings}}
<h2>Findings ({{len .Findings}})</h2>
<table><tr><th>Risk</th><th>Severity</th><th>CVE</th><th>Title</th><th>Status</th><th>Asset</th></tr>
{{range .Findings}}<tr><td>{{printf "%.0f" .RiskScore}}</td><td>{{.Severity}}</td><td>{{.CVEID}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td><code>{{.AssetID}}</code></td></tr>{{end}}
</table>{{end}}

{{if .Assets}}
<h2>Assets ({{len .Assets}})</h2>
<table><tr><th>Hostname</th><th>Type</th><th>OS</th><th>Exposure</th><th>Criticality</th><th>Risk</th><th>Last seen</th></tr>
{{range .Assets}}<tr><td>{{if .Hostname}}{{.Hostname}}{{else}}<code>{{.ID}}</code>{{end}}</td><td>{{.DeviceType}}</td><td>{{.OSName}}</td><td>{{.Exposure}}</td><td>{{.Criticality}}</td><td>{{printf "%.0f" .RiskScore}}</td><td>{{.LastSeen.Format "2006-01-02"}}</td></tr>{{end}}
</table>{{end}}

<footer>Aegis Security Platform — report includes only data visible to the requesting organization. Risk scores are explainable composites, not raw CVSS.</footer>
</body></html>`

// CreateDefinition registers a new report definition + queued job.
func (s *Service) CreateDefinition(ctx context.Context, orgID, createdBy string, typ domain.ReportType, format domain.ReportFormat, siteID, assetID, scanID string, minSev domain.Severity) (*domain.ReportDefinition, *domain.ReportJob, error) {
	def := &domain.ReportDefinition{
		ID: ids.New(), OrganizationID: orgID, Name: titleFor(&domain.ReportDefinition{Type: typ}),
		Type: typ, Format: format, SiteID: siteID, AssetID: assetID, ScanID: scanID,
		MinSeverity: minSev, CreatedBy: createdBy, CreatedAt: time.Now().UTC(),
	}
	_ = def.Name
	if err := s.Reports.Create(ctx, def); err != nil {
		return nil, nil, err
	}
	job := &domain.ReportJob{
		ID: ids.New(), OrgID: orgID, Definition: def.ID,
		State: "queued", Progress: 0, CreatedAt: time.Now().UTC(),
	}
	if err := s.Reports.CreateJob(ctx, job); err != nil {
		return nil, nil, err
	}
	return def, job, nil
}
