package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// DetailSource supplies report snapshots. Implementations must enforce tenant
// scope even when a caller has already validated the parent site or device.
type DetailSource interface {
	Organization(context.Context, string) (*domain.Organization, error)
	Site(context.Context, string, string) (*domain.Site, error)
	Asset(context.Context, string, string) (*domain.Asset, error)
	Inventory(context.Context, string, string) ([]domain.Asset, error)
	Networks(context.Context, string, string) ([]domain.Network, error)
	Device(context.Context, string, string) (*pg.ReportDeviceRecords, error)
	Scans(context.Context, string, string) ([]domain.Scan, error)
}

// DeviceDetails is the reusable typed device snapshot consumed by detail
// renderers. Machine identifiers are retained for JSON linking, not labels.
type DeviceDetails struct {
	pg.ReportDeviceRecords
}

// ReportDetails documents the precise coverage of a detail export; it is not
// a claim to export every table or telemetry backend in the platform.
type ReportDetails struct {
	Site     *domain.Site     `json:"site"`
	Networks []domain.Network `json:"networks"`
	Devices  []DeviceDetails  `json:"devices"`
	Scans    []domain.Scan    `json:"scans"`
	Coverage []string         `json:"coverage"`
	Omitted  []string         `json:"omitted"`
}

func (s *Service) gatherDetail(ctx context.Context, orgID string, def *domain.ReportDefinition) (*reportData, error) {
	if orgID == "" || (def.OrganizationID != "" && def.OrganizationID != orgID) {
		return nil, fmt.Errorf("report organization scope is invalid")
	}
	if s.Details == nil {
		return nil, fmt.Errorf("report detail repository is not configured")
	}
	if def.Type == domain.ReportSiteDetail && def.SiteID == "" {
		return nil, fmt.Errorf("site detail requires a site")
	}
	if def.Type == domain.ReportSiteDetail && def.AssetID != "" {
		return nil, fmt.Errorf("site detail does not support a device filter")
	}
	if def.Type == domain.ReportDeviceDetail && def.AssetID == "" {
		return nil, fmt.Errorf("device detail requires a device")
	}
	// Detail reports describe current stored inventory, not a time-windowed or
	// severity-filtered subset. Reject these rather than silently ignore them.
	if def.DateFrom != nil || def.DateTo != nil || def.MinSeverity != "" || def.ScanID != "" || len(def.Sections) > 0 {
		return nil, fmt.Errorf("detail reports do not support date, severity, scan or section filters")
	}
	org, err := s.Details.Organization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("load report organization: %w", err)
	}
	if org == nil || org.ID != orgID {
		return nil, fmt.Errorf("report organization scope is invalid")
	}
	var assets []domain.Asset
	siteID := def.SiteID
	if def.Type == domain.ReportDeviceDetail {
		// This MUST precede device children, site inventory and scan queries.
		asset, err := s.Details.Asset(ctx, orgID, def.AssetID)
		if err != nil {
			return nil, fmt.Errorf("load report device: %w", err)
		}
		if asset == nil || asset.OrganizationID != orgID || asset.ID != def.AssetID || (siteID != "" && asset.SiteID != siteID) {
			return nil, fmt.Errorf("report device is outside the requested scope")
		}
		siteID = asset.SiteID
		assets = []domain.Asset{*asset}
	}
	site, err := s.Details.Site(ctx, orgID, siteID)
	if err != nil {
		return nil, fmt.Errorf("load report site: %w", err)
	}
	if site == nil || site.OrganizationID != orgID || site.ID != siteID {
		return nil, fmt.Errorf("report site is outside the requested scope")
	}
	if def.Type == domain.ReportSiteDetail {
		assets, err = s.Details.Inventory(ctx, orgID, siteID)
		if err != nil {
			return nil, fmt.Errorf("load site inventory: %w", err)
		}
	}
	// Check the entire list before fetching any subordinate records.
	for _, a := range assets {
		if a.OrganizationID != orgID || a.SiteID != siteID {
			return nil, fmt.Errorf("report inventory contains an out-of-scope device")
		}
	}
	details := &ReportDetails{
		Site: site, Networks: []domain.Network{}, Devices: []DeviceDetails{}, Scans: []domain.Scan{},
		Coverage: []string{
			"Current stored asset attributes; identifiers (type, value, weight); interfaces and recorded IP addresses.",
			"All stored service states with banner, TLS, HTTP, version, CPE, confidence and source metadata; software inventory.",
			"All stored device findings and their evidence, without severity or status filtering.",
			"Device scan records are linked only by scan_changes.asset_id; an absent link does not prove a device was never scanned.",
			"Open ports count current open protocol/port endpoints per device, not globally unique port numbers.",
			"Lists are exhaustive and not UI-paginated; separate reads are not an atomic historical snapshot.",
		},
		Omitted: []string{
			"Raw scan observations and task payloads; service/software observation history and scan scopes/change bodies.",
			"Endpoint processes/events/posture, agent tasks, detections, topology, audit log, separate analyst notes and vulnerability-feed enrichment.",
			"Identifier creation timestamps are not exposed by the identifier repository. KEV enrichment is not computed.",
		},
	}
	data := &reportData{Title: titleFor(def), Type: string(def.Type), OrgID: orgID, OrgLabel: org.Name,
		SiteID: siteID, SiteLabel: site.Name, AssetID: def.AssetID, GeneratedAt: time.Now().UTC(),
		Scope: "Current stored inventory", Summary: map[string]any{}, OpenPortsByAsset: map[string]int{},
		Assets: assets, Findings: []domain.Finding{}, Details: details}
	if def.Type == domain.ReportSiteDetail {
		details.Networks, err = s.Details.Networks(ctx, orgID, siteID)
		if err != nil {
			return nil, fmt.Errorf("load site networks: %w", err)
		}
		details.Scans, err = s.Details.Scans(ctx, orgID, siteID)
		if err != nil {
			return nil, fmt.Errorf("load site scans: %w", err)
		}
		details.Coverage = append(details.Coverage, "Site metadata, configured networks and all scan records in the site (including config, stats and lifecycle state).")
	} else {
		details.Coverage = append(details.Coverage, "Parent site metadata; only explicitly device-linked scan records, not all scans from its site.")
		details.Omitted = append(details.Omitted, "Site networks and site-wide scan records are excluded from device detail.")
	}
	severity := map[string]int{}
	totalPorts, assetsWithPorts := 0, 0
	for _, a := range assets {
		records, err := s.Details.Device(ctx, orgID, a.ID)
		if err != nil {
			return nil, fmt.Errorf("load device detail: %w", err)
		}
		if records == nil || records.Asset.ID != a.ID || records.Asset.OrganizationID != orgID || records.Asset.SiteID != siteID {
			return nil, fmt.Errorf("device detail is outside the requested scope")
		}
		ports := 0
		for _, svc := range records.Services {
			if svc.State == "open" {
				ports++
			}
		}
		data.OpenPortsByAsset[a.ID] = ports
		totalPorts += ports
		if ports > 0 {
			assetsWithPorts++
		}
		for _, finding := range records.Findings {
			severity[string(finding.Severity)]++
		}
		data.Findings = append(data.Findings, records.Findings...)
		details.Devices = append(details.Devices, DeviceDetails{ReportDeviceRecords: *records})
		if def.Type == domain.ReportDeviceDetail {
			details.Scans = records.Scans
		}
	}
	data.Scans = details.Scans
	data.Summary["assets"] = len(assets)
	data.Summary["open_ports"] = totalPorts
	data.Summary["assets_with_open_ports"] = assetsWithPorts
	data.Summary["total_findings"] = len(data.Findings)
	data.Summary["by_severity"] = severity
	// Omit KEV instead of reporting a fabricated zero.
	return data, nil
}
