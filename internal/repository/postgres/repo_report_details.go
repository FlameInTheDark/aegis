package postgres

import (
	"context"
	"fmt"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/Masterminds/squirrel"
)

// ReportDeviceRecords is the typed current-state inventory exported for one
// authorized device. Services include all states; scans require an explicit
// scan_changes asset association (IP-based historical attribution is unsafe).
type ReportDeviceRecords struct {
	Asset       domain.Asset        `json:"asset"`
	Identifiers []domain.Identifier `json:"identifiers"`
	Interfaces  []domain.Interface  `json:"interfaces"`
	Services    []domain.Service    `json:"services"`
	Software    []domain.Software   `json:"software"`
	Findings    []domain.Finding    `json:"findings"`
	Evidence    []domain.Evidence   `json:"evidence"`
	Scans       []domain.Scan       `json:"scans"`
}

// ReportDetailRepo provides unpaginated tenant-scoped reporting queries. It
// deliberately does not reuse UI list methods with implicit maximum limits.
type ReportDetailRepo struct{ db *DB }

// NewReportDetailRepo constructs a read-only report detail repository.
func NewReportDetailRepo(db *DB) *ReportDetailRepo { return &ReportDetailRepo{db: db} }

// Organization loads the requested report tenant.
func (r *ReportDetailRepo) Organization(ctx context.Context, orgID string) (*domain.Organization, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization is required")
	}
	return NewOrgRepo(r.db).ByID(ctx, orgID)
}

// Site validates tenant ownership before any site subordinate queries.
func (r *ReportDetailRepo) Site(ctx context.Context, orgID, siteID string) (*domain.Site, error) {
	if orgID == "" || siteID == "" {
		return nil, fmt.Errorf("organization and site are required")
	}
	return NewSiteRepo(r.db).ByID(ctx, orgID, siteID)
}

// Asset validates tenant ownership before any asset subordinate queries.
func (r *ReportDetailRepo) Asset(ctx context.Context, orgID, assetID string) (*domain.Asset, error) {
	if orgID == "" || assetID == "" {
		return nil, fmt.Errorf("organization and device are required")
	}
	return NewAssetRepo(r.db).ByID(ctx, orgID, assetID)
}

// Inventory returns all current site assets after validating its tenant.
func (r *ReportDetailRepo) Inventory(ctx context.Context, orgID, siteID string) ([]domain.Asset, error) {
	if _, err := r.Site(ctx, orgID, siteID); err != nil {
		return nil, fmt.Errorf("authorize site inventory: %w", err)
	}
	return NewAssetRepo(r.db).Inventory(ctx, orgID, siteID)
}

// Networks returns all configured networks in the authorized site.
func (r *ReportDetailRepo) Networks(ctx context.Context, orgID, siteID string) ([]domain.Network, error) {
	if _, err := r.Site(ctx, orgID, siteID); err != nil {
		return nil, fmt.Errorf("authorize site networks: %w", err)
	}
	q := r.db.Select(netCols).From("networks").Where(squirrel.Eq{"organization_id": orgID, "site_id": siteID}).OrderBy("id")
	return reportRows(ctx, r.db, q, func(row scanner) (*domain.Network, error) { return scanNetwork(row) })
}

// Scans returns every scan record belonging to the authorized site.
func (r *ReportDetailRepo) Scans(ctx context.Context, orgID, siteID string) ([]domain.Scan, error) {
	if _, err := r.Site(ctx, orgID, siteID); err != nil {
		return nil, fmt.Errorf("authorize site scans: %w", err)
	}
	q := r.db.Select(scanCols).From("scans").Where(squirrel.Eq{"organization_id": orgID, "site_id": siteID}).OrderBy("created_at", "id")
	return reportRows(ctx, r.db, q, scanScan)
}

// Device validates the asset before reading its subordinate records. All
// queries are uncapped; each failure aborts the export rather than hiding data.
func (r *ReportDetailRepo) Device(ctx context.Context, orgID, assetID string) (*ReportDeviceRecords, error) {
	asset, err := r.Asset(ctx, orgID, assetID)
	if err != nil {
		return nil, fmt.Errorf("authorize report device: %w", err)
	}
	out := &ReportDeviceRecords{Asset: *asset, Evidence: []domain.Evidence{}}
	out.Identifiers, err = NewIdentifierRepo(r.db).ListForAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("load device identifiers: %w", err)
	}
	out.Interfaces, err = r.interfaces(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("load device interfaces: %w", err)
	}
	// Unlike ServiceRepo.ListForAsset, do not filter out closed/filtered states.
	out.Services, err = reportRows(ctx, r.db, r.db.Select(serviceCols).From("services").Where(squirrel.Eq{"organization_id": orgID, "asset_id": assetID}).OrderBy("protocol", "port", "id"), scanService)
	if err != nil {
		return nil, fmt.Errorf("load device services: %w", err)
	}
	out.Software, err = NewSoftwareRepo(r.db).ListForAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("load device software: %w", err)
	}
	out.Findings, err = reportRows(ctx, r.db, r.db.Select(findingCols).From("findings f"+findingJoins).Where(squirrel.Eq{"f.organization_id": orgID, "f.asset_id": assetID}).OrderBy("f.id"), scanFinding)
	if err != nil {
		return nil, fmt.Errorf("load device findings: %w", err)
	}
	for _, f := range out.Findings {
		evidence, err := NewEvidenceRepo(r.db).ListForFinding(ctx, f.ID)
		if err != nil {
			return nil, fmt.Errorf("load finding evidence: %w", err)
		}
		out.Evidence = append(out.Evidence, evidence...)
	}
	q := r.db.Select(scanCols).From("scans").Where(squirrel.Eq{"organization_id": orgID, "site_id": asset.SiteID}).
		Where(squirrel.Expr("EXISTS (SELECT 1 FROM scan_changes c WHERE c.scan_id = scans.id AND c.site_id = scans.site_id AND c.asset_id = ?)", assetID)).OrderBy("created_at", "id")
	out.Scans, err = reportRows(ctx, r.db, q, scanScan)
	if err != nil {
		return nil, fmt.Errorf("load device scans: %w", err)
	}
	return out, nil
}

// interfaces closes the parent cursor before loading addresses and propagates
// each child cursor's terminal error (the UI repository omits that check).
func (r *ReportDetailRepo) interfaces(ctx context.Context, assetID string) ([]domain.Interface, error) {
	q := r.db.Select("id, asset_id, mac, name, vlan_id, mtu, speed_mbps, status, first_seen, last_seen").From("network_interfaces").Where(squirrel.Eq{"asset_id": assetID}).OrderBy("id")
	out, err := reportRows(ctx, r.db, q, func(row scanner) (*domain.Interface, error) {
		var i domain.Interface
		err := row.Scan(&i.ID, &i.AssetID, &i.MAC, &i.Name, &i.VLANID, &i.MTU, &i.SpeedMbps, &i.Status, &i.FirstSeen, &i.LastSeen)
		return &i, err
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		q := r.db.Select("host(ip) AS ip, is_primary, first_seen, last_seen").From("ip_addresses").Where(squirrel.Eq{"interface_id": out[i].ID}).OrderBy("ip")
		out[i].Addresses, err = reportRows(ctx, r.db, q, func(row scanner) (*domain.IPObservation, error) {
			var ip domain.IPObservation
			err := row.Scan(&ip.IP, &ip.IsPrimary, &ip.FirstSeen, &ip.LastSeen)
			return &ip, err
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func reportRows[T any](ctx context.Context, db *DB, q squirrel.Sqlizer, scan func(scanner) (*T, error)) ([]T, error) {
	rows, err := db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]T, 0)
	for rows.Next() {
		value, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
