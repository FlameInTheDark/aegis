package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== assets

type AssetRepo struct{ db *DB }

func NewAssetRepo(db *DB) *AssetRepo { return &AssetRepo{db: db} }

const assetCols = `id, organization_id, site_id, hostname, fqdn, vendor, model, serial_number,
device_type, os_family, os_name, os_version, kernel_version, architecture,
os_confidence, os_sources, device_type_confidence, device_type_sources,
exposure, criticality, risk_score, risk_explanation, has_agent, agent_id, tags, owner, notes,
demo_source, first_seen, last_seen, updated_at,
name_override, device_type_override, parent_override,
-- The address this asset currently answers on, used for human-friendly
-- naming when no hostname is known ("Router · 192.168.1.1"). The
-- highest-weighted address wins (an endpoint's reported management address
-- outranks its other NICs), recency breaks ties between equal weights.
COALESCE((SELECT i.value FROM asset_identifiers i WHERE i.asset_id = assets.id AND i.type = 'ip'
 ORDER BY i.weight DESC, i.created_at DESC LIMIT 1), '') AS primary_ip`

func scanAsset(row scanner) (*domain.Asset, error) {
	var a domain.Asset
	err := row.Scan(&a.ID, &a.OrganizationID, &a.SiteID, &a.Hostname, &a.FQDN, &a.Vendor,
		&a.Model, &a.SerialNumber, &a.DeviceType, &a.OSFamily, &a.OSName, &a.OSVersion,
		&a.KernelVersion, &a.Architecture, &a.OSConfidence, &a.OSSources,
		&a.DeviceTypeConf, &a.DeviceTypeSrcs, &a.Exposure, &a.Criticality, &a.RiskScore,
		&a.RiskExplanation, &a.HasAgent, &a.AgentID, &a.Tags, &a.Owner, &a.Notes,
		&a.DemoSource, &a.FirstSeen, &a.LastSeen, &a.UpdatedAt,
		&a.NameOverride, &a.TypeOverride, &a.ParentOverride, &a.PrimaryIP)
	if err != nil {
		return nil, mapNotFound(err)
	}
	// Apply analyst overrides onto the effective fields: every consumer
	// (inventory, topology, search results) sees the corrected value,
	// while the scanned columns stay untouched and the *_override fields
	// still serialize so the UI can badge + reset. NULL = no override.
	if a.NameOverride != nil && *a.NameOverride != "" {
		a.Hostname = *a.NameOverride
	}
	if a.TypeOverride != nil && *a.TypeOverride != "" {
		a.DeviceType = domain.DeviceType(*a.TypeOverride)
	}
	return &a, nil
}

type scanner interface{ Scan(dest ...any) error }

// AssetFilter constrains asset list queries.
type AssetFilter struct {
	OrgID       string
	SiteID      string
	DeviceType  string
	OS          string
	Search      string
	Tags        []string
	HasAgent    *bool
	MinRisk     float64
	Criticality string
	LastSeenIn  time.Duration
	Limit       int
	Page        int
}

func (r *AssetRepo) Insert(ctx context.Context, a *domain.Asset) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	q := r.db.Insert("assets").Columns(
		"id", "organization_id", "site_id", "hostname", "fqdn", "vendor", "model",
		"serial_number", "device_type", "os_family", "os_name", "os_version",
		"kernel_version", "architecture", "os_confidence", "os_sources",
		"device_type_confidence", "device_type_sources", "exposure", "criticality",
		"risk_score", "risk_explanation", "has_agent", "agent_id", "tags", "owner",
		"notes", "demo_source").
		Values(a.ID, a.OrganizationID, a.SiteID, a.Hostname, a.FQDN, a.Vendor, a.Model,
			a.SerialNumber, a.DeviceType, a.OSFamily, a.OSName, a.OSVersion,
			a.KernelVersion, a.Architecture, a.OSConfidence, nonNil(a.OSSources),
			a.DeviceTypeConf, nonNil(a.DeviceTypeSrcs), a.Exposure, a.Criticality,
			a.RiskScore, a.RiskExplanation, a.HasAgent, a.AgentID, nonNil(a.Tags), a.Owner,
			a.Notes, a.DemoSource)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AssetRepo) ByID(ctx context.Context, orgID, id string) (*domain.Asset, error) {
	// Empty orgID means "no org scoping" — the identity resolver looks up
	// by identifier first and checks org membership itself. Filtering
	// with organization_id = '' here made every lookup miss and forced
	// ProvisionHost to fork a new asset on every observation.
	where := squirrel.Eq{"id": id}
	if orgID != "" {
		where["organization_id"] = orgID
	}
	q := r.db.Select(assetCols).From("assets").Where(where)
	return scanAsset(r.db.QueryRow(ctx, q))
}

func (r *AssetRepo) Update(ctx context.Context, orgID, id string, fields map[string]any) error {
	fields["updated_at"] = time.Now().UTC()
	q := r.db.Update("assets")
	for k, v := range fields {
		q = q.Set(k, v)
	}
	// The organization_id predicate is the tenant boundary: a bare id
	// update let any asset:write holder modify another organization's
	// asset (owner, tags, criticality, overrides) by guessing its UUID.
	q = q.Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AssetRepo) TouchSeen(ctx context.Context, id string) error {
	q := r.db.Update("assets").Set("last_seen", time.Now().UTC()).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AssetRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("assets").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AssetRepo) List(ctx context.Context, f AssetFilter) ([]domain.Asset, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	q := r.db.Select(assetCols).From("assets").Where(assetFilterWhere(f))
	rows, err := r.db.Query(ctx, q.OrderBy("risk_score DESC, last_seen DESC").
		Limit(uint64(f.Limit)).Offset(uint64((f.Page-1)*f.Limit)))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	total, err := r.count(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// CountBySite returns asset counts per site id for the whole org — the
// scope dropdown and sites table show them; one aggregate, no N+1.
func (r *AssetRepo) CountBySite(ctx context.Context, orgID string) (map[string]int64, error) {
	q := r.db.Select("site_id::text", "count(*)").From("assets").
		Where(squirrel.Eq{"organization_id": orgID}).
		GroupBy("site_id")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var sid string
		var n int64
		if err := rows.Scan(&sid, &n); err != nil {
			return nil, err
		}
		out[sid] = n
	}
	return out, rows.Err()
}

// assetFilterWhere builds the shared WHERE clause for List and count so
// filtered totals match the rows actually returned (a stale count showed
// "N results" under every filter).
func assetFilterWhere(f AssetFilter) squirrel.Sqlizer {
	where := squirrel.Eq{"organization_id": f.OrgID}
	if f.SiteID != "" {
		where["site_id"] = f.SiteID
	}
	if f.DeviceType != "" {
		where["device_type"] = f.DeviceType
	}
	if f.Criticality != "" {
		where["criticality"] = f.Criticality
	}
	conds := squirrel.And{where}
	if f.MinRisk > 0 {
		conds = append(conds, squirrel.GtOrEq{"risk_score": f.MinRisk})
	}
	if f.OS != "" {
		conds = append(conds, squirrel.ILike{"os_name": "%" + f.OS + "%"})
	}
	if f.Search != "" {
		pat := "%" + escapeLike(f.Search) + "%"
		// Identity fields plus ANY stored identifier (ip, mac, …) —
		// operators type an address into the search box and expect the
		// device to come up.
		conds = append(conds, squirrel.Or{
			squirrel.ILike{"hostname": pat},
			squirrel.ILike{"fqdn": pat},
			squirrel.ILike{"vendor": pat},
			squirrel.ILike{"model": pat},
			squirrel.ILike{"os_name": pat},
			squirrel.Expr(`EXISTS (SELECT 1 FROM asset_identifiers ai WHERE ai.asset_id = assets.id AND ai.value ILIKE ?)`, pat),
		})
	}
	if len(f.Tags) > 0 {
		conds = append(conds, squirrel.Expr("tags @> ?", f.Tags))
	}
	if f.HasAgent != nil {
		conds = append(conds, squirrel.Eq{"has_agent": *f.HasAgent})
	}
	if f.LastSeenIn > 0 {
		conds = append(conds, squirrel.Gt{"last_seen": time.Now().UTC().Add(-f.LastSeenIn)})
	}
	return conds
}

func (r *AssetRepo) count(ctx context.Context, f AssetFilter) (int64, error) {
	q := r.db.Select("count(*)").From("assets").Where(assetFilterWhere(f))
	var n int64
	err := r.db.QueryRow(ctx, q).Scan(&n)
	return n, err
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// Search performs global search across assets, services, software, CVEs.
func (r *AssetRepo) Search(ctx context.Context, orgID, term string, limit int) (*SearchResults, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	pat := "%" + escapeLike(term) + "%"
	res := &SearchResults{Query: term}

	assetQ := r.db.Select("id, COALESCE(name_override, hostname) AS hostname, fqdn, device_type, site_id, risk_score").
		From("assets").
		Where(squirrel.Eq{"organization_id": orgID}).
		Where(squirrel.Or{
			// COALESCE so an overridden asset matches on the name the
			// operator actually sees now, not only the scanned one.
			squirrel.Expr("COALESCE(name_override, hostname) ILIKE ?", pat),
			squirrel.ILike{"fqdn": pat},
			squirrel.ILike{"vendor": pat},
			// Addresses are the number one thing an operator pastes
			// into a search box — match stored identifiers too.
			squirrel.Expr(`EXISTS (SELECT 1 FROM asset_identifiers ai WHERE ai.asset_id = assets.id AND ai.value ILIKE ?)`, pat),
		}).Limit(uint64(limit))
	rows, err := r.db.Query(ctx, assetQ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hit AssetHit
		if err := rows.Scan(&hit.ID, &hit.Label, &hit.FQDN, &hit.DeviceType, &hit.SiteID, &hit.Risk); err != nil {
			return nil, err
		}
		if hit.Label == "" {
			hit.Label = hit.FQDN
		}
		res.Assets = append(res.Assets, hit)
	}
	return res, rows.Err()
}

// SearchResults is the global search response.
type SearchResults struct {
	Query  string     `json:"query"`
	Assets []AssetHit `json:"assets,omitempty"`
}

// AssetHit is one search result row.
type AssetHit struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	FQDN       string  `json:"fqdn"`
	DeviceType string  `json:"device_type"`
	SiteID     string  `json:"site_id"`
	Risk       float64 `json:"risk"`
}

// ==================================================================== identifiers

type IdentifierRepo struct{ db *DB }

func NewIdentifierRepo(db *DB) *IdentifierRepo { return &IdentifierRepo{db: db} }

func (r *IdentifierRepo) Upsert(ctx context.Context, assetID, typ, value string, weight float64) error {
	q := r.db.Insert("asset_identifiers").
		Columns("id", "asset_id", "type", "value", "weight").
		Values(ids.New(), assetID, typ, value, weight).
		Suffix(`ON CONFLICT (asset_id, type, value) DO UPDATE SET weight = EXCLUDED.weight`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// FindByIdentifier returns organization-scoped assets sharing an identifier
// (correlation input). The organization filter lives in the query, not in
// post-fetch checks: a global identifier lookup let one tenant's hostnames,
// MACs and addresses poison another tenant's candidate sets (ambiguity
// skips, wrong-asset merges) and leak asset IDs across tenants. An empty
// orgID fails closed — identity resolution without tenancy is a bug, not a
// lookup mode.
func (r *IdentifierRepo) FindByIdentifier(ctx context.Context, orgID, typ, value string) ([]string, error) {
	if orgID == "" {
		return nil, nil
	}
	q := r.db.Select("i.asset_id").From("asset_identifiers i").
		Join("assets a ON a.id = i.asset_id").
		Where(squirrel.Eq{"i.type": typ, "i.value": value, "a.organization_id": orgID}).
		OrderBy("i.weight DESC").Limit(10)
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *IdentifierRepo) ListForAsset(ctx context.Context, assetID string) ([]domain.Identifier, error) {
	q := r.db.Select("asset_id, type, value, weight").From("asset_identifiers").
		Where(squirrel.Eq{"asset_id": assetID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Identifier
	for rows.Next() {
		var i domain.Identifier
		if err := rows.Scan(&i.AssetID, &i.Type, &i.Value, &i.Weight); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ==================================================================== interfaces / ips

type InterfaceRepo struct{ db *DB }

func NewInterfaceRepo(db *DB) *InterfaceRepo { return &InterfaceRepo{db: db} }

func (r *InterfaceRepo) Upsert(ctx context.Context, iface *domain.Interface) error {
	if iface.ID == "" {
		iface.ID = ids.New()
	}
	q := r.db.Insert("network_interfaces").
		Columns("id", "asset_id", "mac", "vendor", "name", "vlan_id", "mtu", "speed_mbps", "status").
		Values(iface.ID, iface.AssetID, iface.MAC, iface.Vendor, iface.Name, iface.VLANID, iface.MTU, iface.SpeedMbps, iface.Status).
		Suffix(`ON CONFLICT (asset_id, mac) DO UPDATE SET name = COALESCE(NULLIF(EXCLUDED.name,''), network_interfaces.name),
                        vendor = COALESCE(NULLIF(EXCLUDED.vendor,''), network_interfaces.vendor),
                        last_seen = now() RETURNING id`)
	return r.db.QueryRow(ctx, q).Scan(&iface.ID)
}

func (r *InterfaceRepo) AddIP(ctx context.Context, ifaceID, ip string, isPrimary bool) error {
	q := r.db.Insert("ip_addresses").
		Columns("id", "interface_id", "ip", "is_primary").
		Values(ids.New(), ifaceID, ip, isPrimary).
		Suffix(`ON CONFLICT (interface_id, ip) DO UPDATE SET last_seen = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// SetPrimaryIP makes `ip` the interface's single primary address: every
// row of the interface is flagged by comparison, so exactly one row (the
// one holding `ip`) is primary afterwards — previous flags and previous
// multiple-primary states converge. An address recorded earlier as primary
// keeps its flag when the primary selection moves; the flag column is a
// derived view of "which address the UI displays", never authoritative
// history. No-op on an empty ip.
func (r *InterfaceRepo) SetPrimaryIP(ctx context.Context, ifaceID, ip string) error {
	if ip == "" {
		return nil
	}
	q := r.db.Update("ip_addresses").
		Set("is_primary", squirrel.Expr("ip = ?", ip)).
		Where(squirrel.Eq{"interface_id": ifaceID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *InterfaceRepo) ListForAsset(ctx context.Context, assetID string) ([]domain.Interface, error) {
	q := r.db.Select("id, asset_id, mac, vendor, name, vlan_id, mtu, speed_mbps, status, first_seen, last_seen").
		From("network_interfaces").Where(squirrel.Eq{"asset_id": assetID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Interface
	for rows.Next() {
		var i domain.Interface
		if err := rows.Scan(&i.ID, &i.AssetID, &i.MAC, &i.Vendor, &i.Name, &i.VLANID, &i.MTU, &i.SpeedMbps, &i.Status, &i.FirstSeen, &i.LastSeen); err != nil {
			return nil, err
		}
		ipQ := r.db.Select("host(ip) AS ip, is_primary, first_seen, last_seen").From("ip_addresses").
			// Primary first, then stable insertion order (first_seen, ip) —
			// without a secondary key the primary-selection fallback
			// (addresses[0]) was nondeterministic between reads.
			Where(squirrel.Eq{"interface_id": i.ID}).OrderBy("is_primary DESC", "first_seen ASC", "ip ASC")
		ipRows, err := r.db.Query(ctx, ipQ)
		if err != nil {
			return nil, err
		}
		for ipRows.Next() {
			var ipo domain.IPObservation
			if err := ipRows.Scan(&ipo.IP, &ipo.IsPrimary, &ipo.FirstSeen, &ipo.LastSeen); err != nil {
				ipRows.Close()
				return nil, err
			}
			i.Addresses = append(i.Addresses, ipo)
		}
		ipRows.Close()
		out = append(out, i)
	}
	return out, rows.Err()
}

// ==================================================================== services

type ServiceRepo struct{ db *DB }

func NewServiceRepo(db *DB) *ServiceRepo { return &ServiceRepo{db: db} }

const serviceCols = `id, asset_id, organization_id, protocol, port, service_name, product, vendor,
detected_version, version_range, version_confidence, cpes, banner, tls, http, sources, confidence,
exposure, flags, state, first_seen, last_seen, version_norm`

func scanService(row scanner) (*domain.Service, error) {
	var s domain.Service
	err := row.Scan(&s.ID, &s.AssetID, &s.OrganizationID, &s.Protocol, &s.Port,
		&s.ServiceName, &s.Product, &s.Vendor, &s.DetectedVersion, &s.VersionRange,
		&s.VersionConf, &s.CPEs, &s.Banner, &s.TLS, &s.HTTP, &s.Sources, &s.Confidence,
		&s.Exposure, &s.Flags, &s.State, &s.FirstSeen, &s.LastSeen, &s.VersionNorm)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (r *ServiceRepo) Upsert(ctx context.Context, s *domain.Service) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("services").
		Columns("id", "asset_id", "organization_id", "protocol", "port", "service_name",
			"product", "vendor", "detected_version", "version_range", "version_confidence",
			"cpes", "banner", "tls", "http", "sources", "confidence", "exposure", "flags", "state", "version_norm").
		Values(s.ID, s.AssetID, s.OrganizationID, s.Protocol, s.Port, s.ServiceName,
			s.Product, s.Vendor, s.DetectedVersion, s.VersionRange, s.VersionConf,
			nonNil(s.CPEs), s.Banner, s.TLS, s.HTTP, nonNil(s.Sources), s.Confidence, s.Exposure, nonNil(s.Flags), s.State, s.VersionNorm).
		Suffix(`ON CONFLICT (asset_id, protocol, port) DO UPDATE SET
                        service_name = EXCLUDED.service_name,
                        product = EXCLUDED.product,
                        vendor = EXCLUDED.vendor,
                        detected_version = EXCLUDED.detected_version,
                        version_range = EXCLUDED.version_range,
                        version_confidence = EXCLUDED.version_confidence,
                        cpes = EXCLUDED.cpes,
                        banner = EXCLUDED.banner,
                        tls = EXCLUDED.tls,
                        http = EXCLUDED.http,
                        sources = EXCLUDED.sources,
                        confidence = EXCLUDED.confidence,
                        exposure = EXCLUDED.exposure,
                        flags = EXCLUDED.flags,
                        state = EXCLUDED.state,
                        version_norm = EXCLUDED.version_norm,
                        last_seen = now()
                        RETURNING id, first_seen`)
	return r.db.QueryRow(ctx, q).Scan(&s.ID, &s.FirstSeen)
}

func (r *ServiceRepo) ByID(ctx context.Context, orgID, id string) (*domain.Service, error) {
	q := r.db.Select(serviceCols).From("services").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanService(r.db.QueryRow(ctx, q))
}

func (r *ServiceRepo) ListForAsset(ctx context.Context, assetID string) ([]domain.Service, error) {
	q := r.db.Select(serviceCols).From("services").
		Where(squirrel.Eq{"asset_id": assetID, "state": "open"}).
		OrderBy("port")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Service
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ListForCorrelation returns open services of an org that carry a product
// identity (product, service name or CPE) — the inputs the vulnerability
// matching sweep consumes. Bounded to keep a sweep predictable.
func (r *ServiceRepo) ListForCorrelation(ctx context.Context, orgID string, limit int) ([]domain.Service, error) {
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	q := r.db.Select(serviceCols).From("services").
		Where(squirrel.Eq{"organization_id": orgID, "state": "open"}).
		Where(squirrel.Or{
			squirrel.NotEq{"product": nil},
			squirrel.NotEq{"service_name": nil},
			squirrel.NotEq{"cpes": nil},
		}).
		OrderBy("last_seen DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Service
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ServiceFilter constrains service queries.
type ServiceFilter struct {
	OrgID    string
	Product  string
	Port     int
	Protocol string
	Search   string
	Limit    int
	Page     int
}

func (r *ServiceRepo) List(ctx context.Context, f ServiceFilter) ([]domain.Service, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	where := squirrel.Eq{"organization_id": f.OrgID, "state": "open"}
	if f.Product != "" {
		where["product"] = f.Product
	}
	if f.Port > 0 {
		where["port"] = f.Port
	}
	if f.Protocol != "" {
		where["protocol"] = f.Protocol
	}
	// Dedicated count query: appending "count(*) OVER()" to the select list
	// breaks Scan (column count must match scan targets exactly).
	q := r.db.Select(serviceCols).From("services").Where(where)
	if f.Search != "" {
		pat := "%" + escapeLike(f.Search) + "%"
		q = q.Where(squirrel.Or{
			squirrel.ILike{"service_name": pat},
			squirrel.ILike{"product": pat},
		})
	}
	cq := r.db.Select("count(*)").From("services").Where(where)
	if f.Search != "" {
		pat := "%" + escapeLike(f.Search) + "%"
		cq = cq.Where(squirrel.Or{
			squirrel.ILike{"service_name": pat},
			squirrel.ILike{"product": pat},
		})
	}
	var total int64
	if err := r.db.QueryRow(ctx, cq).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, q.OrderBy("port").Limit(uint64(f.Limit)).Offset(uint64((f.Page-1)*f.Limit)))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Service
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// AddObservation records a service observation with provenance.
func (r *ServiceRepo) AddObservation(ctx context.Context, serviceID, scanID, source string, raw map[string]any, confidence float64) error {
	q := r.db.Insert("service_observations").
		Columns("id", "service_id", "scan_id", "source", "raw", "confidence").
		Values(ids.New(), serviceID, nullStr(scanID), source, raw, confidence)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== software

type SoftwareRepo struct{ db *DB }

func NewSoftwareRepo(db *DB) *SoftwareRepo { return &SoftwareRepo{db: db} }

func (r *SoftwareRepo) Upsert(ctx context.Context, s *domain.Software) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("software").
		Columns("id", "asset_id", "name", "version", "version_norm", "vendor", "ecosystem", "purl", "cpes", "source").
		Values(s.ID, s.AssetID, s.Name, s.Version, s.VersionNorm, s.Vendor, s.Ecosystem, s.PURL, nonNil(s.CPEs), s.Source).
		Suffix(`ON CONFLICT (asset_id, name, version, ecosystem) DO UPDATE SET
                        version_norm = EXCLUDED.version_norm, purl = EXCLUDED.purl, cpes = EXCLUDED.cpes, last_seen = now() RETURNING id`)
	return r.db.QueryRow(ctx, q).Scan(&s.ID)
}

func (r *SoftwareRepo) ListForAsset(ctx context.Context, assetID string) ([]domain.Software, error) {
	q := r.db.Select("id, asset_id, name, version, version_norm, vendor, ecosystem, purl, cpes, source, first_seen, last_seen").
		From("software").Where(squirrel.Eq{"asset_id": assetID}).OrderBy("name")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Software
	for rows.Next() {
		var s domain.Software
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Name, &s.Version, &s.VersionNorm, &s.Vendor, &s.Ecosystem,
			&s.PURL, &s.CPEs, &s.Source, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AllPackages returns the full package inventory for matching pipelines.
func (r *SoftwareRepo) AllPackages(ctx context.Context, orgID string) ([]domain.Software, error) {
	q := r.db.Select("s.id, s.asset_id, s.name, s.version, s.version_norm, s.vendor, s.ecosystem, s.purl, s.cpes, s.source, s.first_seen, s.last_seen").
		From("software s").
		Join("assets a ON a.id = s.asset_id").
		Where(squirrel.Eq{"a.organization_id": orgID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Software
	for rows.Next() {
		var s domain.Software
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Name, &s.Version, &s.VersionNorm, &s.Vendor, &s.Ecosystem,
			&s.PURL, &s.CPEs, &s.Source, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ExistsForAsset reports whether a package row already exists for an asset
// (and returns its id). The agent inventory path uses it to emit
// software.installed only for genuinely new rows.
func (r *SoftwareRepo) ExistsForAsset(ctx context.Context, assetID, name, version, ecosystem string) (bool, string, error) {
	q := r.db.Select("id").From("software").
		Where(squirrel.Eq{"asset_id": assetID, "name": name, "version": version, "ecosystem": ecosystem}).
		Limit(1)
	var id string
	err := r.db.QueryRow(ctx, q).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, id, nil
}
