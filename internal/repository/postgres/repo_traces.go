package postgres

import (
	"context"
	"encoding/json"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== traces

type TraceRepo struct{ db *DB }

func NewTraceRepo(db *DB) *TraceRepo { return &TraceRepo{db: db} }

// Upsert stores one traceroute result. One row per (site, target): a fresh
// scan REPLACES the stored path, probe and raw output and refreshes
// last_seen — first_seen stays stable so the UI can show when the address
// first appeared on the map. (History lives in the observations table.)
func (r *TraceRepo) Upsert(ctx context.Context, t *domain.AssetTrace) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	if t.HopIPs == nil {
		t.HopIPs = []string{}
	}
	if t.Path == nil {
		t.Path = []domain.TraceHop{}
	}
	q := r.db.Insert("asset_traces").
		Columns("id", "organization_id", "site_id", "scan_id", "target_ip",
			"method", "probe", "complete", "hops_count", "path", "hop_ips", "raw", "confidence").
		Values(t.ID, t.OrganizationID, t.SiteID, t.ScanID, t.TargetIP,
			t.Method, t.Probe, t.Complete, t.HopsCount, jsonMarshal(t.Path), t.HopIPs, t.Raw, float64(t.Confidence)).
		Suffix(`ON CONFLICT (site_id, target_ip) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			scan_id = EXCLUDED.scan_id,
			method = EXCLUDED.method,
			probe = EXCLUDED.probe,
			complete = EXCLUDED.complete,
			hops_count = EXCLUDED.hops_count,
			path = EXCLUDED.path,
			hop_ips = EXCLUDED.hop_ips,
			raw = EXCLUDED.raw,
			confidence = EXCLUDED.confidence,
			last_seen = now()
			RETURNING id, first_seen, last_seen`)
	return r.db.QueryRow(ctx, q).Scan(&t.ID, &t.FirstSeen, &t.LastSeen)
}

const traceColumns = `id, organization_id, site_id::text, scan_id, target_ip,
	method, probe, complete, hops_count, path, hop_ips, raw, confidence,
	first_seen, last_seen`

func scanTrace(row interface{ Scan(dest ...any) error }) (domain.AssetTrace, error) {
	var t domain.AssetTrace
	var raw []byte
	if err := row.Scan(&t.ID, &t.OrganizationID, &t.SiteID, &t.ScanID, &t.TargetIP,
		&t.Method, &t.Probe, &t.Complete, &t.HopsCount, &raw, &t.HopIPs, &t.Raw, &t.Confidence,
		&t.FirstSeen, &t.LastSeen); err != nil {
		return t, err
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &t.Path) // JSONB always valid; nil path stays empty
	}
	if t.Path == nil {
		t.Path = []domain.TraceHop{}
	}
	if t.HopIPs == nil {
		t.HopIPs = []string{}
	}
	return t, nil
}

// ForAssetIPs returns the most recently refreshed traces whose path touches
// ANY of the given addresses — the target itself or any hop in between, so
// a router asset lists every trace passing through it, a host asset lists
// the traces aimed at it. hop_ips && ARRAY[...] is GIN-indexed
// (idx_asset_traces_hop_ips); pgx maps []string natively to text[].
func (r *TraceRepo) ForAssetIPs(ctx context.Context, orgID string, ips []string, limit int) ([]domain.AssetTrace, error) {
	if len(ips) == 0 {
		return []domain.AssetTrace{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if len(ips) > 32 { // an asset with hundreds of historical addresses must not build a huge overlap list
		ips = ips[:32]
	}
	q := r.db.Select(traceColumns).
		From("asset_traces").
		Where(squirrel.Eq{"organization_id": orgID}).
		Where(squirrel.Expr("hop_ips && ?::text[]", ips)).
		OrderBy("last_seen DESC").
		Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AssetTrace{}
	for rows.Next() {
		t, err := scanTrace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ByTarget returns the current trace stored for one address (org-scoped) —
// used by scan detail views and tests.
func (r *TraceRepo) ByTarget(ctx context.Context, orgID, siteID, ip string) (*domain.AssetTrace, error) {
	q := r.db.Select(traceColumns).
		From("asset_traces").
		Where(squirrel.Eq{"organization_id": orgID, "site_id": siteID, "target_ip": ip})
	row := r.db.QueryRow(ctx, q)
	t, err := scanTrace(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}
