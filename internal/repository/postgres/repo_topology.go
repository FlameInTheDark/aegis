package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== topology

type TopologyRepo struct{ db *DB }

func NewTopologyRepo(db *DB) *TopologyRepo { return &TopologyRepo{db: db} }

// UpsertNode creates or refreshes a topology node (reconciliation, not
// wholesale replacement).
func (r *TopologyRepo) UpsertNode(ctx context.Context, n *domain.TopologyNode) error {
	props := jsonMarshal(n.Props)
	q := r.db.Insert("topology_nodes").
		Columns("id", "organization_id", "site_id", "kind", "ref_id", "label", "props").
		Values(ids.New(), n.OrganizationID, n.SiteID, string(n.Kind), n.RefID, n.Label, props).
		Suffix(`ON CONFLICT (site_id, kind, ref_id) DO UPDATE SET
                        label = EXCLUDED.label, props = EXCLUDED.props, last_seen = now()
                        RETURNING id, first_seen`)
	return r.db.QueryRow(ctx, q).Scan(&n.ID, &n.FirstSeen)
}

// UpsertEdge creates or refreshes an edge, keeping first_seen stable.
func (r *TopologyRepo) UpsertEdge(ctx context.Context, e *domain.TopologyEdge) error {
	if e.ID == "" {
		e.ID = ids.New()
	}
	q := r.db.Insert("topology_edges").
		Columns("id", "organization_id", "site_id", "src_node_id", "dst_node_id", "kind", "confidence").
		Values(e.ID, e.OrganizationID, e.SiteID, e.SrcNodeID, e.DstNodeID, string(e.Kind), float64(e.Confidence)).
		Suffix(`ON CONFLICT (src_node_id, dst_node_id, kind) DO UPDATE SET
                        confidence = GREATEST(topology_edges.confidence, EXCLUDED.confidence),
                        last_seen = now()
                        RETURNING id, first_seen`)
	return r.db.QueryRow(ctx, q).Scan(&e.ID, &e.FirstSeen)
}

func (r *TopologyRepo) AddEvidence(ctx context.Context, ev *domain.TopologyEvidence) error {
	if ev.ID == "" {
		ev.ID = ids.New()
	}
	q := r.db.Insert("topology_evidence").
		Columns("id", "edge_id", "source", "statement", "detail", "observed_at").
		Values(ev.ID, ev.EdgeID, string(ev.Source), ev.Statement, jsonMarshal(ev.Detail), ev.ObservedAt)
	_, err := r.db.Exec(ctx, q)
	return err
}

// Graph returns the graph for a site, or org-wide when siteID is empty
// (the UI defaults to ?site_id= before a site is selected). For very large
// sites the API layer applies view-scoped filters (site/network/VLAN).
func (r *TopologyRepo) Graph(ctx context.Context, orgID, siteID string) ([]domain.TopologyNode, []domain.TopologyEdge, error) {
	nwhere := squirrel.Eq{"organization_id": orgID}
	ewhere := squirrel.Eq{"organization_id": orgID}
	if siteID != "" {
		nwhere["site_id"] = siteID
		ewhere["site_id"] = siteID
	}
	nq := r.db.Select("id, organization_id, site_id::text, kind, ref_id, label, props, first_seen, last_seen").
		From("topology_nodes").
		Where(nwhere).
		OrderBy("kind, label")
	nodes := []domain.TopologyNode{}
	rows, err := r.db.Query(ctx, nq)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n domain.TopologyNode
		if err := rows.Scan(&n.ID, &n.OrganizationID, &n.SiteID, &n.Kind, &n.RefID,
			&n.Label, &n.Props, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	eq := r.db.Select("id, organization_id, site_id::text, src_node_id::text, dst_node_id::text, kind, confidence, first_seen, last_seen").
		From("topology_edges").
		Where(ewhere)
	edges := []domain.TopologyEdge{}
	erows, err := r.db.Query(ctx, eq)
	if err != nil {
		return nil, nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var e domain.TopologyEdge
		if err := erows.Scan(&e.ID, &e.OrganizationID, &e.SiteID, &e.SrcNodeID, &e.DstNodeID,
			&e.Kind, &e.Confidence, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, nil, err
		}
		edges = append(edges, e)
	}
	return nodes, edges, erows.Err()
}

// EvidenceForEdge returns evidence rows of one edge.
func (r *TopologyRepo) EvidenceForEdge(ctx context.Context, edgeID string) ([]domain.TopologyEvidence, error) {
	q := r.db.Select("id, edge_id::text, source, statement, detail, observed_at").
		From("topology_evidence").Where(squirrel.Eq{"edge_id": edgeID}).
		OrderBy("observed_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.TopologyEvidence
	for rows.Next() {
		var e domain.TopologyEvidence
		if err := rows.Scan(&e.ID, &e.EdgeID, &e.Source, &e.Statement, &e.Detail, &e.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneStaleEdges marks edges not seen since cutoff as low confidence
// rather than deleting them (topology is evidence-backed history).
func (r *TopologyRepo) PruneStaleEdges(ctx context.Context, siteID string, cutoff time.Time) error {
	q := r.db.Update("topology_edges").
		Set("confidence", 0.1).
		Where(squirrel.Eq{"site_id": siteID}).
		Where(squirrel.Lt{"last_seen": cutoff})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== reports

type ReportRepo struct{ db *DB }

func NewReportRepo(db *DB) *ReportRepo { return &ReportRepo{db: db} }

func (r *ReportRepo) Create(ctx context.Context, d *domain.ReportDefinition) error {
	if d.ID == "" {
		d.ID = ids.New()
	}
	q := r.db.Insert("reports").
		Columns("id", "organization_id", "name", "type", "format", "site_id", "asset_id", "scan_id",
			"date_from", "date_to", "sections", "min_severity", "created_by").
		Values(d.ID, d.OrganizationID, d.Name, string(d.Type), string(d.Format),
			nullStr(d.SiteID), nullStr(d.AssetID), nullStr(d.ScanID), d.DateFrom, d.DateTo, nonNil(d.Sections),
			nullPtrStr((*string)(&d.MinSeverity)), nullStr(d.CreatedBy))
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ReportRepo) Definition(ctx context.Context, orgID, id string) (*domain.ReportDefinition, error) {
	q := r.db.Select("id, organization_id, name, type, format, COALESCE(site_id::text,'') AS site_id, COALESCE(asset_id::text,'') AS asset_id, COALESCE(scan_id::text,'') AS scan_id, date_from, date_to, sections, COALESCE(min_severity,'') AS min_severity, created_by::text, created_at").
		From("reports").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	var d domain.ReportDefinition
	err := r.db.QueryRow(ctx, q).Scan(&d.ID, &d.OrganizationID, &d.Name, &d.Type, &d.Format,
		&d.SiteID, &d.AssetID, &d.ScanID, &d.DateFrom, &d.DateTo, &d.Sections, &d.MinSeverity,
		&d.CreatedBy, &d.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &d, nil
}

func (r *ReportRepo) List(ctx context.Context, orgID string) ([]domain.ReportDefinition, error) {
	q := r.db.Select("id, organization_id, name, type, format, COALESCE(site_id::text,'') AS site_id, COALESCE(asset_id::text,'') AS asset_id, COALESCE(scan_id::text,'') AS scan_id, date_from, date_to, sections, COALESCE(min_severity,'') AS min_severity, created_by::text, created_at").
		From("reports").Where(squirrel.Eq{"organization_id": orgID}).OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ReportDefinition
	for rows.Next() {
		var d domain.ReportDefinition
		if err := rows.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.Type, &d.Format,
			&d.SiteID, &d.AssetID, &d.ScanID, &d.DateFrom, &d.DateTo, &d.Sections, &d.MinSeverity,
			&d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *ReportRepo) CreateJob(ctx context.Context, j *domain.ReportJob) error {
	if j.ID == "" {
		j.ID = ids.New()
	}
	q := r.db.Insert("report_jobs").
		Columns("id", "definition_id", "organization_id", "state").
		Values(j.ID, j.Definition, j.OrgID, j.State)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ReportRepo) UpdateJob(ctx context.Context, j *domain.ReportJob) error {
	q := r.db.Update("report_jobs").
		Set("state", j.State).
		Set("progress", j.Progress).
		Set("artifact_key", j.ArtifactKey).
		Set("size_bytes", j.SizeBytes).
		Set("error", nullStr(j.Error)).
		Set("started_at", j.StartedAt).
		Set("finished_at", j.FinishedAt).
		Where(squirrel.Eq{"id": j.ID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ReportRepo) Job(ctx context.Context, orgID, id string) (*domain.ReportJob, error) {
	q := r.db.Select("id, definition_id::text, organization_id, state, progress, artifact_key, size_bytes, COALESCE(error,'') AS error, created_at, started_at, finished_at").
		From("report_jobs").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	var j domain.ReportJob
	err := r.db.QueryRow(ctx, q).Scan(&j.ID, &j.Definition, &j.OrgID, &j.State, &j.Progress,
		&j.ArtifactKey, &j.SizeBytes, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &j, nil
}

func (r *ReportRepo) ListJobs(ctx context.Context, orgID string, limit int) ([]domain.ReportJob, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	q := r.db.Select("id, definition_id::text, organization_id, state, progress, artifact_key, size_bytes, COALESCE(error,'') AS error, created_at, started_at, finished_at").
		From("report_jobs").Where(squirrel.Eq{"organization_id": orgID}).
		OrderBy("created_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ReportJob
	for rows.Next() {
		var j domain.ReportJob
		if err := rows.Scan(&j.ID, &j.Definition, &j.OrgID, &j.State, &j.Progress,
			&j.ArtifactKey, &j.SizeBytes, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// jsonMarshal keeps nil maps as '{}' to satisfy JSONB columns.
func jsonMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

// QueuedJobs returns queued report jobs across orgs (worker picks them up).
func (r *ReportRepo) QueuedJobs(ctx context.Context, limit int) ([]domain.ReportJob, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	q := r.db.Select("id", "organization_id", "definition_id", "state", "progress",
		"artifact_key", "size_bytes", "COALESCE(error,'') AS error", "created_at", "started_at", "finished_at").
		From("report_jobs").Where(squirrel.Eq{"state": "queued"}).
		OrderBy("created_at ASC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ReportJob{}
	for rows.Next() {
		var j domain.ReportJob
		if err := rows.Scan(&j.ID, &j.OrgID, &j.Definition, &j.State, &j.Progress,
			&j.ArtifactKey, &j.SizeBytes, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err == nil {
			out = append(out, j)
		}
	}
	return out, rows.Err()
}
