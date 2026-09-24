package postgres

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// OpenSeverityByOrg aggregates OPEN finding counts per asset and severity
// (org-wide, optionally site-scoped). The assets list renders per-row
// critical/high badges from this single aggregate instead of N queries.
type SeverityCount struct {
	AssetID  string
	Severity domain.Severity
	Count    int64
}

func (r *FindingRepo) OpenSeverityByOrg(ctx context.Context, orgID, siteID string) ([]SeverityCount, error) {
	// "Open" = not yet resolved/accepted/suppressed — the same set the
	// asset-detail findings_count uses, so list badges and detail agree.
	where := squirrel.Eq{"f.organization_id": orgID}
	openConds := squirrel.Or{
		squirrel.Eq{"f.status": "open"},
		squirrel.Eq{"f.status": "acknowledged"},
		squirrel.Eq{"f.status": "in_progress"},
	}
	if siteID != "" {
		where["a.site_id"] = siteID
	}
	q := r.db.Select("f.asset_id::text", "f.severity", "count(*)").
		From("findings f").Join("assets a ON a.id = f.asset_id").
		Where(squirrel.And{where, openConds}).
		GroupBy("f.asset_id", "f.severity")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeverityCount
	for rows.Next() {
		var c SeverityCount
		if err := rows.Scan(&c.AssetID, &c.Severity, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ==================================================================== findings

type FindingRepo struct{ db *DB }

func NewFindingRepo(db *DB) *FindingRepo { return &FindingRepo{db: db} }

// All columns are table-qualified: FindingRepo.List joins `assets` when a
// site filter is present, and unqualified columns like bare `id` made that
// query fail with SQLSTATE 42702 ("column reference \"id\" is ambiguous") —
// which broke report generation for any site-scoped report definition.
const findingCols = `f.id, f.organization_id, f.asset_id::text, f.service_id::text, f.software_id::text,
COALESCE(f.cve_id,'') AS cve_id, COALESCE(f.osv_id,'') AS osv_id, f.title, f.match_type, f.confidence, f.risk_score, f.severity, f.status, f.owner, f.notes,
f.remediation, f.suppressed_until, f.first_seen, f.last_seen, f.resolved_at, f.created_at, f.updated_at`

func scanFinding(row scanner) (*domain.Finding, error) {
	var f domain.Finding
	err := row.Scan(&f.ID, &f.OrganizationID, &f.AssetID, &f.ServiceID, &f.SoftwareID,
		&f.CVEID, &f.OSVID, &f.Title, &f.MatchType, &f.Confidence, &f.RiskScore,
		&f.Severity, &f.Status, &f.Owner, &f.Notes, &f.Remediation, &f.SuppressedUntil,
		&f.FirstSeen, &f.LastSeen, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &f, nil
}

// Upsert creates or refreshes a finding; first_seen is preserved.
func (r *FindingRepo) Upsert(ctx context.Context, f *domain.Finding) error {
	if f.ID == "" {
		f.ID = ids.New()
	}
	q := r.db.Insert("findings").
		Columns("id", "organization_id", "asset_id", "service_id", "software_id", "cve_id",
			"osv_id", "title", "match_type", "confidence", "risk_score", "severity", "status", "remediation").
		Values(f.ID, f.OrganizationID, f.AssetID, nullPtrID(f.ServiceID), nullPtrID(f.SoftwareID),
			nullStr(f.CVEID), nullStr(f.OSVID), f.Title, f.MatchType, f.Confidence,
			f.RiskScore, f.Severity, f.Status, f.Remediation).
		Suffix(`ON CONFLICT (asset_id, (COALESCE(cve_id, '')), (COALESCE(service_id::text, ''))) DO UPDATE SET
                        title = EXCLUDED.title,
                        match_type = EXCLUDED.match_type,
                        -- a match that knows the exact fix (e.g. the advisory
                        -- plane's "Upgrade openssl to X (USN-...)") wins over
                        -- the generic text; empty never blanks an existing one
                        remediation = CASE WHEN COALESCE(EXCLUDED.remediation, '') <> '' THEN EXCLUDED.remediation ELSE findings.remediation END,
                        confidence = EXCLUDED.confidence,
                        risk_score = EXCLUDED.risk_score,
                        severity = EXCLUDED.severity,
                        software_id = COALESCE(EXCLUDED.software_id, findings.software_id),
                        last_seen = now(),
                        updated_at = now(),
                        -- a re-observed finding reopens resolved ones
                        status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END,
                        resolved_at = CASE WHEN findings.status = 'resolved' THEN NULL ELSE findings.resolved_at END
                        RETURNING id, first_seen`)
	return r.db.QueryRow(ctx, q).Scan(&f.ID, &f.FirstSeen)
}

func (r *FindingRepo) ByID(ctx context.Context, orgID, id string) (*domain.Finding, error) {
	q := r.db.Select(findingCols).From("findings f").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanFinding(r.db.QueryRow(ctx, q))
}

// FindingFilter constrains finding listings.
type FindingFilter struct {
	OrgID    string
	SiteID   string
	AssetID  string
	Status   string
	Severity string
	MinRisk  float64
	KEV      bool
	Search   string
	Limit    int
	Page     int
}

func (r *FindingRepo) List(ctx context.Context, f FindingFilter) ([]domain.Finding, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	where := squirrel.Eq{"f.organization_id": f.OrgID}
	join := ""
	if f.SiteID != "" {
		join = " JOIN assets a ON a.id = f.asset_id"
		where["a.site_id"] = f.SiteID
	}
	if f.AssetID != "" {
		where["f.asset_id"] = f.AssetID
	}
	if f.Status != "" {
		where["f.status"] = f.Status
	}
	if f.Severity != "" {
		where["f.severity"] = f.Severity
	}
	conds := []squirrel.Sqlizer{where}
	if f.MinRisk > 0 {
		conds = append(conds, squirrel.GtOrEq{"f.risk_score": f.MinRisk})
	}
	if f.KEV {
		conds = append(conds, squirrel.Expr("f.cve_id IN (SELECT cve_id FROM vulnerability_kev WHERE known_exploited)"))
	}
	if f.Search != "" {
		pat := "%" + escapeLike(f.Search) + "%"
		conds = append(conds, squirrel.Or{
			squirrel.ILike{"f.title": pat},
			squirrel.ILike{"f.cve_id": pat},
		})
	}
	fullWhere := squirrel.And(conds)

	// count is a dedicated query on the same predicates — appending
	// count(*) to the column list would mix aggregates with plain columns.
	cq := r.db.Select("count(*)").From("findings f" + join).Where(fullWhere)
	var total int64
	if err := r.db.QueryRow(ctx, cq).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := r.db.Select(findingCols).From("findings f" + join).Where(fullWhere)
	rows, err := r.db.Query(ctx, q.OrderBy("f.risk_score DESC, f.first_seen DESC").
		Limit(uint64(f.Limit)).Offset(uint64((f.Page-1)*f.Limit)))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		fnd, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *fnd)
	}
	return out, total, rows.Err()
}

func (r *FindingRepo) SetStatus(ctx context.Context, orgID, id string, status domain.FindingStatus, changedBy, reason string) error {
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		var from string
		sel := r.db.Select("status").From("findings").
			Where(squirrel.Eq{"id": id, "organization_id": orgID})
		if err := r.db.QueryRow(ctx, sel).Scan(&from); err != nil {
			return mapNotFound(err)
		}
		set := map[string]any{
			"status":     status,
			"updated_at": time.Now().UTC(),
		}
		if status == domain.FindingResolved {
			set["resolved_at"] = time.Now().UTC()
		}
		uq := r.db.Update("findings")
		for k, v := range set {
			uq = uq.Set(k, v)
		}
		uq = uq.Where(squirrel.Eq{"id": id})
		if err := r.db.ExecTx(ctx, tx, uq); err != nil {
			return err
		}
		h := r.db.Insert("finding_status_history").
			Columns("id", "finding_id", "from_state", "to_state", "changed_by", "reason").
			Values(ids.New(), id, from, string(status), changedBy, reason)
		return r.db.ExecTx(ctx, tx, h)
	})
}

// BulkStatus applies a status transition to many findings.
func (r *FindingRepo) BulkStatus(ctx context.Context, orgID string, idsList []string, status domain.FindingStatus, changedBy, reason string) (int, error) {
	n := 0
	for _, id := range idsList {
		if err := r.SetStatus(ctx, orgID, id, status, changedBy, reason); err != nil {
			if err == ErrNotFound {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *FindingRepo) SetOwner(ctx context.Context, orgID, id, owner string) error {
	q := r.db.Update("findings").
		Set("owner", owner).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ListForAsset returns open findings of an asset.
func (r *FindingRepo) ListForAsset(ctx context.Context, assetID string) ([]domain.Finding, error) {
	q := r.db.Select(findingCols).From("findings f").
		Where(squirrel.Eq{"asset_id": assetID}).
		Where(squirrel.NotEq{"status": domain.FindingResolved}).
		OrderBy("risk_score DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// ListForCVE returns findings for a CVE across the org.
func (r *FindingRepo) ListForCVE(ctx context.Context, orgID, cveID string) ([]domain.Finding, error) {
	q := r.db.Select(findingCols).From("findings f").
		Where(squirrel.Eq{"organization_id": orgID, "cve_id": cveID}).
		OrderBy("risk_score DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// MarkStale closes findings whose last_seen predates the cutoff
// (vulnerability resolved: service/asset disappeared).
func (r *FindingRepo) MarkStale(ctx context.Context, cutoff time.Time) (int64, error) {
	q := r.db.Update("findings").
		Set("status", domain.FindingResolved).
		Set("resolved_at", time.Now().UTC()).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"status": domain.FindingOpen}).
		Where(squirrel.Lt{"last_seen": cutoff})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ==================================================================== evidence

type EvidenceRepo struct{ db *DB }

func NewEvidenceRepo(db *DB) *EvidenceRepo { return &EvidenceRepo{db: db} }

func (r *EvidenceRepo) Insert(ctx context.Context, e *domain.Evidence) error {
	if e.ID == "" {
		e.ID = ids.New()
	}
	q := r.db.Insert("finding_evidence").
		Columns("id", "finding_id", "kind", "statement", "detail", "source").
		Values(e.ID, e.FindingID, e.Kind, e.Statement, e.Detail, string(e.Source))
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *EvidenceRepo) ListForFinding(ctx context.Context, findingID string) ([]domain.Evidence, error) {
	q := r.db.Select("id, finding_id, kind, statement, detail, source, created_at").
		From("finding_evidence").Where(squirrel.Eq{"finding_id": findingID}).
		OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Evidence
	for rows.Next() {
		var e domain.Evidence
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Kind, &e.Statement, &e.Detail, &e.Source, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ==================================================================== suppressions

type SuppressionRepo struct{ db *DB }

func NewSuppressionRepo(db *DB) *SuppressionRepo { return &SuppressionRepo{db: db} }

func (r *SuppressionRepo) Insert(ctx context.Context, s *domain.Suppression) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("suppressions").
		Columns("id", "organization_id", "asset_id", "service_id", "vulnerability", "site_id", "tag",
			"reason", "created_by", "expires_at").
		Values(s.ID, s.OrgID, nullPtrID(s.Scope.AssetID), nullPtrID(s.Scope.ServiceID),
			nullPtrStr(s.Scope.Vulnerability), nullPtrStr(s.Scope.SiteID), nullPtrStr(s.Scope.Tag),
			s.Reason, s.CreatedBy, s.ExpiresAt)
	_, err := r.db.Exec(ctx, q)
	return err
}

// Active returns non-expired suppressions for an org.
func (r *SuppressionRepo) Active(ctx context.Context, orgID string) ([]domain.Suppression, error) {
	q := r.db.Select("id, organization_id, asset_id::text, service_id::text, vulnerability, site_id::text, tag, reason, created_by, created_at, expires_at").
		From("suppressions").
		Where(squirrel.Eq{"organization_id": orgID}).
		Where(squirrel.Or{
			squirrel.Expr("expires_at IS NULL"),
			squirrel.Gt{"expires_at": time.Now().UTC()},
		})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Suppression
	for rows.Next() {
		var s domain.Suppression
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Scope.AssetID, &s.Scope.ServiceID,
			&s.Scope.Vulnerability, &s.Scope.SiteID, &s.Scope.Tag, &s.Reason,
			&s.CreatedBy, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ==================================================================== notes

type NoteRepo struct{ db *DB }

func NewNoteRepo(db *DB) *NoteRepo { return &NoteRepo{db: db} }

func (r *NoteRepo) Insert(ctx context.Context, n *domain.Note) error {
	if n.ID == "" {
		n.ID = ids.New()
	}
	q := r.db.Insert("notes").
		Columns("id", "organization_id", "entity", "entity_id", "author_id", "author_name", "content").
		Values(n.ID, n.OrgID, n.Entity, n.EntityID, n.AuthorID, n.AuthorName, n.Content)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *NoteRepo) List(ctx context.Context, entity, entityID string) ([]domain.Note, error) {
	q := r.db.Select("id, organization_id, entity, entity_id, author_id, author_name, content, created_at").
		From("notes").Where(squirrel.Eq{"entity": entity, "entity_id": entityID}).
		OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Note
	for rows.Next() {
		var n domain.Note
		if err := rows.Scan(&n.ID, &n.OrgID, &n.Entity, &n.EntityID, &n.AuthorID, &n.AuthorName, &n.Content, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func nullPtrID(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func nullPtrStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

// StatusHistory returns the status-change trail of a finding.
func (r *FindingRepo) StatusHistory(ctx context.Context, findingID string) ([]domain.FindingStatusChange, error) {
	q := r.db.Select("id", "finding_id", "from_state", "to_state", "changed_by", "reason", "created_at").
		From("finding_status_history").Where(squirrel.Eq{"finding_id": findingID}).
		OrderBy("created_at ASC").Limit(100)
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.FindingStatusChange{}
	for rows.Next() {
		var h domain.FindingStatusChange
		if err := rows.Scan(&h.ID, &h.FindingID, &h.From, &h.To, &h.ChangedBy, &h.Reason, &h.CreatedAt); err == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}
