package postgres

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// GroupRepo persists analyst-defined asset groups and their membership.
// Groups are org-scoped; membership is enforced to belong to the same org
// through the asset lookup at the service layer (never trust client ids).

type GroupRepo struct{ db *DB }

func NewGroupRepo(db *DB) *GroupRepo { return &GroupRepo{db: db} }

const groupCols = `id, organization_id, name, description, color, icon, kind, created_at, updated_at`

func scanGroup(row scanner) (*domain.AssetGroup, error) {
	var g domain.AssetGroup
	err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.Color, &g.Icon, &g.Kind, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &g, nil
}

// List returns every group of the org. Membership is fetched in a second
// query and assembled in Go — a LEFT JOIN + array_agg scan is harder to
// keep null-safe, and group counts are small (tens, not thousands).
func (r *GroupRepo) List(ctx context.Context, orgID string) ([]domain.AssetGroupWithMembers, error) {
	q := r.db.Select(groupCols).From("asset_groups").
		Where(squirrel.Eq{"organization_id": orgID}).
		OrderBy("created_at ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AssetGroupWithMembers
	index := map[string]int{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		index[g.ID] = len(out)
		out = append(out, domain.AssetGroupWithMembers{AssetGroup: *g, AssetIDs: []string{}})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	mq := r.db.Select("group_id::text, asset_id::text").From("asset_group_members").
		Where(squirrel.Eq{"asset_groups.organization_id": orgID}).
		Join("asset_groups ON asset_groups.id = asset_group_members.group_id").
		OrderBy("added_at ASC")
	mrows, err := r.db.Query(ctx, mq)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var gid, aid string
		if err := mrows.Scan(&gid, &aid); err != nil {
			return nil, err
		}
		if i, ok := index[gid]; ok {
			out[i].AssetIDs = append(out[i].AssetIDs, aid)
		}
	}
	return out, mrows.Err()
}

// ByID returns one group with members; orgID scopes the lookup.
func (r *GroupRepo) ByID(ctx context.Context, orgID, id string) (*domain.AssetGroupWithMembers, error) {
	q := r.db.Select(groupCols).From("asset_groups").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	g, err := scanGroup(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, err
	}
	out := &domain.AssetGroupWithMembers{AssetGroup: *g, AssetIDs: []string{}}
	mq := r.db.Select("asset_id::text").From("asset_group_members").
		Where(squirrel.Eq{"group_id": id}).OrderBy("added_at ASC")
	mrows, err := r.db.Query(ctx, mq)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var aid string
		if err := mrows.Scan(&aid); err != nil {
			return nil, err
		}
		out.AssetIDs = append(out.AssetIDs, aid)
	}
	return out, mrows.Err()
}

// Create inserts a group. The (organization_id, name) unique index guards
// against duplicates; mapNotFound turns that into ErrNotFound.
func (r *GroupRepo) Create(ctx context.Context, g *domain.AssetGroup) error {
	if g.ID == "" {
		g.ID = ids.New()
	}
	q := r.db.Insert("asset_groups").
		Columns("id", "organization_id", "name", "description", "color", "icon", "kind").
		Values(g.ID, g.OrgID, g.Name, g.Description, g.Color, g.Icon, g.Kind).
		Suffix("RETURNING created_at, updated_at")
	return r.db.QueryRow(ctx, q).Scan(&g.CreatedAt, &g.UpdatedAt)
}

// Update patches analyst-controlled fields (whitelisted by the handler).
func (r *GroupRepo) Update(ctx context.Context, orgID, id string, fields map[string]any) error {
	q := r.db.Update("asset_groups").Set("updated_at", time.Now().UTC())
	for k, v := range fields {
		q = q.Set(k, v)
	}
	q = q.Where(squirrel.Eq{"id": id, "organization_id": orgID})
	cmd, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes the group; membership rows cascade.
func (r *GroupRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("asset_groups").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	cmd, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddMembers links assets to a group. Assets belonging to another org are
// rejected here via a subquery guard — the FK alone cannot see tenancy.
func (r *GroupRepo) AddMembers(ctx context.Context, orgID, groupID string, assetIDs []string) error {
	if len(assetIDs) == 0 {
		return nil
	}
	// The group id is bound as a parameter (Column(col, args...)). The
	// previous version passed it to DB.Select as a *column string*, so the
	// uuid text was rendered verbatim into the SELECT list while the "?"
	// placeholder was left without an argument — every membership insert
	// failed with a bind/parse error and groups silently never got members.
	q := r.db.Insert("asset_group_members").
		Columns("group_id", "asset_id").
		Select(squirrel.Select().Column("?::uuid", groupID).Column("a.id::uuid").
			From("assets a").
			Where(squirrel.Eq{"a.organization_id": orgID}).
			Where(squirrel.Eq{"a.id": assetIDs})).
		Suffix("ON CONFLICT (group_id, asset_id) DO NOTHING")
	_, err := r.db.Exec(ctx, q)
	return err
}

// RemoveMembers unlinks assets from a group; rows for assets of other orgs
// cannot exist (AddMembers guards the org), so no extra filter is needed.
func (r *GroupRepo) RemoveMembers(ctx context.Context, groupID string, assetIDs []string) error {
	if len(assetIDs) == 0 {
		return nil
	}
	q := r.db.Delete("asset_group_members").
		Where(squirrel.Eq{"group_id": groupID}).Where(squirrel.Eq{"asset_id": assetIDs})
	_, err := r.db.Exec(ctx, q)
	return err
}

// MemberGroupIDs returns the group ids an asset belongs to (org-scoped) —
// used by the asset detail view.
func (r *GroupRepo) MemberGroupIDs(ctx context.Context, orgID, assetID string) ([]string, error) {
	q := r.db.Select("m.group_id::text").From("asset_group_members m").
		Join("asset_groups g ON g.id = m.group_id").
		Where(squirrel.Eq{"m.asset_id": assetID, "g.organization_id": orgID}).
		OrderBy("m.added_at ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err != nil {
			return nil, err
		}
		out = append(out, gid)
	}
	return out, rows.Err()
}
