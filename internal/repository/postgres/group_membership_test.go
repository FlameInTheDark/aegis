package postgres

// Regression tests for the asset-group membership bug (v1.14.0 field
// report: "created a group, checked assets to assign them, but after i
// saved, nothing was actually added to the group" and the "+" cell on
// asset rows silently failing).
//
// Root cause: GroupRepo.AddMembers passed the group id to DB.Select as a
// *column string* — squirrel renders plain strings verbatim, so the uuid
// text landed inside the SELECT list, the "?::uuid" placeholder was left
// without an argument, and every membership insert failed with a
// bind/parse error that the UI surfaced as a 500 (or swallowed).
//
//   - TestGroupMembersQueryShape: DB-free — pins the parameterized SQL
//     shape (uuid bound as $1, asset ids as IN-list args).
//   - TestIntegrationGroupMembership: end-to-end against real Postgres
//     (skipped unless AEGIS_TEST_PG_URL is set).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// TestGroupMembersQueryShape pins the exact binding pattern AddMembers
// must use: the group id as a bound parameter, the asset ids as the
// IN-list arguments, no raw uuid text inside the SQL.
func TestGroupMembersQueryShape(t *testing.T) {
	orgID, groupID := ids.New(), ids.New()
	assetIDs := []string{ids.New(), ids.New(), ids.New()}

	q := squirrel.Insert("asset_group_members").
		Columns("group_id", "asset_id").
		Select(squirrel.Select().Column("?::uuid", groupID).Column("a.id::uuid").
			From("assets a").
			Where(squirrel.Eq{"a.organization_id": orgID}).
			Where(squirrel.Eq{"a.id": assetIDs})).
		Suffix("ON CONFLICT (group_id, asset_id) DO NOTHING")

	// The repo's DB wrapper applies the Dollar placeholder format.
	sql, args, err := q.PlaceholderFormat(squirrel.Dollar).ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	if strings.Contains(sql, groupID) {
		t.Fatalf("group id rendered verbatim into SQL (the v1.14 bug):\n%s", sql)
	}
	if !strings.Contains(sql, "SELECT $1::uuid, a.id::uuid FROM assets a") {
		t.Fatalf("unexpected select shape:\n%s", sql)
	}
	// args = [groupID, orgID, asset1..3]; the uuid placeholder must be $1.
	if len(args) != 2+len(assetIDs) {
		t.Fatalf("arg count = %d, want %d (sql:\n%s)", len(args), 2+len(assetIDs), sql)
	}
	if args[0] != groupID {
		t.Fatalf("arg[0] = %v, want group id %s", args[0], groupID)
	}
	if !strings.Contains(sql, "$1::uuid") {
		t.Fatalf("group id not bound as $1:\n%s", sql)
	}
}

// TestIntegrationGroupMembership exercises the membership lifecycle end to
// end: create → add (with an out-of-org id that must be skipped) → list →
// remove → member group ids.
func TestIntegrationGroupMembership(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	db, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	org, err := NewOrgRepo(db).Create(ctx, "group-org-"+ids.New(), "grp-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	site := &domain.Site{ID: ids.New(), OrganizationID: org.ID, Name: "grp-site", SiteType: "lab",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}

	mkAsset := func(name string) string {
		a := &domain.Asset{ID: ids.New(), OrganizationID: org.ID, SiteID: site.ID,
			Hostname: name, Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
		if err := NewAssetRepo(db).Insert(ctx, a); err != nil {
			t.Fatalf("asset insert: %v", err)
		}
		return a.ID
	}
	a1, a2 := mkAsset("grp-host-1"), mkAsset("grp-host-2")
	foreign := ids.New() // belongs to no org — must never be added

	g := &domain.AssetGroup{OrgID: org.ID, Name: "grp-1", Kind: domain.GroupKindCustom}
	repo := NewGroupRepo(db)
	if err := repo.Create(ctx, g); err != nil {
		t.Fatalf("group create: %v", err)
	}

	if err := repo.AddMembers(ctx, org.ID, g.ID, []string{a1, a2, foreign}); err != nil {
		t.Fatalf("AddMembers failed (v1.14 bind bug?): %v", err)
	}
	out, err := repo.ByID(ctx, org.ID, g.ID)
	if err != nil {
		t.Fatalf("group ByID: %v", err)
	}
	if len(out.AssetIDs) != 2 {
		t.Fatalf("members = %v, want exactly [%s %s] (foreign id leaked?)", out.AssetIDs, a1, a2)
	}

	// Idempotent re-add must not duplicate or error.
	if err := repo.AddMembers(ctx, org.ID, g.ID, []string{a1}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if out2, _ := repo.ByID(ctx, org.ID, g.ID); len(out2.AssetIDs) != 2 {
		t.Fatalf("re-add changed membership: %v", out2.AssetIDs)
	}

	if err := repo.RemoveMembers(ctx, g.ID, []string{a1}); err != nil {
		t.Fatalf("RemoveMembers: %v", err)
	}
	ids2, err := repo.MemberGroupIDs(ctx, org.ID, a2)
	if err != nil {
		t.Fatalf("MemberGroupIDs: %v", err)
	}
	if len(ids2) != 1 || ids2[0] != g.ID {
		t.Fatalf("MemberGroupIDs(a2) = %v, want [%s]", ids2, g.ID)
	}
	ids1, err := repo.MemberGroupIDs(ctx, org.ID, a1)
	if err != nil {
		t.Fatalf("MemberGroupIDs(a1): %v", err)
	}
	if len(ids1) != 0 {
		t.Fatalf("MemberGroupIDs(a1) = %v, want empty after remove", ids1)
	}
}
