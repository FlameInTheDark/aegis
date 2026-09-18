package postgres

import (
 "context"
 "github.com/FlameInTheDark/aegis/internal/domain"
 "github.com/Masterminds/squirrel"
)

// Inventory returns all assets in the authorized report scope without UI pagination.
func (r *AssetRepo) Inventory(ctx context.Context, orgID, siteID string) ([]domain.Asset, error) {
 q := r.db.Select(assetCols).From("assets").Where(assetFilterWhere(AssetFilter{OrgID:orgID, SiteID:siteID})).OrderBy("id")
 rows, err := r.db.Query(ctx,q)
 if err != nil { return nil,err }; defer rows.Close()
 out:=make([]domain.Asset,0)
 for rows.Next() { a,err:=scanAsset(rows); if err!=nil { return nil,err }; out=append(out,*a) }
 return out,rows.Err()
}

// OpenPortCounts counts open protocol/port endpoints per asset, not globally unique port numbers.
func (r *ServiceRepo) OpenPortCounts(ctx context.Context, orgID, siteID string) (map[string]int,error) {
 q:=r.db.Select("s.asset_id", "count(*)").From("services s").Join("assets a ON a.id = s.asset_id AND a.organization_id = s.organization_id").Where(squirrel.Eq{"s.organization_id":orgID,"s.state":"open"}).GroupBy("s.asset_id")
 if siteID!="" { q=q.Where(squirrel.Eq{"a.site_id":siteID}) }
 rows,err:=r.db.Query(ctx,q); if err!=nil{return nil,err}; defer rows.Close()
 out:=make(map[string]int)
 for rows.Next(){var id string; var n int; if err:=rows.Scan(&id,&n);err!=nil{return nil,err};out[id]=n}
 return out,rows.Err()
}
