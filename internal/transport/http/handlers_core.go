package httpx

import (
	gocontext "context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// sha256Sum hashes a refresh token for at-rest storage.
func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// pageParams parses page/limit with caps.
func pageParams(c *fiber.Ctx) (page, limit int) {
	page, _ = strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	limit, _ = strconv.Atoi(c.Query("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return page, limit
}

func itoa(n int) string { return strconv.Itoa(n) }

func f64(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// Organizations

// handleListOrgs returns orgs the caller can see.
func (a *App) handleListOrgs(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	orgs, err := a.svc.Memberships.OrgsFor(Context(c), claims.Subject)
	if err != nil {
		return Internal("list organizations failed")
	}
	if claims.Role == domain.RoleOwner {
		all, err := a.svc.Orgs.List(Context(c))
		if err == nil && len(all) > len(orgs) {
			orgs = all
		}
	}
	return c.JSON(fiber.Map{"items": orgs})
}

func (a *App) handleCreateOrg(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermOrgManage); he != nil {
		return he
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		return BadRequest("name is required")
	}
	org, err := a.svc.OrgService.CreateOrg(Context(c), req.Name, a.claimsFrom(c).Subject)
	if err != nil {
		return Conflict(err.Error())
	}
	return c.Status(201).JSON(org)
}

// handleRenameOrg renames the caller's organization (spec: orgs are named,
// not addressed by UUID in any user-visible surface).
func (a *App) handleRenameOrg(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermOrgManage); he != nil {
		return he
	}
	claims := a.claimsFrom(c)
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		return BadRequest("name is required")
	}
	org, err := a.svc.OrgService.Rename(Context(c), claims.OrganizationID, req.Name)
	if err != nil {
		return NotFound("organization not found")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "org.renamed", "organization:"+org.ID, c.IP(), "", "success", map[string]any{"name": org.Name})
	return c.JSON(org)
}

// ---------------------------------------------------------------------------
// Sites & networks

func (a *App) handleListSites(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	sites, err := a.svc.Sites.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("list sites failed")
	}
	// asset_count drives the scope dropdown + sites table; one aggregate for
	// the whole org, missing sites stay at zero.
	counts, err := a.svc.Assets.CountBySite(Context(c), claims.OrganizationID)
	if err != nil {
		counts = map[string]int64{}
	}
	type siteView struct {
		domain.Site
		AssetCount int64 `json:"asset_count"`
	}
	items := make([]siteView, 0, len(sites))
	for _, s := range sites {
		items = append(items, siteView{Site: s, AssetCount: counts[s.ID]})
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateSite(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSiteManage); he != nil {
		return he
	}
	var req struct {
		Name        string `json:"name"`
		SiteType    string `json:"site_type"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid JSON body")
	}
	site, err := a.svc.OrgService.CreateSite(Context(c), claims.OrganizationID, req.Name, req.SiteType, req.Description)
	if err != nil {
		return BadRequest(err.Error())
	}
	userID, ip, ua := a.auditContext(c)
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, userID, "site.created", "site:"+site.ID, ip, ua, "success", map[string]any{"name": site.Name})
	return c.Status(201).JSON(site)
}

func (a *App) handleGetSite(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	site, err := a.svc.Sites.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("site not found")
	}
	nets, _ := a.svc.Networks.ListBySite(Context(c), site.ID)
	return c.JSON(fiber.Map{"site": site, "networks": nets})
}

func (a *App) handleUpdateSite(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSiteManage); he != nil {
		return he
	}
	var fields map[string]any
	if err := c.BodyParser(&fields); err != nil {
		return BadRequest("invalid JSON body")
	}
	// Whitelist updatable fields (input validation).
	allowed := map[string]bool{"name": true, "description": true, "site_type": true}
	for k := range fields {
		if !allowed[k] {
			delete(fields, k)
		}
	}
	if err := a.svc.Sites.Update(Context(c), claims.OrganizationID, c.Params("id"), fields); err != nil {
		return NotFound("site not found or update failed")
	}
	return c.JSON(fiber.Map{"updated": true})
}

func (a *App) handleDeleteSite(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSiteManage); he != nil {
		return he
	}
	if err := a.svc.Sites.Delete(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("site not found")
	}
	userID, ip, ua := a.auditContext(c)
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, userID, "site.deleted", "site:"+c.Params("id"), ip, ua, "success", nil)
	return c.SendStatus(204)
}

func (a *App) handleCreateNetwork(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSiteManage); he != nil {
		return he
	}
	var req struct {
		CIDR     string `json:"cidr"`
		Name     string `json:"name"`
		Gateway  string `json:"gateway"`
		Exposure string `json:"exposure"`
		VLANID   *int   `json:"vlan_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid JSON body")
	}
	net, err := a.svc.OrgService.CreateNetwork(Context(c), claims.OrganizationID, c.Params("id"), req.CIDR, req.Name, req.Gateway, req.Exposure, req.VLANID)
	if err != nil {
		return BadRequest(err.Error())
	}
	return c.Status(201).JSON(net)
}

func (a *App) handleListNetworks(c *fiber.Ctx) error {
	nets, err := a.svc.Networks.ListBySite(Context(c), c.Params("id"))
	if err != nil {
		return Internal("list networks failed")
	}
	return c.JSON(fiber.Map{"items": nets})
}

// ---------------------------------------------------------------------------
// Search

func (a *App) handleSearch(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		return BadRequest("q is required")
	}
	if len(q) > 128 {
		q = q[:128]
	}
	res, err := a.svc.Assets.Search(Context(c), claims.OrganizationID, q, 20)
	if err != nil {
		return Internal("search failed")
	}
	return c.JSON(res)
}

// ---------------------------------------------------------------------------
// Notes

// handleAddNote records a note on an asset. The note body is accepted as
// either {"note"} (the console's contract) or {"content"}: the mismatch used
// to make every UI-saved note fail validation. The endpoint now also requires
// asset:write and resolves the asset inside the caller's organization before
// writing - it previously had no permission check and trusted a client-supplied
// entity type.
func (a *App) handleAddNote(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	var req struct {
		Entity  string `json:"entity"`
		Note    string `json:"note"`
		Content string `json:"content"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	content := req.Content
	if content == "" {
		content = req.Note
	}
	if content == "" {
		return BadRequest("note content is required")
	}
	// Tenant boundary: the asset must exist in the caller's organization.
	if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("asset not found")
	}
	n := &domain.Note{
		ID: ids.New(), OrgID: claims.OrganizationID, Entity: "asset",
		EntityID: c.Params("id"), AuthorID: claims.Subject,
		AuthorName: a.authorName(c), Content: content, CreatedAt: time.Now().UTC(),
	}
	if err := a.svc.Notes.Insert(Context(c), n); err != nil {
		return Internal("note insert failed")
	}
	return c.Status(201).JSON(n)
}

// handleListNotes returns an asset's notes, newest first. The read path was
// never exposed before, so notes written through the API were invisible in
// the console; the listing is org-scoped via the asset resolution.
func (a *App) handleListNotes(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetRead); he != nil {
		return he
	}
	if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("asset not found")
	}
	items, err := a.svc.Notes.List(Context(c), claims.OrganizationID, "asset", c.Params("id"))
	if err != nil {
		return Internal("note list failed")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

// ---------------------------------------------------------------------------
// Metrics (dashboard data)

func (a *App) handleMetricsSummary(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	siteID := c.Query("site_id")

	assets, _, err := a.svc.Assets.List(ctx, pg.AssetFilter{OrgID: claims.OrganizationID, SiteID: siteID, Limit: 200})
	if err != nil {
		return Internal("metrics failed")
	}
	svcs, totalSvc, _ := a.svc.Services.List(ctx, pg.ServiceFilter{OrgID: claims.OrganizationID, Limit: 1})
	_ = svcs
	findings, totalFindings, _ := a.svc.Findings.List(ctx, pg.FindingFilter{OrgID: claims.OrganizationID, SiteID: siteID, Status: string(domain.FindingOpen), Limit: 200})

	critical, high, med, low, info := 0, 0, 0, 0, 0
	highRiskAssets := 0
	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		case domain.SeverityMedium:
			med++
		case domain.SeverityLow:
			low++
		default:
			info++
		}
	}
	for _, a := range assets {
		if a.RiskScore >= 70 {
			highRiskAssets++
		}
	}
	return c.JSON(fiber.Map{
		"assets":           len(assets),
		"open_ports":       totalSvc,
		"vulnerabilities":  totalFindings,
		"critical":         critical,
		"high":             high,
		"kev":              a.kevFindingsCount(ctx, claims.OrganizationID),
		"high_risk_assets": highRiskAssets,
		"active_alerts":    a.activeAlertsCount(ctx, claims.OrganizationID),
		"by_severity": map[string]int{
			"critical": critical, "high": high, "medium": med, "low": low, "info": info,
		},
	})
}

func (a *App) kevFindingsCount(ctx gocontext.Context, orgID string) int {
	// Findings whose CVE is in the KEV set (5-minute cache).
	cacheKey := "metrics:kev:" + orgID
	if a.svc.Redis != nil {
		var n int
		if ok, _ := a.svc.Redis.CacheGet(ctx, cacheKey, &n); ok {
			return n
		}
	}
	kevSet, err := a.svc.Vulns.KEVSet(ctx)
	if err != nil {
		return 0
	}
	findings, _, _ := a.svc.Findings.List(ctx, pg.FindingFilter{OrgID: orgID, Status: string(domain.FindingOpen), Limit: 200})
	n := 0
	for _, f := range findings {
		if kevSet[f.CVEID] {
			n++
		}
	}
	if a.svc.Redis != nil {
		_ = a.svc.Redis.CacheSet(ctx, cacheKey, n, 5*time.Minute)
	}
	return n
}

func (a *App) activeAlertsCount(ctx gocontext.Context, orgID string) int {
	_, total, _ := a.svc.Matches.List(ctx, pg.MatchFilter{OrgID: orgID, Limit: 1})
	return int(total)
}

func (a *App) handleMetricsTimeseries(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	days, _ := strconv.Atoi(c.Query("days"))
	if days <= 0 || days > 90 {
		days = 30
	}
	metric := c.Query("metric", "events")
	from := time.Now().UTC().AddDate(0, 0, -days)
	var points []fiber.Map
	switch metric {
	case "events":
		if a.svc.CH == nil {
			// No ClickHouse: fall through with no points instead of panicking.
			break
		}
		// Daily buckets with a per-category breakdown for the overview's
		// stacked event-volume chart. The ts/value pair stays for clients
		// that only read totals (old dashboard).
		cats, err := a.svc.CH.EventVolumeByCategory(Context(c), claims.OrganizationID, from, "day")
		if err != nil {
			break
		}
		order := []string{}
		byDay := map[string]map[string]int64{}
		for _, p := range cats {
			key := p.Bucket.Format("2006-01-02")
			if _, ok := byDay[key]; !ok {
				byDay[key] = map[string]int64{}
				order = append(order, key)
			}
			byDay[key][p.Category] += int64(p.Count)
		}
		sort.Strings(order)
		for _, key := range order {
			total := int64(0)
			for _, n := range byDay[key] {
				total += n
			}
			points = append(points, fiber.Map{"ts": key, "value": total, "by_category": byDay[key]})
		}
	case "risk", "vulns":
		// Postgres-backed approximations from finding history.
		findings, _, _ := a.svc.Findings.List(Context(c), pg.FindingFilter{OrgID: claims.OrganizationID, Limit: 200})
		byDay := map[string]float64{}
		for _, f := range findings {
			key := f.FirstSeen.Format("2006-01-02")
			byDay[key] += f.RiskScore
		}
		for d := days; d >= 0; d-- {
			day := time.Now().UTC().AddDate(0, 0, -d)
			key := day.Format("2006-01-02")
			v := byDay[key]
			if metric == "risk" {
				v = v / 10
			}
			points = append(points, fiber.Map{"ts": key, "value": v})
		}
	}
	return c.JSON(fiber.Map{"points": points})
}

// ---------------------------------------------------------------------------
// Audit log

func (a *App) handleAuditLog(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAuditRead); he != nil {
		return he
	}
	page, limit := pageParams(c)
	p := pg.Page{Limit: limit, Page: page, Action: c.Query("action")}
	if from := c.Query("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			p.From = t
		}
	}
	entries, total, err := a.svc.Audit.List(Context(c), claims.OrganizationID, p)
	if err != nil {
		return Internal("audit list failed")
	}
	return c.JSON(fiber.Map{"items": entries, "total": total, "page": page, "limit": limit})
}
