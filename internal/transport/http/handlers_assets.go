package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
	chx "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Assets

// handleListAssets lists the org's assets with filters.
func (a *App) handleListAssets(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	var hasAgent *bool
	if v := c.Query("has_agent"); v == "true" {
		hasAgent = boolPtr(true)
	} else if v == "false" {
		hasAgent = boolPtr(false)
	}
	f := pg.AssetFilter{
		OrgID:       claims.OrganizationID,
		SiteID:      c.Query("site_id"),
		DeviceType:  c.Query("device_type"),
		OS:          c.Query("os"),
		Search:      c.Query("search"),
		Criticality: c.Query("criticality"),
		HasAgent:    hasAgent,
		Limit:       limit,
		Page:        page,
	}
	if mr := c.QueryFloat("min_risk", -1); mr >= 0 {
		f.MinRisk = mr
	}
	items, total, err := a.svc.Assets.List(Context(c), f)
	if err != nil {
		return Internal("asset list failed")
	}
	// Per-asset open-finding severity counts (one aggregate for the page) —
	// the inventory renders critical/high badges without N+1 queries.
	counts, _ := a.svc.Findings.OpenSeverityByOrg(Context(c), claims.OrganizationID, f.SiteID)
	byAsset := map[string]map[string]int64{}
	for _, c := range counts {
		m, ok := byAsset[c.AssetID]
		if !ok {
			m = map[string]int64{}
			byAsset[c.AssetID] = m
		}
		m[string(c.Severity)] += c.Count
	}
	type assetListItem struct {
		domain.Asset
		Findings map[string]int64 `json:"findings"`
		// Endpoint is the device collecting data for this asset (nil
		// for scan-only assets) — the list carries the live status so
		// the table needs no separate device registry.
		Endpoint *deviceView `json:"endpoint,omitempty"`
	}
	views := make([]assetListItem, 0, len(items))
	for _, it := range items {
		views = append(views, assetListItem{
			Asset:    it,
			Findings: byAsset[it.ID],
			Endpoint: a.deviceViewByID(Context(c), it.AgentID),
		})
	}
	return c.JSON(fiber.Map{"items": views, "total": total, "page": page, "limit": limit})
}

// deviceViewByID resolves the endpoint-device summary of an asset row
// (nil when the asset has no linked device).

// nonNilSlice guarantees an empty JSON array ([]) instead of null for list
// fields. Go nil slices serialize as null, which crashes JS callers that
// read.length — the asset detail UI crashed exactly this way.
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (a *App) deviceViewByID(ctx context.Context, agentID *string) *deviceView {
	if agentID == nil || *agentID == "" || a.svc.AgentsService == nil {
		return nil
	}
	dev, err := a.svc.AgentsService.Repo.ByIDAnyOrg(ctx, *agentID)
	if err != nil || dev == nil || dev.Revoked {
		return nil
	}
	return deviceViewFor(dev)
}

// serviceView is the serialized shape of a service row: the domain
// row promoted inline plus read-time normalization metadata for the
// version column. version_meta is computed on read, not persisted —
// rows collected before a normalization upgrade render correctly too,
// and the detail always reflects the current normalizer.
type serviceView struct {
	domain.Service
	VersionMeta *fingerprinting.NormalizedVersion `json:"version_meta,omitempty"`
}

// softwareView is serviceView's software-inventory counterpart: the
// normalization runs against the row's own ecosystem label.
type softwareView struct {
	domain.Software
	VersionMeta *fingerprinting.NormalizedVersion `json:"version_meta,omitempty"`
}

func serviceViews(rows []domain.Service) []serviceView {
	out := make([]serviceView, len(rows))
	for i := range rows {
		out[i].Service = rows[i]
		if rows[i].DetectedVersion != "" {
			nv := fingerprinting.NormalizeServiceVersion(rows[i].DetectedVersion)
			out[i].VersionMeta = &nv
		}
	}
	return out
}

func softwareViews(rows []domain.Software) []softwareView {
	out := make([]softwareView, len(rows))
	for i := range rows {
		out[i].Software = rows[i]
		if rows[i].Version != "" {
			nv := fingerprinting.NormalizeObservedVersion(rows[i].Version, rows[i].Ecosystem)
			out[i].VersionMeta = &nv
		}
	}
	return out
}

// interfaceView flattens a network interface for the UI. The browser reads
// `ip` (the address it reaches the host on) and `vlan` - fields the raw
// domain.Interface does not serialize (it keeps historical `addresses` and
// `vlan_id` instead), so the Interfaces table rendered blank Address and
// VLAN columns even when rows were stored. ip prefers the primary address.
type interfaceView struct {
	domain.Interface
	IP   string `json:"ip,omitempty"`
	VLAN *int   `json:"vlan,omitempty"`
}

func interfaceViews(rows []domain.Interface) []interfaceView {
	out := make([]interfaceView, len(rows))
	for i := range rows {
		out[i].Interface = rows[i]
		for _, a := range rows[i].Addresses {
			if a.IsPrimary {
				out[i].IP = a.IP
				break
			}
			if out[i].IP == "" {
				out[i].IP = a.IP
			}
		}
		out[i].VLAN = rows[i].VLANID
	}
	return out
}

// handleGetAsset returns one asset with its relations.
func (a *App) handleGetAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	asset, err := a.svc.Assets.ByID(ctx, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	// Best-effort relations: a failure in one section must not 404 the whole
	// asset view, and nil slices must serialize as [] (never null — a null
	// list crashed the UI reading .length).
	ifaces := nonNilSlice(listOrEmpty(a.svc.Ifaces.ListForAsset(ctx, asset.ID)))
	services := nonNilSlice(listOrEmpty(a.svc.Services.ListForAsset(ctx, asset.ID)))
	software := nonNilSlice(listOrEmpty(a.svc.Software.ListForAsset(ctx, asset.ID)))
	findings := nonNilSlice(listOrEmpty(a.svc.Findings.ListForAsset(ctx, asset.ID)))
	open, crit, high, med, low := 0, 0, 0, 0, 0
	for _, f := range findings {
		if f.Status == domain.FindingOpen || f.Status == domain.FindingAcknowledged || f.Status == domain.FindingInProgress {
			open++
		}
		switch f.Severity {
		case domain.SeverityCritical:
			crit++
		case domain.SeverityHigh:
			high++
		case domain.SeverityMedium:
			med++
		case domain.SeverityLow:
			low++
		}
	}
	groupIDs := nonNilSlice(listOrEmpty(a.svc.Groups.MemberGroupIDs(ctx, claims.OrganizationID, asset.ID)))
	return c.JSON(fiber.Map{
		"asset": asset, "interfaces": interfaceViews(ifaces), "services": serviceViews(services), "software": softwareViews(software),
		"findings_count": fiber.Map{"open": open, "critical": crit, "high": high, "medium": med, "low": low},
		"group_ids":      groupIDs,
		"endpoint":       a.endpointView(ctx, claims.OrganizationID, asset.AgentID),
	})
}

// endpointView summarizes the endpoint device collecting data for an asset
// (nil when the asset has none — scan-only assets). The connector name is
// resolved so the UI can link the asset to the connection that owns the
// collector.
func (a *App) endpointView(ctx context.Context, orgID string, agentID *string) fiber.Map {
	if agentID == nil || *agentID == "" || a.svc.AgentsService == nil {
		return nil
	}
	dev, err := a.svc.AgentsService.Repo.ByIDAnyOrg(ctx, *agentID)
	if err != nil || dev == nil || dev.Revoked {
		return nil
	}
	view := fiber.Map{
		"id": dev.ID, "status": dev.Status, "last_seen": dev.LastSeen.UTC().Format(time.RFC3339),
		"version": dev.AgentVersion, "platform": dev.Platform,
	}
	if dev.ConnectorID != "" && a.svc.ConnectorsService != nil {
		if conn, err := a.svc.ConnectorsService.Get(ctx, orgID, dev.ConnectorID); err == nil {
			view["connector_id"] = conn.ID
			view["connector_name"] = conn.Name
		}
	}
	return view
}

// ---------------------------------------------------------------------------
// Device metrics (asset performance page)

// metricsBucketLadder is the set of "nice" bucket sizes (seconds) the
// density selector rounds to; every chart stays within its point target.
var metricsBucketLadder = []int{1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400}

// pickMetricsBucket chooses the smallest ladder bucket keeping the point
// count at or under target (span/bucket <= target); spans longer than the
// ladder fall back to whole-day multiples.
func pickMetricsBucket(span time.Duration, target int) int {
	if target <= 0 {
		target = 240
	}
	secs := int(span.Seconds())
	for _, b := range metricsBucketLadder {
		if secs/b <= target {
			return b
		}
	}
	day := 86400
	if n := (secs + day*target - 1) / (day * target); n > 1 {
		return day * n
	}
	return day
}

// parseMetricsWindow parses a tail window: the legacy presets, a duration
// ("30s", "5m", "2h", "90") or plain seconds. "Nd" day suffixes are handled
// here — time.ParseDuration has no day unit.
func parseMetricsWindow(w string) (time.Duration, bool) {
	switch w {
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "", "24h":
		return 24 * time.Hour, true
	}
	if n, err := strconv.Atoi(w); err == nil && n > 0 {
		return time.Duration(n) * time.Second, true
	}
	if strings.HasSuffix(w, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(w, "d")); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, true
		}
		return 0, false
	}
	if d, err := time.ParseDuration(w); err == nil && d > 0 {
		return d, true
	}
	return 0, false
}

// metricsRange is the resolved query window of the metrics endpoint.
type metricsRange struct {
	From   time.Time
	To     time.Time
	Bucket int    // seconds per point bucket
	Tail   bool   // true for live tails (window=); false for explicit ranges
	Window string // echoed label ("24h", "30s"…; "range" for from/to)
}

const (
	// metricsMinSpan keeps degenerate windows (0s tails, inverted ranges
	// collapsed to a point) from producing single-bucket queries.
	metricsMinSpan = 10 * time.Second
	// metricsMaxSpan caps both modes at a year of storage — beyond the
	// retention the series is empty anyway.
	metricsMaxSpan = 366 * 24 * time.Hour
)

// resolveMetricsRange validates ?window / ?from / ?to into a query range.
// Tail mode (?window=): preset, duration or seconds — from = now-N with an
// auto bucket (~240 points; legacy presets keep their exact buckets).
// Range mode (?from=&to=): RFC3339 bounds, to defaults to now, no tail —
// the caller disables polling — with an auto bucket (~360 points).
func resolveMetricsRange(window, fromS, toS string, now time.Time) (metricsRange, error) {
	if fromS != "" || toS != "" {
		if window != "" {
			return metricsRange{}, fmt.Errorf("use either window or from/to, not both")
		}
		from, err := time.Parse(time.RFC3339, fromS)
		if err != nil {
			return metricsRange{}, fmt.Errorf("from must be an RFC3339 timestamp")
		}
		to := now
		if toS != "" {
			if to, err = time.Parse(time.RFC3339, toS); err != nil {
				return metricsRange{}, fmt.Errorf("to must be an RFC3339 timestamp")
			}
		}
		if !to.After(from) {
			return metricsRange{}, fmt.Errorf("to must be after from")
		}
		span := to.Sub(from)
		if span < metricsMinSpan {
			return metricsRange{}, fmt.Errorf("range must be at least %s", metricsMinSpan)
		}
		if span > metricsMaxSpan {
			return metricsRange{}, fmt.Errorf("range must not exceed %s", metricsMaxSpan)
		}
		return metricsRange{From: from, To: to, Bucket: pickMetricsBucket(span, 360), Tail: false, Window: "range"}, nil
	}
	span, ok := parseMetricsWindow(window)
	if !ok {
		return metricsRange{}, fmt.Errorf("window must be a preset (1h, 6h, 24h, 7d), a duration like 30s/5m/2h, or seconds")
	}
	if span < metricsMinSpan {
		span = metricsMinSpan
	}
	if span > metricsMaxSpan {
		span = metricsMaxSpan
	}
	if bucket, legacy := legacyMetricsBucket(window); legacy {
		return metricsRange{From: now.Add(-span), To: now, Bucket: bucket, Tail: true, Window: window}, nil
	}
	return metricsRange{From: now.Add(-span), To: now, Bucket: pickMetricsBucket(span, 240), Tail: true, Window: window}, nil
}

// legacyMetricsBucket pins the historical preset buckets so older clients
// keep rendering identical series.
func legacyMetricsBucket(window string) (int, bool) {
	switch window {
	case "1h":
		return 60, true
	case "6h":
		return 300, true
	case "7d":
		return 3600, true
	case "", "24h":
		return 900, true
	}
	return 0, false
}

// handleGetAssetMetrics GET /assets/:id/metrics?window=… | ?from=…&to=…
//
// Performance history of the endpoint device collecting this asset, from
// the ClickHouse metrics tier. Tail mode (?window=30s|5m|24h|7d|seconds)
// returns the most recent span and is polled; range mode (?from=&to=)
// returns a fixed span for static inspection. Assets without a bound
// endpoint (and deployments without the analytics tier) return empty
// series — an empty state, not an error. The response also carries the
// effective from/to/bucket and per-NIC rate series (ifaces) for the
// interface sparklines.
func (a *App) handleGetAssetMetrics(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	asset, err := a.svc.Assets.ByID(ctx, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	rng, err := resolveMetricsRange(c.Query("window"), c.Query("from"), c.Query("to"), time.Now().UTC())
	if err != nil {
		return BadRequest(err.Error())
	}
	empty := fiber.Map{
		"points": []any{}, "latest": nil, "ifaces": []any{},
		"window": rng.Window, "from": rng.From.Format(time.RFC3339), "to": rng.To.Format(time.RFC3339),
		"bucket": rng.Bucket, "tail": rng.Tail,
	}
	if a.svc.CH == nil {
		return c.JSON(empty)
	}
	if asset.AgentID == nil || *asset.AgentID == "" {
		return c.JSON(empty)
	}
	points, err := a.svc.CH.QueryDeviceMetrics(ctx, claims.OrganizationID, *asset.AgentID, rng.From, rng.To, rng.Bucket)
	if err != nil {
		a.svc.Log.Warn("device metrics query failed", "asset", asset.ID, "err", err)
		return c.JSON(empty)
	}
	latest, err := a.svc.CH.LatestDeviceSample(ctx, claims.OrganizationID, *asset.AgentID)
	if err != nil {
		a.svc.Log.Warn("latest device sample query failed", "asset", asset.ID, "err", err)
		latest = nil
	}
	if points == nil {
		points = []chx.DeviceMetricPoint{}
	}
	// Per-NIC sparkline series: coarse enough to stay light (~60 points per
	// interface), never finer than the main charts' bucket.
	ifaceBucket := pickMetricsBucket(rng.To.Sub(rng.From), 60)
	if ifaceBucket < rng.Bucket {
		ifaceBucket = rng.Bucket
	}
	ifaces := []chx.IfaceSeries{}
	if raw, err := a.svc.CH.QueryIfaceSeries(ctx, claims.OrganizationID, *asset.AgentID, rng.From, rng.To, ifaceBucket); err == nil {
		ifaces = groupIfaceSeries(raw)
	} else {
		a.svc.Log.Warn("iface series query failed", "asset", asset.ID, "err", err)
	}
	return c.JSON(fiber.Map{
		"points": points, "latest": latest, "ifaces": ifaces,
		"window": rng.Window, "from": rng.From.Format(time.RFC3339), "to": rng.To.Format(time.RFC3339),
		"bucket": rng.Bucket, "tail": rng.Tail,
	})
}

// IfaceSeries is one NIC's rate history for the interface table.
// (Wire shape declared in the clickhouse package next to the query.)

// groupIfaceSeries folds flat (bucket, nic) rows into per-NIC series,
// ordered by first appearance (the query orders by name, bucket).
func groupIfaceSeries(rows []chx.IfaceSeriesPoint) []chx.IfaceSeries {
	index := map[string]int{}
	out := []chx.IfaceSeries{}
	for _, r := range rows {
		i, ok := index[r.Name]
		if !ok {
			i = len(out)
			index[r.Name] = i
			out = append(out, chx.IfaceSeries{Name: r.Name, Rx: []float64{}, Tx: []float64{}})
		}
		out[i].Rx = append(out[i].Rx, r.RxBPS)
		out[i].Tx = append(out[i].Tx, r.TxBPS)
	}
	return out
}

// listOrEmpty converts a (items, err) repo pair into items, swapping errors
// for empty results — relation sections are best-effort.
func listOrEmpty[T any](items []T, err error) []T {
	if err != nil {
		return []T{}
	}
	return items
}

// handleUpdateAsset updates analyst-controlled fields.
func (a *App) handleUpdateAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	var fields map[string]any
	if err := c.BodyParser(&fields); err != nil {
		return BadRequest("invalid JSON body")
	}
	allowed := map[string]bool{"criticality": true, "exposure": true, "tags": true, "owner": true, "notes": true,
		"name_override": true, "device_type_override": true, "parent_override": true}
	for k := range fields {
		if !allowed[k] {
			delete(fields, k)
		}
	}
	// Analyst overrides (migration 0031): non-destructive corrections on
	// top of scanned data. The scanned columns are never touched here, so
	// clearing the override (NULL) reveals the scanned value again.
	if v, ok := fields["name_override"]; ok {
		switch t := v.(type) {
		case nil:
			fields["name_override"] = nil
		case string:
			n := strings.TrimSpace(t)
			if n == "" {
				fields["name_override"] = nil // empty string clears
			} else {
				if len(n) > 120 {
					return BadRequest("name_override is too long (max 120)")
				}
				fields["name_override"] = n
			}
		default:
			return BadRequest("name_override must be a string or null")
		}
	}
	if v, ok := fields["device_type_override"]; ok {
		switch t := v.(type) {
		case nil:
			fields["device_type_override"] = nil
		case string:
			t = strings.TrimSpace(t)
			if t == "" {
				fields["device_type_override"] = nil // empty string clears
			} else if domain.ValidDeviceType(t) {
				fields["device_type_override"] = t
			} else {
				return BadRequest("unknown device_type_override value")
			}
		default:
			return BadRequest("device_type_override must be a string or null")
		}
	}
	// parent_override (migration 0032) pins the asset's topology parent to
	// another asset of the same organization. The DB CHECK rejects the
	// trivial self-parent; here we additionally require an existing,
	// same-org reference and walk the candidate's override chain to reject
	// cycles before they reach the graph derivation.
	if v, ok := fields["parent_override"]; ok {
		switch t := v.(type) {
		case nil:
			fields["parent_override"] = nil
		case string:
			t = strings.TrimSpace(t)
			if t == "" {
				fields["parent_override"] = nil // empty string clears
			} else {
				if uuid.Validate(t) != nil {
					return BadRequest("parent_override must be an asset id (UUID)")
				}
				if t == c.Params("id") {
					return BadRequest("parent_override cannot reference the asset itself")
				}
				if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, t); err != nil {
					return BadRequest("parent_override must reference an asset in this organization")
				}
				cycle, err := domain.ParentOverrideCycle(func(id string) (*string, error) {
					p, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, id)
					if err != nil {
						return nil, err
					}
					return p.ParentOverride, nil
				}, c.Params("id"), t)
				if err != nil {
					return BadRequest("parent_override chain is invalid")
				}
				if cycle {
					return BadRequest("parent_override would create a cycle")
				}
				fields["parent_override"] = t
			}
		default:
			return BadRequest("parent_override must be a string or null")
		}
	}
	if len(fields) == 0 {
		return BadRequest("no updatable fields provided")
	}
	// Resolve within the caller's organization BEFORE writing: the bare-id
	// update let any asset:write holder modify another tenant's asset.
	if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("asset not found")
	}
	if err := a.svc.Assets.Update(Context(c), claims.OrganizationID, c.Params("id"), fields); err != nil {
		return NotFound("asset not found or update failed")
	}
	asset, _ := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	return c.JSON(asset)
}

func (a *App) handleAssetServices(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	// Org-scoped resolve first: reading by the raw path id alone returned
	// any tenant's service inventory (BOLA).
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil || asset == nil {
		return NotFound("asset not found")
	}
	items, err := a.svc.Services.ListForAsset(Context(c), asset.ID)
	if err != nil {
		return NotFound("asset not found")
	}
	// nil slices serialize as JSON null; JS callers read .length on it.
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

func (a *App) handleAssetSoftware(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil || asset == nil {
		return NotFound("asset not found")
	}
	items, err := a.svc.Software.ListForAsset(Context(c), asset.ID)
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

func (a *App) handleAssetFindings(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil || asset == nil {
		return NotFound("asset not found")
	}
	items, err := a.svc.Findings.ListForAsset(Context(c), asset.ID)
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

// handleRediscoverAsset re-runs vulnerability matching for everything
// already discovered on this asset (services + software inventory) against
// the current CVE index — the "Rediscover" button. Use case: a feed sync
// pulled in new CVEs after the last scan, so previously discovered software
// was never matched against them. No network scan is involved; only the
// correlation pipeline re-runs, and existing findings are refreshed
// (last_seen bumped) rather than duplicated.
func (a *App) handleRediscoverAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	if a.svc.Correlator == nil {
		return Unavailable("correlator unavailable")
	}
	assetID := c.Params("id")
	if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, assetID); err != nil {
		return NotFound("asset not found")
	}
	// Asset-scoped sweep is bounded (a handful of services/software rows),
	// so it runs synchronously and reports real counts instead of a vague 202.
	ctx, cancel := context.WithTimeout(Context(c), 2*time.Minute)
	defer cancel()
	n, err := a.svc.Correlator.SweepAsset(ctx, claims.OrganizationID, assetID)
	if err != nil {
		a.svc.Log.Warn("asset rediscover failed", "asset", assetID, "err", err)
		return Internal("rediscover failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "asset.rediscover", "asset:"+assetID, c.IP(), "", "success",
		map[string]any{"findings_created": n})
	return c.JSON(fiber.Map{"findings_created": n, "detail": "matching refreshed against the current CVE index"})
}

// handleDeleteAsset removes an asset from the inventory (DELETE /assets/:id).
// Deletion is the remedy for false discoveries, temporarily present hosts and
// devices that left the network: the row and every dependent record
// (identifiers, interfaces and their addresses, MACs, services, software,
// findings, group memberships) are removed in one cascading delete. The bound
// endpoint device survives but is unlinked (agents.asset_id is ON DELETE SET
// NULL) — its next inventory report re-provisions the asset, and the next scan
// that sees the address re-creates a scan-side asset, so nothing is lost by
// removing a record that discovery will regenerate. Scan-change history and
// traceroute evidence carry no foreign key and deliberately survive as the
// audit trail of what was observed.
func (a *App) handleDeleteAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	// Resolve first so a missing/foreign-org id is a clean 404 and the audit
	// entry can name what was removed.
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	if err := a.svc.Assets.Delete(Context(c), claims.OrganizationID, asset.ID); err != nil {
		a.svc.Log.Warn("asset delete failed", "asset", asset.ID, "err", err)
		return Internal("asset delete failed")
	}
	if a.svc.DB != nil {
		_ = alerting.EmitAssetDeleted(Context(c), a.svc.DB, claims.OrganizationID, asset.SiteID, asset.ID, "operator")
	}
	userID, ip, ua := a.auditContext(c)
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, userID, "asset.deleted", "asset:"+asset.ID, ip, ua, "success",
		map[string]any{"hostname": asset.Hostname, "primary_ip": asset.PrimaryIP, "had_agent": asset.AgentID != nil && *asset.AgentID != ""})
	return c.SendStatus(204)
}

func (a *App) handleAssetInterfaces(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil || asset == nil {
		return NotFound("asset not found")
	}
	items, err := a.svc.Ifaces.ListForAsset(Context(c), asset.ID)
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": interfaceViews(nonNilSlice(items))})
}

// handleListServices lists observed services org-wide.
func (a *App) handleListServices(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	f := pg.ServiceFilter{
		OrgID:    claims.OrganizationID,
		Product:  c.Query("product"),
		Port:     c.QueryInt("port"),
		Protocol: c.Query("protocol"),
		Search:   c.Query("search"),
		Limit:    limit,
		Page:     page,
	}
	items, total, err := a.svc.Services.List(Context(c), f)
	if err != nil {
		return Internal("service list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

// handleAssetTraces lists the stored traceroute results that COVER this
// asset's address — traces aimed at it (the asset is the target) and traces
// passing through it (the asset is a router/hop on someone else's path).
// Each trace carries the parsed hop path and the raw probe output (nmap
// XML / tracert text) so operators can audit what the scanner observed.
func (a *App) handleAssetTraces(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	asset, err := a.svc.Assets.ByID(ctx, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	// Every address the asset is known by: the primary plus interface
	// observations. A trace "covers" the asset when any of them appears on
	// its hop path.
	ips := make([]string, 0, 4)
	if asset.PrimaryIP != "" {
		ips = append(ips, asset.PrimaryIP)
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		seen[ip] = true
	}
	for _, iface := range listOrEmpty(a.svc.Ifaces.ListForAsset(ctx, asset.ID)) {
		for _, addr := range iface.Addresses {
			if addr.IP != "" && !seen[addr.IP] {
				seen[addr.IP] = true
				ips = append(ips, addr.IP)
			}
		}
	}
	items, err := a.svc.Traces.ForAssetIPs(ctx, claims.OrganizationID, ips, 20)
	if err != nil {
		return Internal("trace query failed")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items), "ips": nonNilSlice(ips)})
}

// ---------------------------------------------------------------------------
// Topology

func (a *App) handleTopology(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	siteID := c.Query("site_id")
	// Empty = org-wide view (UI default before a site is selected); a
	// non-empty value must be a real UUID or the DB would reject the query.
	if siteID != "" && uuid.Validate(siteID) != nil {
		return BadRequest("site_id must be a UUID")
	}
	nodes, edges, err := a.svc.Topology.Graph(Context(c), claims.OrganizationID, siteID)
	if err != nil {
		return Internal("topology query failed")
	}
	// TopologyNode carries its reference as ref_id; the UI reads asset_id
	// for asset-kind nodes (graph ring styling + click-through to the
	// asset detail page). Emit both so clients keep working: the embedded
	// struct flattens in JSON, the alias carries the asset reference.
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		m, err := structToMap(n)
		if err != nil {
			continue
		}
		if n.Kind == domain.NodeAsset && n.RefID != "" {
			m["asset_id"] = n.RefID
		}
		out = append(out, m)
	}
	return c.JSON(fiber.Map{"nodes": out, "edges": nonNilSlice(edges)})
}

// structToMap marshals a value and unmarshals it back into a generic map —
// used to append computed fields to API rows without re-declaring every
// column. Marshaling cannot fail for domain structs (plain JSON types).
func structToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	m := make(map[string]any, 16)
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (a *App) handleTopologyEvidence(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	// Evidence rows carry no organization_id; the repo joins through the
	// edge so a foreign org's edge id yields nothing instead of leaking
	// raw traceroute probes across tenants.
	items, err := a.svc.Topology.EvidenceForEdge(Context(c), claims.OrganizationID, c.Params("edgeID"))
	if err != nil {
		return NotFound("edge not found")
	}
	return c.JSON(fiber.Map{"items": items})
}
