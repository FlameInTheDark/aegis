// Platform settings API: operator-controlled platform behavior (currently
// the device metrics retention) backed by the settings KV store.
// Reads are open to any authenticated user; changes require
// settings:manage and are audited.

package httpx

import (
	"context"
	"encoding/json"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	chx "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	"github.com/FlameInTheDark/aegis/internal/retention"
	"github.com/gofiber/fiber/v2"
)

// metricsSettingsView is the API projection of the metrics settings.
type metricsSettingsView struct {
	// RetentionDays is the configured retention (0 = keep forever).
	RetentionDays int `json:"retention_days"`
	// AppliedDays is what the device_metrics TTL is currently synced to
	// (differs briefly after a change until the retention loop applies it).
	AppliedDays int `json:"applied_days"`
	// Stats is a storage snapshot; nil when the analytics tier is off.
	Stats *chx.DeviceMetricsStats `json:"stats,omitempty"`
}

type settingsView struct {
	Metrics metricsSettingsView `json:"metrics"`
}

// settingsStore returns the settings repo, nil-safe for tests.
func (a *App) settingsStore() settingGetterSetter {
	if a.svc.Retention == nil {
		return nil
	}
	return a.svc.Retention.Settings
}

type settingGetterSetter interface {
	Get(ctx context.Context, key string) (json.RawMessage, error)
	Set(ctx context.Context, key string, value json.RawMessage) error
}

// handleGetSettings GET /settings — the effective platform settings plus a
// storage snapshot. Anyone authenticated may read; only settings:manage
// may change (the SPA hides the editors on 403 the same way as elsewhere).
func (a *App) handleGetSettings(c *fiber.Ctx) error {
	ctx := Context(c)
	view := settingsView{Metrics: metricsSettingsView{RetentionDays: retention.DefaultRetentionDays, AppliedDays: retention.DefaultRetentionDays}}
	store := a.settingsStore()
	if store != nil {
		if days, err := retention.EffectiveDays(ctx, store); err == nil {
			view.Metrics.RetentionDays = days
		}
		if applied, err := store.Get(ctx, retention.KeyRetentionApplied); err == nil && applied != nil {
			var n int
			if json.Unmarshal(applied, &n) == nil && n >= 0 {
				view.Metrics.AppliedDays = n
			}
		}
	}
	if a.svc.CH != nil {
		if stats, err := a.svc.CH.DeviceMetricsStats(ctx); err == nil {
			view.Metrics.Stats = &stats
		}
	}
	return c.JSON(view)
}

// handleUpdateSettings PATCH /settings — update platform settings. Body:
//
//	{"metrics": {"retention_days": 30}}   // 0 = keep forever
//
// Unknown keys are ignored (the view is additive by design). A retention
// change pokes the retention loop, which syncs the ClickHouse TTL and
// purges beyond the new window right away.
func (a *App) handleUpdateSettings(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	claims := a.claimsFrom(c)
	var req struct {
		Metrics *struct {
			RetentionDays *int `json:"retention_days"`
		} `json:"metrics"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid JSON body")
	}
	if req.Metrics == nil || req.Metrics.RetentionDays == nil {
		return BadRequest("no settings to update: expected {\"metrics\":{\"retention_days\":N}}")
	}
	days := *req.Metrics.RetentionDays
	if days < 0 || days > retention.MaxRetentionDays {
		return BadRequest("retention_days must be between 0 (keep forever) and 3650")
	}
	store := a.settingsStore()
	if store == nil {
		return Internal("settings store unavailable")
	}
	raw, _ := json.Marshal(days)
	if err := store.Set(Context(c), retention.KeyRetention, raw); err != nil {
		return Internal("could not save settings")
	}
	if a.svc.Retention != nil {
		a.svc.Retention.Notify()
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "settings.updated", "settings:metrics.retention_days", c.IP(), c.Get("User-Agent"), "success",
		map[string]any{"retention_days": days})
	return c.JSON(settingsView{Metrics: metricsSettingsView{RetentionDays: days, AppliedDays: days}})
}

// handleMetricsCleanup POST /settings/metrics/cleanup — run a synchronous
// purge of everything older than the configured retention. Reports the
// cutoff and a row estimate captured before the mutation started.
func (a *App) handleMetricsCleanup(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	claims := a.claimsFrom(c)
	if a.svc.CH == nil || a.svc.Retention == nil {
		return BadRequest("the analytics tier is not configured on this deployment")
	}
	// Bound the synchronous mutation well under the fiber write timeout —
	// if it cannot finish in time the mutation keeps running in ClickHouse
	// and the operator retries when storage catches up.
	ctx, cancel := context.WithTimeout(Context(c), 30*time.Second)
	defer cancel()
	cutoff, days, estimate, err := a.svc.Retention.SweepNow(ctx, a.svc.CH.CountDeviceMetricsBefore)
	if err != nil {
		a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "metrics.cleanup", "settings:metrics", c.IP(), c.Get("User-Agent"), "failure",
			map[string]any{"err": err.Error()})
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "metrics.cleanup", "settings:metrics", c.IP(), c.Get("User-Agent"), "success",
		map[string]any{"retention_days": days, "cutoff": cutoff.Format(time.RFC3339), "estimate_rows": estimate})
	return c.JSON(fiber.Map{
		"status": "cleanup started", "retention_days": days,
		"cutoff": cutoff.Format(time.RFC3339), "estimate_rows": estimate,
	})
}
