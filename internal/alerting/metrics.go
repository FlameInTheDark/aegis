package alerting

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

var errNoRows = pgx.ErrNoRows

// Metric fields the evaluator understands (all present in the ClickHouse
// device_metrics table). The capabilities API advertises exactly this list.
var MetricFields = []string{"cpu_percent", "mem_used_percent", "rx_bps", "tx_bps", "load1", "load5", "load15"}

// Aggregations supported by the ClickHouse rolling window query.
var Aggregations = []string{"avg", "min", "max", "p95", "sum", "count"}

// MetricAgg is one per-asset aggregate over the evaluation window.
type MetricAgg struct {
	AssetID string
	Value   float64
	Samples int
}

// MetricsSource is the read view of the metrics tier the evaluator needs.
type MetricsSource interface {
	// WindowMetricAggregates returns the aggregate of one metric field per
	// asset over the trailing window, org-scoped.
	WindowMetricAggregates(ctx context.Context, tenantID, field, agg string, window time.Duration) ([]MetricAgg, error)
}

// --- Pure state machine ------------------------------------------------------

// ruleState is the locked evaluation state row.
type ruleState struct {
	state          string
	pendingSince   *time.Time
	lastValue      *float64
	lastTransition *time.Time
	lastEventID    string
}

// Actions the state machine can request from the store.
const (
	actionNone       = "none"
	actionArm        = "arm"         // breach started; activation timer armed
	actionClear      = "clear"       // back to normal before activation
	actionFire       = "fire"        // activation satisfied: open occurrence
	actionRepeat     = "repeat"      // re-notify on an open occurrence
	actionRecoverArm = "recover_arm" // recovery timer started
	actionRecover    = "recover"     // recovery satisfied: close occurrence
)

type metricAction struct {
	kind    string
	degrade bool // mark the rule state degraded (source unavailable)
}

// missingData policies.
const (
	policyIgnore  = domain.MissingDataIgnore
	policyTrigger = domain.MissingDataTrigger
	policyResolve = domain.MissingDataResolve
)

// metricDecision is the deterministic per-step policy: given the locked
// state, the trigger definition and the fresh aggregate, it returns the
// action to apply. Unit tests pin boundary, activation, hysteresis and
// missing-data behavior here — evaluation and storage stay dumb pipes.
func metricDecision(st *ruleState, t *domain.Trigger, value *float64, samples int, now time.Time) metricAction {
	if st == nil {
		st = &ruleState{state: domain.RuleStateNormal}
	}
	// Missing data never reads as healthy: the policy decides what to do,
	// and an infrastructure error (degrade) always preserves prior state.
	if samples <= 0 || value == nil {
		switch t.MissingDataPolicy {
		case policyTrigger:
			return applyBreach(st, t, nil, now)
		case policyResolve:
			if st.state == domain.RuleStateFiring {
				return metricAction{kind: actionRecover}
			}
			return metricAction{kind: actionNone}
		default: // ignore: keep prior state untouched
			return metricAction{kind: actionNone}
		}
	}
	breach := compareThreshold(*value, t.Operator, t.Threshold)
	if breach {
		return applyBreach(st, t, value, now)
	}
	// Not breaching. In firing state, recovery requires the value to be
	// below the hysteresis threshold (when set) for recovery_secs.
	if st.state == domain.RuleStateFiring {
		if !recoveredEnough(*value, t) {
			// Value fell below the alert threshold but not below the
			// hysteresis bound: stay firing.
			return metricAction{kind: actionNone}
		}
		if st.pendingSince == nil {
			return metricAction{kind: actionRecoverArm}
		}
		if now.Sub(*st.pendingSince) >= time.Duration(maxInt(t.RecoverySecs, 1))*time.Second {
			return metricAction{kind: actionRecover}
		}
		return metricAction{kind: actionNone}
	}
	if st.state == domain.RuleStatePending {
		return metricAction{kind: actionClear}
	}
	return metricAction{kind: actionNone}
}

// applyBreach handles the breach branch from any state.
func applyBreach(st *ruleState, t *domain.Trigger, value *float64, now time.Time) metricAction {
	switch st.state {
	case domain.RuleStateFiring:
		// Already firing: a re-breach cancels any recovery arming.
		if st.pendingSince != nil {
			// was arming recovery; a fresh breach cancels it
			return metricAction{kind: actionArm}
		}
		if t.RepeatSecs > 0 && st.lastTransition != nil &&
			now.Sub(*st.lastTransition) >= time.Duration(t.RepeatSecs)*time.Second {
			return metricAction{kind: actionRepeat}
		}
		return metricAction{kind: actionNone}
	case domain.RuleStatePending:
		if st.pendingSince != nil &&
			now.Sub(*st.pendingSince) >= time.Duration(maxInt(t.ActivationSecs, 1))*time.Second {
			return metricAction{kind: actionFire}
		}
		return metricAction{kind: actionNone}
	default: // normal or degraded
		if t.ActivationSecs <= 0 {
			return metricAction{kind: actionFire}
		}
		return metricAction{kind: actionArm}
	}
}

// compareThreshold evaluates value OPERATOR threshold.
func compareThreshold(value float64, op string, threshold float64) bool {
	switch op {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	}
	return false
}

// recoveredEnough applies hysteresis: recovery requires the value on the
// healthy side of the recovery threshold when one is configured.
func recoveredEnough(value float64, t *domain.Trigger) bool {
	if t.RecoveryThreshold == nil {
		return !compareThreshold(value, t.Operator, t.Threshold)
	}
	switch t.Operator {
	case "lt", "lte":
		// alert on low values: recovery means back above the bound
		return value >= *t.RecoveryThreshold
	default: // gt, gte: recovery means at or below the bound
		return value <= *t.RecoveryThreshold
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- Periodic evaluator -------------------------------------------------------

// MetricEvaluator runs the ClickHouse rolling-window evaluation loop.
// A ClickHouse outage must never cause false recovery: on query failure
// the trigger is marked degraded and its states are left untouched.
type MetricEvaluator struct {
	DB           *pg.DB
	Store        *Store
	Triggers     *pg.AlertTriggerRepo
	Destinations *pg.DestinationRepo
	CH           MetricsSource
	Log          *slog.Logger
	Interval     time.Duration
	Now          func() time.Time
}

// Run blocks until ctx is done, evaluating every Interval.
func (e *MetricEvaluator) Run(ctx context.Context) {
	if e.Interval <= 0 {
		e.Interval = 30 * time.Second
	}
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.EvaluateOnce(ctx)
		}
	}
}

// EvaluateOnce performs one evaluation pass over all enabled metric
// triggers, grouped by organization to keep queries org-scoped.
func (e *MetricEvaluator) EvaluateOnce(ctx context.Context) {
	triggers, err := e.Triggers.EnabledMetricTriggers(ctx)
	if err != nil {
		e.Log.Warn("metric evaluator: load triggers failed", "err", err)
		return
	}
	now := e.now()
	byOrg := map[string][]*domain.Trigger{}
	for _, t := range triggers {
		byOrg[t.OrgID] = append(byOrg[t.OrgID], t)
	}
	for orgID, ts := range byOrg {
		dests, err := e.Destinations.List(ctx, orgID)
		if err != nil {
			e.Log.Warn("metric evaluator: destinations unavailable", "org", orgID, "err", err)
			dests = nil
		}
		for _, t := range ts {
			window := time.Duration(t.WindowSecs) * time.Second
			if window <= 0 {
				window = 5 * time.Minute
			}
			aggs, err := e.CH.WindowMetricAggregates(ctx, orgID, t.MetricField, t.Aggregation, window)
			if err != nil {
				// Preserve prior state; surface the degraded condition.
				_ = e.Triggers.SetLastError(ctx, t.ID, "clickhouse: "+err.Error())
				continue
			}
			for _, agg := range aggs {
				if !scopeAllows(t, agg.AssetID) {
					continue
				}
				v := agg.Value
				if _, err := e.Store.MetricState(ctx, t, agg.AssetID, &v, agg.Samples, dests, now); err != nil {
					e.Log.Warn("metric evaluation failed", "trigger", t.ID, "asset", agg.AssetID, "err", err)
				}
			}
			_ = e.Triggers.TouchEvaluated(ctx, t.ID)
		}
	}
}

func (e *MetricEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

// scopeAllows applies the trigger's asset allowlist (site scoping happens
// in the ClickHouse query; the asset list is the remaining client filter).
func scopeAllows(t *domain.Trigger, assetID string) bool {
	if len(t.Scope.AssetIDs) == 0 {
		return true
	}
	for _, a := range t.Scope.AssetIDs {
		if a == assetID {
			return true
		}
	}
	return false
}

// TestMetricSample runs the state machine against one synthetic/observed
// sample for the editor's Test action. It returns the action kind without
// touching any state: "fire", "arm", "none", "repeat" or "recover".
func TestMetricSample(t *domain.Trigger, value float64, samples int) string {
	act := metricDecision(nil, t, &value, samples, time.Now().UTC())
	return act.kind
}
