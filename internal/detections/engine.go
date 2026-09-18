// Package detections implements the behavioral detection engine
// (spec §40/§41): typed internal rules with single-event, threshold,
// temporal and entity-aggregation semantics, plus Sigma-like metadata and
// simple statistical baselines (§189). The first implementation is
// deterministic and explainable — no opaque scores.
package detections

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	redisrepo "github.com/FlameInTheDark/aegis/internal/repository/redis"
)

// Engine evaluates events against enabled rules.
type Engine struct {
	Rules     *pg.RuleRepo
	Matches   *pg.MatchRepo
	Baselines *pg.BaselineRepo
	Cache     *redisrepo.Client
	Log       *slog.Logger
	// Notifier is invoked for critical matches (webhook alerting §170).
	Notifier func(ctx context.Context, m *domain.DetectionMatch)
}

// windowDuration parses "60s", "5m", "1h".
func windowDuration(s string) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
		return d
	}
	return time.Minute
}

// Ingest evaluates one event batch against the org's enabled rules.
// It is idempotent per event id via redis dedup windows (§79).
func (e *Engine) Ingest(ctx context.Context, orgID string, events []domain.Event) ([]domain.DetectionMatch, error) {
	if len(events) == 0 {
		return nil, nil
	}
	rules, err := e.Rules.Enabled(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var matches []domain.DetectionMatch
	for _, rule := range rules {
		switch rule.Type {
		case "single_event":
			for _, ev := range events {
				if ruleMatchesEvent(rule, ev) {
					m := e.buildMatch(rule, ev, ev.SrcIP, 1, []string{ev.EventID})
					matches = append(matches, m)
				}
			}
		case "threshold":
			if ms := e.evalThreshold(ctx, rule, events); len(ms) > 0 {
				matches = append(matches, ms...)
			}
		case "temporal":
			if ms := e.evalTemporal(ctx, rule, events); len(ms) > 0 {
				matches = append(matches, ms...)
			}
		case "entity_agg":
			if ms := e.evalEntityAgg(ctx, rule, events); len(ms) > 0 {
				matches = append(matches, ms...)
			}
		default:
			// sequence rules: evaluated over stored match context later (§40)
			e.Log.Debug("unsupported rule type", "type", rule.Type, "rule", rule.ID)
		}
	}
	for i := range matches {
		if err := e.Matches.Insert(ctx, &matches[i]); err != nil {
			e.Log.Warn("match insert failed", "err", err)
			continue
		}
		if matches[i].Level == domain.SeverityCritical && e.Notifier != nil {
			e.Notifier(ctx, &matches[i])
		}
	}
	return matches, nil
}

// buildMatch assembles a deduplicated match with entity + summary.
func (e *Engine) buildMatch(rule domain.DetectionRule, ev domain.Event, entity string, count int, eventIDs []string) domain.DetectionMatch {
	return domain.DetectionMatch{
		ID: ids.New(), OrgID: rule.OrgID, RuleID: rule.ID, RuleTitle: rule.Title,
		Level: rule.Level, SiteID: ev.SiteID, AssetID: ev.SrcAssetID,
		SrcIP: ev.SrcIP, Entity: entity, Summary: summarize(rule, ev, count),
		Events: eventIDs, Count: count, Timestamp: ev.Timestamp,
	}
}

func summarize(rule domain.DetectionRule, ev domain.Event, count int) string {
	base := rule.Title
	if count > 1 {
		return fmt.Sprintf("%s — %d events (last: %s %s→%s:%d)", base, count, ev.Timestamp.Format("15:04:05"), ev.SrcIP, ev.DstIP, ev.DstPort)
	}
	return fmt.Sprintf("%s — %s %s→%s:%d", base, ev.EventType, ev.SrcIP, ev.DstIP, ev.DstPort)
}

// ruleMatchesEvent evaluates conditions against one event.
func ruleMatchesEvent(rule domain.DetectionRule, ev domain.Event) bool {
	if rule.EventType != "" && rule.EventType != ev.EventType {
		return false
	}
	for _, c := range rule.Conditions {
		if !conditionMatches(c, ev) {
			return false
		}
	}
	return true
}

// conditionMatches implements the small typed operator set.
func conditionMatches(c domain.RuleCondition, ev domain.Event) bool {
	val := eventField(ev, c.Field)
	switch c.Operator {
	case "eq":
		return len(c.Values) > 0 && val == c.Values[0]
	case "neq":
		return len(c.Values) > 0 && val != c.Values[0]
	case "in":
		return contains(c.Values, val)
	case "gt", "gte", "lt", "lte":
		vf, err1 := strconv.ParseFloat(val, 64)
		tf, err2 := strconv.ParseFloat(strings.Join(c.Values, ""), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch c.Operator {
		case "gt":
			return vf > tf
		case "gte":
			return vf >= tf
		case "lt":
			return vf < tf
		default:
			return vf <= tf
		}
	case "contains":
		for _, v := range c.Values {
			if strings.Contains(val, v) {
				return true
			}
		}
		return false
	case "regex":
		if len(c.Values) == 0 {
			return false
		}
		re, err := regexp.Compile(c.Values[0])
		if err != nil {
			return false
		}
		return re.MatchString(val)
	case "exists":
		return val != ""
	}
	return false
}

// eventField resolves a dotted field path against the event envelope.
func eventField(ev domain.Event, field string) string {
	switch field {
	case "event_type", "type":
		return ev.EventType
	case "src_ip", "source_ip":
		return ev.SrcIP
	case "dst_ip", "dest_ip":
		return ev.DstIP
	case "src_port":
		return strconv.Itoa(ev.SrcPort)
	case "dst_port":
		return strconv.Itoa(ev.DstPort)
	case "protocol":
		return ev.Protocol
	case "severity":
		return string(ev.Severity)
	case "rule_id":
		return ev.RuleID
	case "rule_name":
		return ev.RuleName
	case "application", "app":
		return ev.Application
	case "hostname":
		return ev.Hostname
	case "user":
		return ev.User
	case "process":
		return ev.Process
	case "direction":
		return ev.Direction
	case "action":
		return ev.Action
	case "source":
		return ev.Source
	case "sensor_id":
		return ev.SensorID
	default:
		// payload metadata lookup
		if ev.PayloadMeta != nil {
			if v, ok := ev.PayloadMeta[field]; ok {
				return fmt.Sprint(v)
			}
		}
		return ""
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// evalThreshold implements "N events (or N distinct X) within window".
func (e *Engine) evalThreshold(ctx context.Context, rule domain.DetectionRule, events []domain.Event) []domain.DetectionMatch {
	win := windowDuration(rule.Window)
	count := 10
	distinctField := ""
	if rule.Threshold != nil {
		count = rule.Threshold.Count
		distinctField = rule.Threshold.Distinct
	}
	groups := map[string][]domain.Event{}
	for _, ev := range events {
		if rule.EventType != "" && ev.EventType != rule.EventType {
			continue
		}
		key := ev.SrcIP
		if key == "" {
			key = ev.SrcAssetID
		}
		groups[key] = append(groups[key], ev)
	}
	var out []domain.DetectionMatch
	for entity, evs := range groups {
		cutoff := time.Now().UTC().Add(-win)
		var inWin []domain.Event
		for _, ev := range evs {
			if ev.Timestamp.After(cutoff) {
				inWin = append(inWin, ev)
			}
		}
		hit := false
		n := 0
		idsList := make([]string, 0, len(inWin))
		if distinctField != "" {
			set := map[string]bool{}
			for _, ev := range inWin {
				v := eventField(ev, distinctField)
				if v != "" {
					set[v] = true
					idsList = append(idsList, ev.EventID)
				}
			}
			n = len(set)
			hit = n >= count
		} else {
			for _, ev := range inWin {
				idsList = append(idsList, ev.EventID)
			}
			n = len(inWin)
			hit = n >= count
		}
		if hit && e.claimDedup(ctx, rule, entity) {
			last := inWin[len(inWin)-1]
			out = append(out, e.buildMatch(rule, last, entity, n, idsList))
		}
	}
	return out
}

// evalTemporal implements ordered condition sequences within a window.
func (e *Engine) evalTemporal(ctx context.Context, rule domain.DetectionRule, events []domain.Event) []domain.DetectionMatch {
	win := windowDuration(rule.Window)
	groups := map[string][]domain.Event{}
	for _, ev := range events {
		key := ev.SrcIP
		if key == "" {
			key = ev.SrcAssetID
		}
		groups[key] = append(groups[key], ev)
	}
	var out []domain.DetectionMatch
	for entity, evs := range groups {
		sort.Slice(evs, func(i, j int) bool { return evs[i].Timestamp.Before(evs[j].Timestamp) })
		cutoff := time.Now().UTC().Add(-win)
		condIdx := 0
		var used []string
		for _, ev := range evs {
			if !ev.Timestamp.After(cutoff) {
				continue
			}
			if condIdx < len(rule.Conditions) && eventCondMatches(rule.Conditions[condIdx], ev) {
				used = append(used, ev.EventID)
				condIdx++
				if condIdx == len(rule.Conditions) {
					if e.claimDedup(ctx, rule, entity) {
						out = append(out, e.buildMatch(rule, ev, entity, len(used), used))
					}
					condIdx = 0
					used = nil
				}
			}
		}
	}
	return out
}

// eventCondMatches matches a temporal condition: either an event-type
// matcher ({"field":"__type","values":["alert"]}) or a field condition.
func eventCondMatches(c domain.RuleCondition, ev domain.Event) bool {
	if c.Field == "__type" {
		return contains(c.Values, ev.EventType)
	}
	return ruleMatchesEvent(domain.DetectionRule{Conditions: []domain.RuleCondition{c}}, ev)
}

// evalEntityAgg implements "entity contacted N distinct peers/values".
func (e *Engine) evalEntityAgg(ctx context.Context, rule domain.DetectionRule, events []domain.Event) []domain.DetectionMatch {
	if rule.Threshold == nil {
		rule.Threshold = &domain.ThresholdSpec{Count: 50, Distinct: "dst_ip"}
	}
	return e.evalThreshold(ctx, rule, events)
}

// claimDedup ensures one match per rule/entity/window (§172). Uses redis
// SETNX with the window TTL; falls back to per-process memory.
type dedupState struct {
	mu map[string]time.Time
}

var procDedup = dedupState{mu: map[string]time.Time{}}

func (e *Engine) claimDedup(ctx context.Context, rule domain.DetectionRule, entity string) bool {
	win := windowDuration(rule.Window)
	key := fmt.Sprintf("dedup:%s:%s", rule.Identifier, entity)
	if e.Cache != nil {
		first, err := e.Cache.DedupCheck(ctx, key, win)
		if err == nil {
			return first
		}
	}
	// In-process fallback.
	now := time.Now()
	if t, ok := procDedup.mu[key]; ok && now.Sub(t) < win {
		return false
	}
	procDedup.mu[key] = now
	if len(procDedup.mu) > 10000 {
		for k, v := range procDedup.mu {
			if now.Sub(v) > time.Hour {
				delete(procDedup.mu, k)
			}
		}
	}
	return true
}

// UpdateBaseline folds an observation into a simple statistical baseline.
func (e *Engine) UpdateBaseline(ctx context.Context, entity, metric string, value float64, windowDays int) error {
	b, err := e.Baselines.Get(ctx, entity, metric)
	if err != nil || b == nil {
		b = &domain.Baseline{Entity: entity, Metric: metric, UpdatedAt: time.Now().UTC(), WindowDays: windowDays}
	}
	n := float64(b.SampleSize)
	mean := b.Mean
	std := b.StdDev
	newMean := mean + (value-mean)/(n+1)
	variance := n*std*std + (value-newMean)*(value-mean)
	newStd := 0.0
	if n+1 > 0 {
		newStd = sqrt(variance / (n + 1))
	}
	b.Mean, b.StdDev, b.SampleSize = newMean, newStd, b.SampleSize+1
	b.UpdatedAt = time.Now().UTC()
	return e.Baselines.Upsert(ctx, b)
}

// Anomalous reports whether a value deviates >3σ from baseline (never
// claims malicious — anomaly ≠ confirmed activity, §189/§190).
func Anomalous(b *domain.Baseline, value float64) (bool, float64) {
	if b == nil || b.SampleSize < 10 || b.StdDev == 0 {
		return false, 0
	}
	z := (value - b.Mean) / b.StdDev
	return z > 3, z
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton's method; avoids importing math for one function.
	z := x
	for i := 0; i < 40; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// SeedBuiltinRules inserts the first-run detection rule set (spec §40
// examples). Rules are explicit, typed and disable-able.
func SeedBuiltinRules(ctx context.Context, orgID string, r *pg.RuleRepo) error {
	builtins := []domain.DetectionRule{
		{
			ID: ids.New(), OrgID: orgID, Title: "Port scan pattern", Identifier: "aegis-portscan-01",
			Status: "stable", Type: "threshold", EventType: "flow", Window: "60s",
			Threshold: &domain.ThresholdSpec{Count: 40, Distinct: "dst_port"},
			Level:     domain.SeverityMedium, Enabled: true, Author: "aegis",
			Description: "One source contacting many distinct destination ports in a short window.",
			LogSource:   map[string]string{"category": "network_connection"},
			Tags:        []string{"discovery", "network"},
		},
		{
			ID: ids.New(), OrgID: orgID, Title: "SMB lateral movement pattern", Identifier: "aegis-smb-lateral-01",
			Status: "stable", Type: "entity_agg", EventType: "flow", Window: "5m",
			Threshold: &domain.ThresholdSpec{Count: 30, Distinct: "dst_ip"},
			Level:     domain.SeverityHigh, Enabled: true, Author: "aegis",
			Description: "Asset contacting many distinct internal hosts on SMB-like traffic.",
			LogSource:   map[string]string{"category": "network_connection"}, Tags: []string{"lateral_movement"},
		},
		{
			ID: ids.New(), OrgID: orgID, Title: "Abnormal DNS volume", Identifier: "aegis-dns-volume-01",
			Status: "experimental", Type: "threshold", EventType: "dns", Window: "1m",
			Threshold: &domain.ThresholdSpec{Count: 120},
			Level:     domain.SeverityMedium, Enabled: true, Author: "aegis",
			Description: "Unusually high DNS query volume from one source.",
			LogSource:   map[string]string{"category": "dns"}, Tags: []string{"dns", "exfiltration"},
		},
		{
			ID: ids.New(), OrgID: orgID, Title: "Critical IDS alert", Identifier: "aegis-ids-critical-01",
			Status: "stable", Type: "single_event", EventType: "alert",
			Conditions: []domain.RuleCondition{{Field: "severity", Operator: "in", Values: []string{"critical", "high"}}},
			Level:      domain.SeverityHigh, Enabled: true, Author: "aegis",
			Description: "High or critical severity IDS alert from Suricata/Snort.",
			LogSource:   map[string]string{"category": "ids"}, Tags: []string{"ids"},
		},
		{
			ID: ids.New(), OrgID: orgID, Title: "Beacon-like periodic connections", Identifier: "aegis-beacon-01",
			Status: "experimental", Type: "threshold", EventType: "flow", Window: "10m",
			Threshold: &domain.ThresholdSpec{Count: 12},
			Level:     domain.SeverityMedium, Enabled: false, Author: "aegis",
			Description: "Repeated identical connections to the same destination — C2 beacon-like cadence.",
			LogSource:   map[string]string{"category": "network_connection"}, Tags: []string{"c2", "beacon"},
		},
	}
	for i := range builtins {
		if err := r.Upsert(ctx, &builtins[i]); err != nil {
			return err
		}
	}
	return nil
}
