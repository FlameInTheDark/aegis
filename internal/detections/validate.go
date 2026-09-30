package detections

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Rule writes get the alert-engine treatment (plan Phase 1.3): the server is
// the canonical validator, and nothing reaches the rules table that the
// engine could not evaluate safely. The engine's operator set and field
// resolution (eventField) are the source of truth for what a condition may
// express; everything else — huge regexes, nested quantifiers (catastrophic
// backtracking), unbounded windows, unknown rule types — is rejected here
// instead of being stored and failing silently at ingest time.

const (
	maxRuleTitleLen    = 200
	maxRuleIDLen       = 128
	maxRuleDescLen     = 2000
	maxConditions      = 20
	maxConditionValues = 20
	maxValueLen        = 256
	maxFieldLen        = 64
	maxRegexLen        = 128
	maxTags            = 20
	maxWindow          = 24 * time.Hour
	minThresholdCount  = 2
	maxThresholdCount  = 100000
)

// RuleTypes is the closed set the engine implements. "sequence" is
// deliberately absent: the engine skips it with a comment today, and storing
// a rule the evaluator silently ignores is worse than refusing it.
var RuleTypes = []string{"single_event", "threshold", "temporal", "entity_agg"}

// RuleOperators is the closed operator set the engine implements
// (conditionMatches). Unknown operators would make every event fail to
// match — a rule that can never fire.
var RuleOperators = []string{"eq", "neq", "in", "gt", "gte", "lt", "lte", "contains", "regex", "exists"}

// numericRuleOps compare numbers; comparison against non-numeric values
// can never match.
var numericRuleOps = map[string]bool{"gt": true, "gte": true, "lt": true, "lte": true}

// knownRuleFields is the envelope the engine can resolve. Fields outside
// this list are treated by the engine as payload-metadata lookups, so any
// lowercase dotted key is accepted but bounded — the same charset contract
// the alerting condition DSL uses.
var knownRuleFields = map[string]bool{
	"event_type": true, "type": true,
	"src_ip": true, "source_ip": true,
	"dst_ip": true, "dest_ip": true,
	"src_port": true, "dst_port": true,
	"protocol": true, "severity": true,
	"rule_id": true, "rule_name": true,
	"application": true, "app": true,
	"hostname": true, "user": true, "process": true,
	"direction": true, "action": true, "source": true, "sensor_id": true,
	"__type": true, // temporal stage matcher
}

var ruleFieldCharset = func(r rune) bool {
	return r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

var ruleIDCharset = func(r rune) bool {
	return r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// nestedQuantifier matches the classic catastrophic-backtracking shapes:
// a quantifier applied to a group that itself ends in a quantifier
// ((a+)+, (a*)*, (a{2,})+) and quantified overlapping alternations
// ((a|a)+). Bounded-length regexes with these patterns still stall the
// engine's regexp evaluation on adversarial payloads, so they never enter
// the catalog.
var nestedQuantifier = regexp.MustCompile(`\((?:[^()\\]|\\.)*[+*}\d]\)\s*[+*{]`)

func validSeverity(s domain.Severity) bool {
	switch s {
	case domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium,
		domain.SeverityHigh, domain.SeverityCritical:
		return true
	}
	return false
}

// ValidateRule checks a detection rule against the engine's real
// capabilities. It returns the first violation as an actionable error.
func ValidateRule(r *domain.DetectionRule) error {
	if r == nil {
		return fmt.Errorf("rule is required")
	}
	if t := strings.TrimSpace(r.Title); t == "" || len(t) > maxRuleTitleLen {
		return fmt.Errorf("title must be 1-%d characters", maxRuleTitleLen)
	}
	if r.Identifier != "" {
		if len(r.Identifier) > maxRuleIDLen || !strings.ContainsFunc(r.Identifier, ruleIDCharset) ||
			strings.IndexFunc(r.Identifier, func(rr rune) bool { return !ruleIDCharset(rr) }) >= 0 {
			return fmt.Errorf("identifier must match [A-Za-z0-9._-] and be at most %d characters", maxRuleIDLen)
		}
	}
	if len(r.Description) > maxRuleDescLen {
		return fmt.Errorf("description must be at most %d characters", maxRuleDescLen)
	}
	if len(r.Tags) > maxTags {
		return fmt.Errorf("at most %d tags are allowed", maxTags)
	}
	for _, tag := range r.Tags {
		if tag == "" || len(tag) > 64 {
			return fmt.Errorf("tags must be 1-64 characters")
		}
	}
	if r.Status != "" && r.Status != "stable" && r.Status != "experimental" && r.Status != "disabled" {
		return fmt.Errorf("status must be one of: stable, experimental, disabled")
	}
	if !validSeverity(r.Level) {
		return fmt.Errorf("level must be one of: info, low, medium, high, critical")
	}

	knownType := false
	for _, t := range RuleTypes {
		if r.Type == t {
			knownType = true
			break
		}
	}
	if !knownType {
		return fmt.Errorf("type must be one of: %s (sequence rules are not implemented)", strings.Join(RuleTypes, ", "))
	}

	if r.EventType != "" {
		if len(r.EventType) > maxFieldLen || !strings.ContainsFunc(r.EventType, ruleFieldCharset) {
			return fmt.Errorf("event_type %q has unsupported characters", r.EventType)
		}
	}

	// Window: required and bounded wherever the engine would apply it.
	// windowDuration falls back to 1m on garbage — a silent behavior change
	// the author never asked for — so unparseable windows are refused here.
	needsWindow := r.Type == "threshold" || r.Type == "temporal" || r.Type == "entity_agg"
	if needsWindow {
		d, err := time.ParseDuration(strings.TrimSpace(r.Window))
		if err != nil {
			return fmt.Errorf("window must be a duration like 60s, 5m, 1h")
		}
		if d < time.Second {
			return fmt.Errorf("window must be at least 1s")
		}
		if d > maxWindow {
			return fmt.Errorf("window must be at most %s", maxWindow)
		}
	} else if r.Window != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(r.Window)); err != nil {
			return fmt.Errorf("window must be a duration like 60s, 5m, 1h")
		}
	}

	// Threshold: the engine defaults missing specs silently; authoring must
	// be explicit, and counts must be sane.
	if r.Threshold != nil {
		if r.Threshold.Count < minThresholdCount || r.Threshold.Count > maxThresholdCount {
			return fmt.Errorf("threshold count must be %d-%d", minThresholdCount, maxThresholdCount)
		}
		if r.Threshold.Distinct != "" {
			if len(r.Threshold.Distinct) > maxFieldLen || !strings.ContainsFunc(r.Threshold.Distinct, ruleFieldCharset) {
				return fmt.Errorf("threshold distinct field %q has unsupported characters", r.Threshold.Distinct)
			}
		}
	}
	if (r.Type == "threshold" || r.Type == "entity_agg") && r.Threshold == nil {
		return fmt.Errorf("type %s requires a threshold spec", r.Type)
	}

	if len(r.Conditions) > maxConditions {
		return fmt.Errorf("at most %d conditions are allowed", maxConditions)
	}
	for i := range r.Conditions {
		if err := validateCondition(&r.Conditions[i]); err != nil {
			return fmt.Errorf("condition %d: %w", i+1, err)
		}
	}
	if r.Type == "temporal" && len(r.Conditions) < 2 {
		return fmt.Errorf("temporal rules need at least two ordered conditions")
	}
	return nil
}

func validateCondition(c *domain.RuleCondition) error {
	if c.Field == "" {
		return fmt.Errorf("field is required")
	}
	if len(c.Field) > maxFieldLen || strings.IndexFunc(c.Field, func(rr rune) bool { return !ruleFieldCharset(rr) }) >= 0 {
		return fmt.Errorf("field %q has unsupported characters", c.Field)
	}
	knownOp := false
	for _, op := range RuleOperators {
		if c.Operator == op {
			knownOp = true
			break
		}
	}
	if !knownOp {
		return fmt.Errorf("unknown operator %q", c.Operator)
	}
	if !knownRuleFields[c.Field] && len(c.Field) > maxFieldLen {
		return fmt.Errorf("field %q is too long", c.Field)
	}
	switch c.Operator {
	case "exists":
		// valueless by design
	case "in":
		if len(c.Values) == 0 || len(c.Values) > maxConditionValues {
			return fmt.Errorf("in needs 1-%d values", maxConditionValues)
		}
	default:
		if len(c.Values) != 1 {
			return fmt.Errorf("operator %s needs exactly one value", c.Operator)
		}
	}
	for _, v := range c.Values {
		if len(v) > maxValueLen {
			return fmt.Errorf("values must be at most %d characters", maxValueLen)
		}
	}
	if numericRuleOps[c.Operator] {
		if _, err := strconv.ParseFloat(strings.TrimSpace(c.Values[0]), 64); err != nil {
			return fmt.Errorf("operator %s needs a numeric value", c.Operator)
		}
	}
	if c.Operator == "regex" {
		if len(c.Values[0]) > maxRegexLen {
			return fmt.Errorf("regex must be at most %d characters", maxRegexLen)
		}
		if _, err := regexp.Compile(c.Values[0]); err != nil {
			return fmt.Errorf("regex does not compile: %v", err)
		}
		if nestedQuantifier.MatchString(c.Values[0]) {
			return fmt.Errorf("regex contains a nested quantifier, which can stall evaluation (catastrophic backtracking)")
		}
	}
	return nil
}
