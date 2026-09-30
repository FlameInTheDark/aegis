package detections

import (
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func validThresholdRule() *domain.DetectionRule {
	return &domain.DetectionRule{
		Title: "Port scan pattern", Identifier: "custom-portscan", Status: "stable",
		Type: "threshold", EventType: "flow", Window: "60s",
		Threshold: &domain.ThresholdSpec{Count: 40, Distinct: "dst_port"},
		Level:     domain.SeverityMedium, Enabled: true, Author: "analyst",
	}
}

func TestValidateRuleAcceptsEngineShapes(t *testing.T) {
	rules := []*domain.DetectionRule{
		validThresholdRule(),
		{
			Title: "Critical IDS alert", Type: "single_event", EventType: "alert",
			Conditions: []domain.RuleCondition{{Field: "severity", Operator: "in", Values: []string{"critical", "high"}}},
			Level:      domain.SeverityHigh,
		},
		{
			Title: "Ordered beacon stages", Type: "temporal", Window: "5m",
			Conditions: []domain.RuleCondition{
				{Field: "__type", Operator: "in", Values: []string{"flow"}},
				{Field: "dst_port", Operator: "eq", Values: []string{"4444"}},
			},
			Level: domain.SeverityHigh,
		},
		{
			Title: "Broad peer contact", Type: "entity_agg", Window: "5m",
			Threshold: &domain.ThresholdSpec{Count: 30, Distinct: "dst_ip"},
			Level:     domain.SeverityMedium,
		},
	}
	for _, r := range rules {
		if err := ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%s) = %v, want nil", r.Title, err)
		}
	}
}

func TestValidateRuleRejectsUnknownType(t *testing.T) {
	r := validThresholdRule()
	r.Type = "sequence"
	err := ValidateRule(r)
	if err == nil || !strings.Contains(err.Error(), "type must be one of") {
		t.Fatalf("ValidateRule(sequence) = %v, want type allowlist error", err)
	}
}

func TestValidateRuleRejectsBadWindow(t *testing.T) {
	for _, w := range []string{"", "soon", "500ms", "25h"} {
		r := validThresholdRule()
		r.Window = w
		if err := ValidateRule(r); err == nil {
			t.Fatalf("ValidateRule(window=%q) = nil, want error", w)
		}
	}
}

func TestValidateRuleRejectsBadThreshold(t *testing.T) {
	r := validThresholdRule()
	r.Threshold.Count = 1
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("ValidateRule(count=1) = %v, want count error", err)
	}
	r = validThresholdRule()
	r.Threshold = nil
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "requires a threshold") {
		t.Fatalf("ValidateRule(no threshold) = %v, want required error", err)
	}
}

func TestValidateRuleRejectsNestedQuantifierRegex(t *testing.T) {
	cases := []string{
		`(a+)+`,
		`(.*)*`,
		`(a{2,})+b`,
	}
	for _, re := range cases {
		r := validThresholdRule()
		r.Type = "single_event"
		r.Window = ""
		r.Threshold = nil
		r.Conditions = []domain.RuleCondition{{Field: "hostname", Operator: "regex", Values: []string{re}}}
		err := ValidateRule(r)
		if err == nil || !strings.Contains(err.Error(), "nested quantifier") {
			t.Fatalf("ValidateRule(regex %q) = %v, want nested-quantifier rejection", re, err)
		}
	}
}

func TestValidateRuleRejectsBadRegexAndLongRegex(t *testing.T) {
	r := validThresholdRule()
	r.Type = "single_event"
	r.Threshold = nil
	r.Conditions = []domain.RuleCondition{{Field: "hostname", Operator: "regex", Values: []string{"([unclosed"}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "compile") {
		t.Fatalf("ValidateRule(uncompilable regex) = %v, want compile error", err)
	}
	r.Conditions = []domain.RuleCondition{{Field: "hostname", Operator: "regex", Values: []string{strings.Repeat("a", 129)}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "at most 128") {
		t.Fatalf("ValidateRule(129-char regex) = %v, want length error", err)
	}
}

func TestValidateRuleRejectsUnknownOperatorAndNumericMismatch(t *testing.T) {
	r := validThresholdRule()
	r.Type = "single_event"
	r.Threshold = nil
	r.Conditions = []domain.RuleCondition{{Field: "dst_port", Operator: "matches", Values: []string{"22"}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "unknown operator") {
		t.Fatalf("ValidateRule(op=matches) = %v, want operator error", err)
	}
	r.Conditions = []domain.RuleCondition{{Field: "dst_port", Operator: "gt", Values: []string{"high"}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "numeric") {
		t.Fatalf("ValidateRule(gt high) = %v, want numeric error", err)
	}
}

func TestValidateRuleRejectsUnknownFieldAndHugeLists(t *testing.T) {
	r := validThresholdRule()
	r.Type = "single_event"
	r.Threshold = nil
	r.Conditions = []domain.RuleCondition{{Field: "bad field!", Operator: "eq", Values: []string{"x"}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "unsupported characters") {
		t.Fatalf("ValidateRule(bad field) = %v, want charset error", err)
	}
	vals := make([]string, 21)
	for i := range vals {
		vals[i] = "v"
	}
	r.Conditions = []domain.RuleCondition{{Field: "severity", Operator: "in", Values: vals}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "1-20 values") {
		t.Fatalf("ValidateRule(21 values) = %v, want list bound error", err)
	}
}

func TestValidateRuleTemporalNeedsTwoStages(t *testing.T) {
	r := validThresholdRule()
	r.Type = "temporal"
	r.Conditions = []domain.RuleCondition{{Field: "severity", Operator: "eq", Values: []string{"high"}}}
	if err := ValidateRule(r); err == nil || !strings.Contains(err.Error(), "two ordered conditions") {
		t.Fatalf("ValidateRule(temporal 1 stage) = %v, want stage error", err)
	}
}
