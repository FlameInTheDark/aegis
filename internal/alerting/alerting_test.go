package alerting

import (
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestConditionValidate(t *testing.T) {
	ok := Condition{Field: "cve_id", Op: OpEq, Value: "CVE-2024-1234"}
	if err := ok.Validate(0); err != nil {
		t.Fatalf("valid condition rejected: %v", err)
	}
	c1 := Condition{Field: "cve_id", Op: "drop table", Value: 1}
	if err := c1.Validate(0); err == nil {
		t.Fatal("unknown operator accepted")
	}
	c2 := Condition{Field: "", Op: OpEq, Value: 1}
	if err := c2.Validate(0); err == nil {
		t.Fatal("empty field accepted")
	}
	c3 := Condition{Field: "kev", Op: OpIn, Value: "x"}
	if err := c3.Validate(0); err == nil {
		t.Fatal("in with scalar value accepted")
	}
	c4 := Condition{Field: "x", Op: OpRegex, Value: "("}
	if err := c4.Validate(0); err == nil {
		t.Fatal("invalid regex accepted")
	}
	deep := Condition{}
	cur := &deep
	for i := 0; i < 6; i++ {
		cur.All = []Condition{{}}
		cur = &cur.All[0]
	}
	if err := deep.Validate(0); err == nil {
		t.Fatal("excessive nesting accepted")
	}
	big := Condition{Any: make([]Condition, 25)}
	if err := big.Validate(0); err == nil {
		t.Fatal("oversized group accepted")
	}
}

func TestConditionEvaluate(t *testing.T) {
	data := map[string]any{
		"state": "failed", "findings_created": float64(3), "kev": true,
		"nested": map[string]any{"product": "OpenSSH"},
	}
	tests := []struct {
		cond Condition
		want bool
	}{
		{Condition{Field: "state", Op: OpEq, Value: "failed"}, true},
		{Condition{Field: "state", Op: OpEq, Value: "completed"}, false},
		{Condition{Field: "state", Op: OpNeq, Value: "completed"}, true},
		{Condition{Field: "findings_created", Op: OpGte, Value: 2.0}, true},
		{Condition{Field: "findings_created", Op: OpLt, Value: 2.0}, false},
		{Condition{Field: "kev", Op: OpEq, Value: true}, true},
		{Condition{Field: "missing", Op: OpExists}, false},
		{Condition{Field: "state", Op: OpExists}, true},
		{Condition{Field: "nested.product", Op: OpContains, Value: "SSH"}, true},
		{Condition{Field: "state", Op: OpIn, Value: []any{"failed", "completed"}}, true},
		{Condition{Field: "state", Op: OpNotIn, Value: []any{"failed", "completed"}}, false},
		{Condition{All: []Condition{
			{Field: "state", Op: OpEq, Value: "failed"},
			{Field: "kev", Op: OpEq, Value: true},
		}}, true},
		{Condition{All: []Condition{
			{Field: "state", Op: OpEq, Value: "failed"},
			{Field: "kev", Op: OpEq, Value: false},
		}}, false},
		{Condition{Any: []Condition{
			{Field: "state", Op: OpEq, Value: "completed"},
			{Field: "kev", Op: OpEq, Value: true},
		}}, true},
		{Condition{Not: &Condition{Field: "kev", Op: OpEq, Value: true}}, false},
	}
	for i, tt := range tests {
		if got := tt.cond.Evaluate(data); got != tt.want {
			t.Errorf("case %d: got %v want %v", i, got, tt.want)
		}
	}
}

func metricTrigger() *domain.Trigger {
	thr := 90.0
	rec := 80.0
	return &domain.Trigger{
		ID: "t1", OrgID: "o1", Name: "CPU", Kind: domain.TriggerKindMetric,
		MetricField: "cpu_percent", Aggregation: "avg", Operator: "gt",
		Threshold: thr, WindowSecs: 300, ActivationSecs: 120, RecoverySecs: 300,
		RecoveryThreshold: &rec, MissingDataPolicy: domain.MissingDataIgnore,
	}
}

func TestMetricDecision(t *testing.T) {
	now := time.Now().UTC()
	t.Run("activation gating", func(t *testing.T) {
		// Fresh breach arms, does not fire.
		if got := metricDecision(nil, metricTrigger(), pv(95), 10, now); got.kind != actionArm {
			t.Fatalf("fresh breach: want arm got %s", got.kind)
		}
		// Pending, not yet activated: none.
		st := &ruleState{state: domain.RuleStatePending, pendingSince: pvTime(now)}
		if got := metricDecision(st, metricTrigger(), pv(95), 10, now.Add(60*time.Second)); got.kind != actionNone {
			t.Fatalf("pending 60s: want none got %s", got.kind)
		}
		// Pending past activation: fire.
		if got := metricDecision(st, metricTrigger(), pv(95), 10, now.Add(121*time.Second)); got.kind != actionFire {
			t.Fatalf("pending 121s: want fire got %s", got.kind)
		}
	})
	t.Run("hysteresis recovery", func(t *testing.T) {
		// Firing, value drops below alert threshold but above recovery bound:
		// stays firing (no recovery arming).
		st := &ruleState{state: domain.RuleStateFiring, lastTransition: pvTime(now)}
		if got := metricDecision(st, metricTrigger(), pv(85), 10, now); got.kind != actionNone {
			t.Fatalf("between bounds: want none got %s", got.kind)
		}
		// Below recovery bound arms recovery.
		if got := metricDecision(st, metricTrigger(), pv(70), 10, now); got.kind != actionRecoverArm {
			t.Fatalf("below hysteresis: want recover_arm got %s", got.kind)
		}
		// Recovery sustained: recover.
		st.pendingSince = pvTime(now)
		if got := metricDecision(st, metricTrigger(), pv(70), 10, now.Add(301*time.Second)); got.kind != actionRecover {
			t.Fatalf("recovery sustained: want recover got %s", got.kind)
		}
		// Breach again during recovery arming: back to breach branch.
		st.pendingSince = pvTime(now)
		if got := metricDecision(st, metricTrigger(), pv(95), 10, now.Add(60*time.Second)); got.kind != actionArm {
			t.Fatalf("re-breach: want arm got %s", got.kind)
		}
	})
	t.Run("missing data never reads healthy", func(t *testing.T) {
		// Firing + no data + ignore: state preserved (none).
		st := &ruleState{state: domain.RuleStateFiring}
		if got := metricDecision(st, metricTrigger(), nil, 0, now); got.kind != actionNone {
			t.Fatalf("ignore policy: want none got %s", got.kind)
		}
		// Firing + no data + resolve: recovers.
		trig := metricTrigger()
		trig.MissingDataPolicy = domain.MissingDataResolve
		if got := metricDecision(st, trig, nil, 0, now); got.kind != actionRecover {
			t.Fatalf("resolve policy: want recover got %s", got.kind)
		}
	})
	t.Run("repeat", func(t *testing.T) {
		trig := metricTrigger()
		trig.RepeatSecs = 600
		st := &ruleState{state: domain.RuleStateFiring, lastTransition: pvTime(now.Add(-700 * time.Second))}
		if got := metricDecision(st, trig, pv(95), 10, now); got.kind != actionRepeat {
			t.Fatalf("repeat overdue: want repeat got %s", got.kind)
		}
		st.lastTransition = pvTime(now.Add(-100 * time.Second))
		if got := metricDecision(st, trig, pv(95), 10, now); got.kind != actionNone {
			t.Fatalf("repeat too soon: want none got %s", got.kind)
		}
	})
	t.Run("boundaries", func(t *testing.T) {
		if !compareThreshold(90.0, "gte", 90.0) {
			t.Fatal("gte boundary failed")
		}
		if compareThreshold(90.0, "gt", 90.0) {
			t.Fatal("gt boundary failed")
		}
		if !recoveredEnough(80.0, metricTrigger()) {
			t.Fatal("recovery at bound failed")
		}
		if recoveredEnough(80.1, metricTrigger()) {
			t.Fatal("recovery above bound must fail")
		}
	})
}

func pv(v float64) *float64         { return &v }
func pvTime(t time.Time) *time.Time { return &t }

func TestFingerprintStability(t *testing.T) {
	trig := &domain.Trigger{ID: "trig"}
	ev := &domain.TriggerEvent{DedupKey: "asset:a1", EntityType: "asset", EntityID: "a1"}
	if fingerprintFor(trig, ev) != "trig|asset:a1" {
		t.Fatalf("dedup key must win: %s", fingerprintFor(trig, ev))
	}
	ev2 := &domain.TriggerEvent{EntityType: "asset", EntityID: "a1"}
	if fingerprintFor(trig, ev2) != "trig|asset:a1" {
		t.Fatalf("fallback to entity id: %s", fingerprintFor(trig, ev2))
	}
}

func TestDestinationSubscribes(t *testing.T) {
	d := &domain.Destination{Enabled: true, MinSeverity: "medium"}
	if !destinationSubscribes(d, "critical", "fired") {
		t.Fatal("critical must pass medium floor")
	}
	if destinationSubscribes(d, "low", "fired") {
		t.Fatal("low must not pass medium floor")
	}
	d.Events = []string{"recovered"}
	if destinationSubscribes(d, "critical", "fired") {
		t.Fatal("fired must be filtered by subscription")
	}
	if !destinationSubscribes(d, "critical", "recovered") {
		t.Fatal("recovered must pass subscription")
	}
	d.Enabled = false
	if destinationSubscribes(d, "critical", "recovered") {
		t.Fatal("disabled destination must never subscribe")
	}
}
