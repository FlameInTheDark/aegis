package endpoint

import (
	"testing"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

func mapOf(items ...*agentv1.IfaceMetrics) map[string]*agentv1.IfaceMetrics {
	m := make(map[string]*agentv1.IfaceMetrics, len(items))
	for _, it := range items {
		m[it.Name] = it
	}
	return m
}

func TestIfaceRatesComputesDeltasOverInterval(t *testing.T) {
	prev := mapOf(
		&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 1000, TxBytes: 500},
		&agentv1.IfaceMetrics{Name: "lo", RxBytes: 10, TxBytes: 10},
	)
	cur := mapOf(
		&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 3000, TxBytes: 1500},
		&agentv1.IfaceMetrics{Name: "lo", RxBytes: 20, TxBytes: 20},
	)
	out := ifaceRates(prev, cur, 10*time.Second)
	if len(out) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(out))
	}
	// Sorted by name: eth0 first.
	eth0 := out[0]
	if eth0.Name != "eth0" || eth0.RxBps != 200 || eth0.TxBps != 100 {
		t.Fatalf("eth0 rates wrong: %+v", eth0)
	}
	if out[1].Name != "lo" || out[1].RxBps != 1 {
		t.Fatalf("lo rates wrong: %+v", out[1])
	}
}

func TestIfaceRatesResetCountersYieldZero(t *testing.T) {
	prev := mapOf(&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 5000, TxBytes: 5000})
	// Counter went backwards (NIC reset): not comparable over the interval.
	cur := mapOf(&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 100, TxBytes: 50})
	out := ifaceRates(prev, cur, 5*time.Second)
	if out[0].RxBps != 0 || out[0].TxBps != 0 {
		t.Fatalf("reset counters must yield zero rates: %+v", out[0])
	}
}

func TestIfaceRatesNewNicYieldsZero(t *testing.T) {
	prev := mapOf(&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 100, TxBytes: 100})
	cur := mapOf(
		&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 200, TxBytes: 200},
		&agentv1.IfaceMetrics{Name: "wlan0", RxBytes: 999, TxBytes: 999},
	)
	out := ifaceRates(prev, cur, 1*time.Second)
	byName := map[string]*agentv1.IfaceMetrics{}
	for _, i := range out {
		byName[i.Name] = i
	}
	if byName["wlan0"].RxBps != 0 || byName["wlan0"].TxBps != 0 {
		t.Fatalf("new NIC has no previous snapshot — rates must be zero: %+v", byName["wlan0"])
	}
	if byName["eth0"].RxBps != 100 {
		t.Fatalf("existing NIC rate wrong: %+v", byName["eth0"])
	}
}

func TestIfaceRatesZeroIntervalYieldsZero(t *testing.T) {
	prev := mapOf(&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 100, TxBytes: 100})
	cur := mapOf(&agentv1.IfaceMetrics{Name: "eth0", RxBytes: 300, TxBytes: 300})
	out := ifaceRates(prev, cur, 0)
	if out[0].RxBps != 0 || out[0].TxBps != 0 {
		t.Fatalf("zero interval must not divide by zero: %+v", out[0])
	}
}
