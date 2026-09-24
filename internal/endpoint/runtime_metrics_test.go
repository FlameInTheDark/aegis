package endpoint

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

func metricsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeMetricsClient records what the runtime sent; batchErr/singleErr let
// each test script the transport failure mode.
type fakeMetricsClient struct {
	batches []*agentv1.MetricsBatchReport
	singles []*agentv1.MetricsReport

	batchErr  error
	singleErr error
}

func (f *fakeMetricsClient) BindDevice(context.Context, *BindRequest) (*BindResult, error) {
	return &BindResult{AgentID: "agt-1"}, nil
}
func (f *fakeMetricsClient) GetConfig(context.Context, string) (*agentv1.AgentConfig, error) {
	return &agentv1.AgentConfig{}, nil
}
func (f *fakeMetricsClient) Heartbeat(context.Context, *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	return &agentv1.HeartbeatResponse{}, nil
}
func (f *fakeMetricsClient) SubmitInventory(context.Context, *agentv1.InventoryReport) error {
	return nil
}
func (f *fakeMetricsClient) SubmitSoftware(context.Context, *agentv1.SoftwareReport) error {
	return nil
}
func (f *fakeMetricsClient) SubmitNetworkState(context.Context, *agentv1.NetworkStateReport) error {
	return nil
}
func (f *fakeMetricsClient) SubmitSecurityPosture(context.Context, *agentv1.SecurityPostureReport) error {
	return nil
}
func (f *fakeMetricsClient) SubmitMetrics(_ context.Context, req *agentv1.MetricsReport) error {
	f.singles = append(f.singles, req)
	return f.singleErr
}
func (f *fakeMetricsClient) SubmitMetricsBatch(_ context.Context, req *agentv1.MetricsBatchReport) error {
	f.batches = append(f.batches, req)
	return f.batchErr
}
func (f *fakeMetricsClient) PollTasks(context.Context, string) ([]*agentv1.AgentTask, error) {
	return nil, nil
}
func (f *fakeMetricsClient) CompleteTask(context.Context, *agentv1.CompleteTaskRequest) error {
	return nil
}
func (f *fakeMetricsClient) Target() string { return "127.0.0.1:9090" }

func newMetricsTestRuntime(client *fakeMetricsClient) *Runtime {
	cfg := &Config{AgentID: "agt-1", HeartbeatSecs: 30}
	return &Runtime{
		Cfg:       cfg,
		Client:    client,
		Collector: &Collector{Cfg: cfg, Log: metricsTestLogger()},
		Log:       metricsTestLogger(),
	}
}

func TestNormalizeMetricsRates(t *testing.T) {
	cases := []struct {
		name              string
		probe, pull       int
		wantProbe, wantPP int
	}{
		{"zeros fall back to defaults", 0, 0, DefaultProbeRateMs, DefaultPullRateMs},
		{"negatives fall back to defaults", -5, -100, DefaultProbeRateMs, DefaultPullRateMs},
		{"below the floor clamps to 100ms", 50, 250, MinRateMs, 250},
		{"above the ceiling clamps to 1h", 7200000, 7200000, MaxRateMs, MaxRateMs},
		{"valid values pass through", 1000, 60000, 1000, 60000},
		{"pull faster than probe clamps up", 5000, 1000, 5000, 5000},
		{"pull zero falls back to its default", 1000, 0, 1000, DefaultPullRateMs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{ProbeRateMs: tc.probe, PullRateMs: tc.pull}
			cfg.normalizeMetricsRates()
			if cfg.ProbeRateMs != tc.wantProbe {
				t.Fatalf("probe = %d, want %d", cfg.ProbeRateMs, tc.wantProbe)
			}
			if cfg.PullRateMs != tc.wantPP {
				t.Fatalf("pull = %d, want %d", cfg.PullRateMs, tc.wantPP)
			}
		})
	}
}

func TestLoadAppliesRateDefaultsAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProbeRateMs != DefaultProbeRateMs || cfg.PullRateMs != DefaultPullRateMs {
		t.Fatalf("defaults not applied: probe=%d pull=%d", cfg.ProbeRateMs, cfg.PullRateMs)
	}

	t.Setenv("AEGIS_PROBE_RATE_MS", "250")
	t.Setenv("AEGIS_PULL_RATE_MS", "15000")
	cfg, err = Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProbeRateMs != 250 || cfg.PullRateMs != 15000 {
		t.Fatalf("env overrides ignored: probe=%d pull=%d", cfg.ProbeRateMs, cfg.PullRateMs)
	}
}

func TestSetMetricsRatesNormalizesAndSignals(t *testing.T) {
	rt := newMetricsTestRuntime(&fakeMetricsClient{})
	rt.SetMetricsRates(50, 99999999) // both out of bounds
	if got := rt.probeDur(); got != 100*time.Millisecond {
		t.Fatalf("probe duration = %v, want 100ms", got)
	}
	if got := rt.pullDur(); got != time.Hour {
		t.Fatalf("pull duration = %v, want 1h", got)
	}
	select {
	case <-rt.rateSignal():
	default:
		t.Fatal("rate change must signal the loop")
	}

	// The same rates again: no signal (the first one was consumed above).
	rt.SetMetricsRates(50, 99999999)
	select {
	case <-rt.rateSignal():
		t.Fatal("unchanged rates must not signal")
	default:
	}
}

func TestCollectMetricsSampleBuffersOneReport(t *testing.T) {
	rt := newMetricsTestRuntime(&fakeMetricsClient{})
	rt.Collector.PrimeCPUSampling()
	rt.collectMetricsSample()
	if len(rt.metricsBuf) != 1 {
		t.Fatalf("expected 1 buffered sample, got %d", len(rt.metricsBuf))
	}
	if rt.metricsBuf[0].AgentId != "agt-1" {
		t.Fatalf("sample not stamped with the device id: %+v", rt.metricsBuf[0])
	}
	// A second sample must produce interface rates against the first one.
	rt.collectMetricsSample()
	if len(rt.metricsBuf) != 2 {
		t.Fatalf("expected 2 buffered samples, got %d", len(rt.metricsBuf))
	}
}

func TestFlushMetricsSendsOneBatchAndClears(t *testing.T) {
	client := &fakeMetricsClient{}
	rt := newMetricsTestRuntime(client)
	rt.collectMetricsSample()
	rt.collectMetricsSample()
	rt.collectMetricsSample()

	rt.flushMetrics(context.Background())
	if len(client.batches) != 1 || len(client.batches[0].GetSamples()) != 3 {
		t.Fatalf("expected ONE batch RPC with 3 samples, got %d batches", len(client.batches))
	}
	if len(client.singles) != 0 {
		t.Fatalf("batch path must not degrade to singles: %d sent", len(client.singles))
	}
	if len(rt.metricsBuf) != 0 {
		t.Fatalf("buffer must be empty after a successful flush, got %d", len(rt.metricsBuf))
	}
	// An empty buffer flushes nothing.
	rt.flushMetrics(context.Background())
	if len(client.batches) != 1 {
		t.Fatalf("empty flush must be a no-op, got %d batches", len(client.batches))
	}
}

func TestFlushMetricsFallsBackToSinglesOnUnimplemented(t *testing.T) {
	client := &fakeMetricsClient{batchErr: ErrMetricsBatchUnsupported}
	rt := newMetricsTestRuntime(client)
	rt.collectMetricsSample()
	rt.collectMetricsSample()

	rt.flushMetrics(context.Background())
	if len(client.singles) != 2 {
		t.Fatalf("fallback must submit each sample, got %d singles", len(client.singles))
	}
	if len(client.batches) != 1 {
		t.Fatalf("fallback must be triggered by the batch attempt, got %d batches", len(client.batches))
	}
	if len(rt.metricsBuf) != 0 {
		t.Fatalf("fallback must drain the buffer, got %d left", len(rt.metricsBuf))
	}
}

func TestFlushMetricsStorageDisabledDrops(t *testing.T) {
	client := &fakeMetricsClient{batchErr: ErrMetricsStorageDisabled}
	rt := newMetricsTestRuntime(client)
	rt.collectMetricsSample()

	rt.flushMetrics(context.Background())
	if len(rt.metricsBuf) != 0 {
		t.Fatalf("storage-disabled drop must clear the buffer, got %d left", len(rt.metricsBuf))
	}
	if len(client.singles) != 0 {
		t.Fatal("storage-disabled must not fall back to singles")
	}
}

func TestFlushMetricsFailureKeepsSamplesBounded(t *testing.T) {
	client := &fakeMetricsClient{batchErr: errors.New("connection refused")}
	rt := newMetricsTestRuntime(client)
	for i := 0; i < 3; i++ {
		rt.collectMetricsSample()
	}

	rt.flushMetrics(context.Background())
	if len(rt.metricsBuf) != 3 {
		t.Fatalf("failed flush must keep the samples, got %d", len(rt.metricsBuf))
	}
	if len(client.batches) != 1 {
		t.Fatalf("expected exactly one batch attempt, got %d", len(client.batches))
	}

	// A pathological accumulation is cut off at maxMetricsBatch, dropping
	// the OLDEST samples so the buffer cannot grow without limit.
	for i := 0; i < maxMetricsBatch+5; i++ {
		rt.metricsBuf = append(rt.metricsBuf, &agentv1.MetricsReport{})
	}
	rt.flushMetrics(context.Background())
	if len(rt.metricsBuf) != maxMetricsBatch {
		t.Fatalf("buffer must be bounded at %d, got %d", maxMetricsBatch, len(rt.metricsBuf))
	}
}
