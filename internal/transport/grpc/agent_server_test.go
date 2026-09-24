package grpcx

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"github.com/FlameInTheDark/aegis/internal/domain"
	chx "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// v1.24.0 regression guards for the endpoint data plane. The old plane had
// NO authentication at all: a client-asserted agent_id decided whose
// inventory was written. Since the connector consolidation every RPC
// authenticates with connector credentials and is resolved to the BOUND
// device — a spoofed id can no longer reach the persistence layer.

type fakeAuth struct {
	creds   map[string]string               // connectorID -> valid secret
	kinds   map[string]domain.ConnectorKind // connectorID -> kind
	configs map[string]json.RawMessage      // connectorID -> settings JSON
}

func (f *fakeAuth) Authenticate(_ context.Context, id, secret string) (*domain.Connector, error) {
	want, ok := f.creds[id]
	if !ok || want != secret {
		return nil, status.Error(codes.Unauthenticated, "invalid connector credentials")
	}
	return &domain.Connector{ID: id, Kind: f.kinds[id], Config: f.configs[id]}, nil
}

type fakeDevices struct{ byConn map[string]*domain.Agent }

func (f *fakeDevices) ByConnector(_ context.Context, connectorID string) (*domain.Agent, error) {
	if a, ok := f.byConn[connectorID]; ok {
		return a, nil
	}
	return nil, status.Error(codes.NotFound, "no device bound")
}

type fakePlane struct {
	inventories []string // agent IDs that received inventory
	touched     []string
}

func (f *fakePlane) LinkInventory(_ context.Context, agentID string, _ *domain.SystemInventory) error {
	f.inventories = append(f.inventories, agentID)
	return nil
}
func (f *fakePlane) TouchSeen(_ context.Context, id, _ string) error {
	f.touched = append(f.touched, id)
	return nil
}
func (f *fakePlane) InsertEvent(_ context.Context, _, _ string, _ map[string]any, _ time.Time) error {
	return nil
}
func (f *fakePlane) PendingTasks(_ context.Context, _ string) ([]domain.AgentTask, error) {
	return nil, nil
}
func (f *fakePlane) CompleteTask(_ context.Context, _ string, _ map[string]any, _ string) error {
	return nil
}

func newTestServer(auth *fakeAuth, dev *fakeDevices, plane *fakePlane) *AgentServer {
	return &AgentServer{Deps: Deps{Auth: auth, Devices: dev, Plane: plane}}
}

func mdCtx(connID, secret string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-aegis-connector-id", connID,
		"x-aegis-connector-secret", secret,
	))
}

func TestBoundDeviceRequiresMetadata(t *testing.T) {
	s := newTestServer(&fakeAuth{}, &fakeDevices{}, &fakePlane{})
	for _, ctx := range []context.Context{context.Background(), metadata.NewIncomingContext(context.Background(), metadata.Pairs("unrelated", "x"))} {
		_, err := s.boundDevice(ctx)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated call must be rejected, got %v", err)
		}
	}
}

func TestBoundDeviceRejectsBadCredentials(t *testing.T) {
	auth := &fakeAuth{creds: map[string]string{"c1": "s1"}, kinds: map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent}}
	s := newTestServer(auth, &fakeDevices{}, &fakePlane{})
	_, err := s.boundDevice(mdCtx("c1", "WRONG"))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad secret must be Unauthenticated, got %v", err)
	}
}

func TestBoundDeviceRejectsNonAgentKind(t *testing.T) {
	auth := &fakeAuth{
		creds: map[string]string{"scan1": "s2"},
		kinds: map[string]domain.ConnectorKind{"scan1": domain.ConnectorScanner},
	}
	s := newTestServer(auth, &fakeDevices{}, &fakePlane{})
	_, err := s.boundDevice(mdCtx("scan1", "s2"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("scanner-kind connector must be denied, got %v", err)
	}
	if !strings.Contains(err.Error(), "scanner") {
		t.Fatalf("error must name the offending kind, got: %v", err)
	}
}

// v1.25.0 hybrid: the data plane follows the agent FUNCTION, not the kind.
// A scanner-kind connection with `agent.enabled` participates like an agent.
func TestBoundDeviceAllowsAgentEnabledScannerKind(t *testing.T) {
	auth := &fakeAuth{
		creds:   map[string]string{"hyb1": "s3"},
		kinds:   map[string]domain.ConnectorKind{"hyb1": domain.ConnectorScanner},
		configs: map[string]json.RawMessage{"hyb1": json.RawMessage(`{"agent":{"enabled":true}}`)},
	}
	dev := &fakeDevices{byConn: map[string]*domain.Agent{"hyb1": {ID: "agt-hyb"}}}
	s := newTestServer(auth, dev, &fakePlane{})
	a, err := s.boundDevice(mdCtx("hyb1", "s3"))
	if err != nil || a.ID != "agt-hyb" {
		t.Fatalf("agent-enabled scanner-kind connection must reach its bound device, got %v %v", a, err)
	}
}

// The toggle cuts both ways: an agent-kind connection with the agent
// function explicitly disabled loses data-plane access too.
func TestBoundDeviceRejectsAgentDisabledAgentKind(t *testing.T) {
	auth := &fakeAuth{
		creds:   map[string]string{"c1": "s1"},
		kinds:   map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent},
		configs: map[string]json.RawMessage{"c1": json.RawMessage(`{"agent":{"enabled":false},"scanner":{"enabled":true}}`)},
	}
	s := newTestServer(auth, &fakeDevices{}, &fakePlane{})
	_, err := s.boundDevice(mdCtx("c1", "s1"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("agent-kind connection with the agent function disabled must be denied, got %v", err)
	}
}

func TestBoundDeviceRequiresBinding(t *testing.T) {
	auth := &fakeAuth{creds: map[string]string{"c1": "s1"}, kinds: map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent}}
	s := newTestServer(auth, &fakeDevices{}, &fakePlane{})
	_, err := s.boundDevice(mdCtx("c1", "s1"))
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unbound connector must be NotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "BindDevice") {
		t.Fatalf("error must point at BindDevice, got: %v", err)
	}
}

// The critical anti-spoofing guarantee: the persistence layer receives the
// BOUND device id; a client-asserted agent_id is ignored (the wire request
// below claims "spoofed-agent").
func TestSubmitInventoryUsesBoundDeviceID(t *testing.T) {
	auth := &fakeAuth{creds: map[string]string{"c1": "s1"}, kinds: map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent}}
	dev := &fakeDevices{byConn: map[string]*domain.Agent{"c1": {ID: "agt-real"}}}
	plane := &fakePlane{}
	s := newTestServer(auth, dev, plane)

	resp, err := s.SubmitInventory(mdCtx("c1", "s1"), &agentv1.InventoryReport{AgentId: "spoofed-agent", Hostname: "h"})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("submit failed: %v %v", err, resp)
	}
	if len(plane.inventories) != 1 || plane.inventories[0] != "agt-real" {
		t.Fatalf("inventory must be applied to the bound device, got %v", plane.inventories)
	}
}

// Regression (v1.26.4): a ClickHouse-less deployment assigned the typed nil
// (*ch.DB) straight into the Metrics interface — the interface itself
// became non-nil, the nil guard never fired and the first performance
// sample panicked the whole server on the nil driver connection. A
// typed-nil sink must behave exactly like a missing tier: acknowledged,
// dropped, other data-plane functions untouched.
func TestSubmitMetricsWithTypedNilSink(t *testing.T) {
	s := newTestServer(
		&fakeAuth{creds: map[string]string{"c1": "s1"}, kinds: map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent}},
		&fakeDevices{byConn: map[string]*domain.Agent{"c1": {ID: "agt-real"}}},
		&fakePlane{})
	var typedNil *chx.DB
	s.Deps.Metrics = typedNil

	resp, err := s.SubmitMetrics(mdCtx("c1", "s1"), &agentv1.MetricsReport{AgentId: "agt-real", CpuPercent: 12.5})
	if err != nil {
		t.Fatalf("typed-nil metrics sink must be handled like a missing tier, got %v", err)
	}
	if resp == nil || !resp.GetAccepted() || !strings.Contains(resp.GetError(), "not configured") {
		t.Fatalf("sample must be acknowledged and dropped, got %+v", resp)
	}
}

// recordingSink captures InsertDeviceMetrics calls; the fakeDevices agent
// carries tenancy fields so the batch stamping is verifiable.
type recordingSink struct{ inserts [][]chx.DeviceMetricSample }

func (f *recordingSink) InsertDeviceMetrics(_ context.Context, samples []chx.DeviceMetricSample) error {
	f.inserts = append(f.inserts, samples)
	return nil
}

func batchTestServer(sink *recordingSink) *AgentServer {
	auth := &fakeAuth{creds: map[string]string{"c1": "s1"}, kinds: map[string]domain.ConnectorKind{"c1": domain.ConnectorAgent}}
	dev := &fakeDevices{byConn: map[string]*domain.Agent{"c1": {
		ID: "agt-real", OrganizationID: "org-1", SiteID: "site-1",
	}}}
	s := newTestServer(auth, dev, &fakePlane{})
	s.Deps.Metrics = sink
	return s
}

// The whole point of the batch RPC: N buffered samples arrive in ONE call
// and are persisted in ONE insert, every row stamped with the BOUND
// device's identity (a spoofed per-sample agent_id is ignored).
func TestSubmitMetricsBatchInsertsAllSamples(t *testing.T) {
	sink := &recordingSink{}
	s := batchTestServer(sink)

	resp, err := s.SubmitMetricsBatch(mdCtx("c1", "s1"), &agentv1.MetricsBatchReport{
		AgentId: "spoofed-agent",
		Samples: []*agentv1.MetricsReport{
			{AgentId: "spoofed", CpuPercent: 11.5, CollectedAtUnix: 1700000100},
			{AgentId: "spoofed", CpuPercent: 12.5, CollectedAtUnix: 1700000200},
			{AgentId: "spoofed", CpuPercent: 13.5, CollectedAtUnix: 1700000300},
		},
	})
	if err != nil {
		t.Fatalf("batch submit failed: %v", err)
	}
	if !resp.GetAccepted() || resp.GetAcceptedCount() != 3 {
		t.Fatalf("batch must accept 3 samples, got %+v", resp)
	}
	if len(sink.inserts) != 1 || len(sink.inserts[0]) != 3 {
		t.Fatalf("expected ONE insert call with 3 samples, got %d calls", len(sink.inserts))
	}
	for i, sample := range sink.inserts[0] {
		if sample.AgentID != "agt-real" || sample.TenantID != "org-1" || sample.SiteID != "site-1" {
			t.Fatalf("sample %d not stamped with the bound device identity: %+v", i, sample)
		}
		if sample.CPUPercent != float64(11.5+float64(i)) {
			t.Fatalf("sample %d cpu mismatch: %v", i, sample.CPUPercent)
		}
	}
}

func TestSubmitMetricsBatchEmpty(t *testing.T) {
	sink := &recordingSink{}
	s := batchTestServer(sink)

	resp, err := s.SubmitMetricsBatch(mdCtx("c1", "s1"), &agentv1.MetricsBatchReport{AgentId: "agt-real"})
	if err != nil {
		t.Fatalf("empty batch failed: %v", err)
	}
	if !resp.GetAccepted() || resp.GetAcceptedCount() != 0 {
		t.Fatalf("empty batch must be accepted with count 0, got %+v", resp)
	}
	if len(sink.inserts) != 0 {
		t.Fatalf("empty batch must not reach the sink, got %d inserts", len(sink.inserts))
	}
}

func TestSubmitMetricsBatchStorageDisabled(t *testing.T) {
	s := batchTestServer(&recordingSink{})
	var typedNil *chx.DB
	s.Deps.Metrics = typedNil

	resp, err := s.SubmitMetricsBatch(mdCtx("c1", "s1"), &agentv1.MetricsBatchReport{
		Samples: []*agentv1.MetricsReport{{CpuPercent: 5}},
	})
	if err != nil {
		t.Fatalf("batch against a missing tier must not fail: %v", err)
	}
	if resp == nil || !resp.GetAccepted() || !strings.Contains(resp.GetError(), "not configured") {
		t.Fatalf("batch must be acknowledged and dropped, got %+v", resp)
	}
}

func TestSubmitMetricsBatchRequiresBoundDevice(t *testing.T) {
	s := batchTestServer(&recordingSink{})

	_, err := s.SubmitMetricsBatch(context.Background(), &agentv1.MetricsBatchReport{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("batch without credentials must be Unauthenticated, got %v", err)
	}
}
