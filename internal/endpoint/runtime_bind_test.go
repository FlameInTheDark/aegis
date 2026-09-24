// Package endpoint_test exercises the device binding + data plane through
// the REAL client transport (agentclient over gRPC). It lives in the
// external test package because agentclient imports endpoint — an
// in-package test would create an import cycle.
package endpoint_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
	"github.com/FlameInTheDark/aegis/internal/endpoint"
	"github.com/FlameInTheDark/aegis/internal/transport/agentclient"
)

// v1.24.0 regression guards: endpoints are agent-kind connectors. The stub
// hub REQUIRES the connector credential metadata on BindDevice — so if the
// client ever stops attaching it (the v1.23.x client attached nothing at
// all), these tests fail loudly instead of silently regressing to an
// unauthenticated data plane.

type bindHub struct {
	connectorv1.UnimplementedConnectorServiceServer
	t         *testing.T
	sawSecret bool
	sawID     string
	got       *connectorv1.BindDeviceRequest
	resp      *connectorv1.BindDeviceResponse
}

func (h *bindHub) BindDevice(ctx context.Context, req *connectorv1.BindDeviceRequest) (*connectorv1.BindDeviceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	ids := md.Get("x-aegis-connector-id")
	secrets := md.Get("x-aegis-connector-secret")
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, status.Error(codes.Unauthenticated, "stub requires connector credentials")
	}
	h.sawID, h.sawSecret = ids[0], secrets[0] != ""
	h.got = req
	if h.resp == nil {
		return nil, status.Error(codes.Internal, "no canned response")
	}
	return h.resp, nil
}

// startHub serves the stub on a real loopback listener; the returned addr
// feeds cfg.ServerURL exactly the way the connector's endpoint role maps it.
func startHub(t *testing.T, impl *bindHub) (hub *bindHub, addr string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorServiceServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return impl, lis.Addr().String()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEnsureBoundHappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := &endpoint.Config{
		StateDir:        dir,
		CertPath:        filepath.Join(dir, "agent.crt"),
		KeyPath:         filepath.Join(dir, "agent.key"),
		ConnectorID:     "conn-1",
		ConnectorSecret: "aegis_conn_s_test",
	}
	hub, addr := startHub(t, &bindHub{
		t: t,
		resp: &connectorv1.BindDeviceResponse{
			AgentId: "agt-777", CertificatePem: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
			SiteId: "site-1", HeartbeatIntervalSecs: 77,
		},
	})
	cfg.ServerURL = "http://" + addr // same mapping the endpoint role performs

	client, err := agentclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := &endpoint.Runtime{Cfg: cfg, Client: client, Collector: &endpoint.Collector{Cfg: cfg, Log: testLogger()}, Log: testLogger()}
	if err := rt.EnsureBound(context.Background()); err != nil {
		t.Fatalf("EnsureBound: %v", err)
	}

	if hub.sawID != "conn-1" || !hub.sawSecret {
		t.Fatalf("connector credentials not attached to the call: id=%q secret=%v", hub.sawID, hub.sawSecret)
	}
	if hub.got == nil {
		t.Fatal("hub never received the BindDevice RPC")
	}
	if !strings.Contains(hub.got.GetCsrPem(), "CERTIFICATE REQUEST") {
		t.Fatalf("CSR missing/invalid on the wire: %q", hub.got.GetCsrPem())
	}
	if hub.got.GetMachineId() == "" {
		t.Fatal("machine_id was empty")
	}
	if cfg.AgentID != "agt-777" {
		t.Fatalf("agent id not applied: %q", cfg.AgentID)
	}
	if cfg.HeartbeatSecs != 77 {
		t.Fatalf("heartbeat hint from response ignored: %d", cfg.HeartbeatSecs)
	}
	// Device state must be persisted WITHOUT the connector secret (the
	// secret lives only in the connector's own 0600 config file).
	b, err := os.ReadFile(filepath.Join(dir, endpoint.StateFileName))
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	if st["agent_id"] != "agt-777" {
		t.Fatalf("state agent_id = %v", st["agent_id"])
	}
	if sec, ok := st["connector_secret"]; ok && sec != "" {
		t.Fatalf("connector secret leaked into device state: %v", sec)
	}
	if _, err := os.Stat(cfg.KeyPath); err != nil {
		t.Fatalf("private key not persisted: %v", err)
	}
}

func TestEnsureBoundWithoutCredentialsFailsWithGuidance(t *testing.T) {
	dir := t.TempDir()
	cfg := &endpoint.Config{ServerURL: "http://127.0.0.1:1", StateDir: dir}
	rt := &endpoint.Runtime{Cfg: cfg, Collector: &endpoint.Collector{Cfg: cfg}, Log: testLogger()}
	err := rt.EnsureBound(context.Background())
	if err == nil {
		t.Fatal("expected failure without connector credentials")
	}
	if !strings.Contains(err.Error(), "aegis-connector --connect") {
		t.Fatalf("error must name the connect command, got: %v", err)
	}
}

func TestEnsureBoundAlreadyBoundSkipsRPC(t *testing.T) {
	dir := t.TempDir()
	cfg := &endpoint.Config{ServerURL: "http://127.0.0.1:1", StateDir: dir, AgentID: "agt-1", ConnectorID: "c", ConnectorSecret: "s"}
	client, err := agentclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := &endpoint.Runtime{Cfg: cfg, Client: client, Collector: &endpoint.Collector{Cfg: cfg}, Log: testLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rt.EnsureBound(ctx); err != nil {
		t.Fatalf("already-bound must be a no-op success, got %v", err)
	}
}

func TestEnsureBoundRejectionSurfaces(t *testing.T) {
	dir := t.TempDir()
	cfg := &endpoint.Config{
		ServerURL: "http://127.0.0.1:1", StateDir: dir,
		CertPath: filepath.Join(dir, "agent.crt"), KeyPath: filepath.Join(dir, "agent.key"),
		ConnectorID: "c", ConnectorSecret: "s",
	}
	_, _ = startHub(t, &bindHub{t: t, resp: nil}) // BindDevice returns Internal
	client, err := agentclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := &endpoint.Runtime{Cfg: cfg, Client: client, Collector: &endpoint.Collector{Cfg: cfg}, Log: testLogger()}
	err = rt.EnsureBound(context.Background())
	if err == nil || !strings.Contains(err.Error(), "device bind rejected") {
		t.Fatalf("server error must surface as bind rejected, got %v", err)
	}
	if cfg.AgentID != "" {
		t.Fatal("agent id must not be set on rejection")
	}
}
