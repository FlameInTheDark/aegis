// Endpoint data-plane transport (aegis.agent.v1.AgentService). Since
// v1.24.0 there is no enrollment here: identity is established through the
// unified ConnectorService (connect token -> secret -> BindDevice), and
// every RPC on this plane authenticates with the connector credentials and
// resolves the caller's BOUND DEVICE. A client-asserted agent_id is
// ignored — this plane cannot be used to impersonate another endpoint.
package grpcx

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"reflect"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/domain"
	chx "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// maxEventPayload bounds streamed agent events (oversized events).
const maxEventPayload = 256 << 10

// ConnectorAuth resolves connector per-call credentials. *connectors.Service
// satisfies it; the interface keeps the transport unit-testable.
type ConnectorAuth interface {
	Authenticate(ctx context.Context, connectorID, secret string) (*domain.Connector, error)
}

// DeviceResolver returns the device record bound to a connector.
// *pg.AgentRepo satisfies it.
type DeviceResolver interface {
	ByConnector(ctx context.Context, connectorID string) (*domain.Agent, error)
}

// DataPlane is the persistence surface the endpoint data plane needs.
// AgentsDataPlane adapts agents.Service to it; tests substitute fakes.
type DataPlane interface {
	LinkInventory(ctx context.Context, agentID string, inv *domain.SystemInventory) error
	TouchSeen(ctx context.Context, id, version string) error
	InsertEvent(ctx context.Context, agentID, typ string, payload map[string]any, occurred time.Time) error
	PendingTasks(ctx context.Context, agentID string) ([]domain.AgentTask, error)
	CompleteTask(ctx context.Context, id string, result map[string]any, errMsg string) error
}

// DeviceMetricsIngest persists device performance samples into the
// analytics tier. *ch.DB implements it; nil disables the metrics tier.
type DeviceMetricsIngest interface {
	InsertDeviceMetrics(ctx context.Context, samples []chx.DeviceMetricSample) error
}

// AgentsDataPlane adapts agents.Service to DataPlane.
type AgentsDataPlane struct{ S *agents.Service }

func (a AgentsDataPlane) LinkInventory(ctx context.Context, agentID string, inv *domain.SystemInventory) error {
	return a.S.LinkInventory(ctx, agentID, inv, nil, nil, nil)
}
func (a AgentsDataPlane) TouchSeen(ctx context.Context, id, version string) error {
	return a.S.Repo.TouchSeen(ctx, id, version)
}
func (a AgentsDataPlane) InsertEvent(ctx context.Context, agentID, typ string, payload map[string]any, occurred time.Time) error {
	return a.S.Events.Insert(ctx, agentID, typ, payload, occurred)
}
func (a AgentsDataPlane) PendingTasks(ctx context.Context, agentID string) ([]domain.AgentTask, error) {
	return a.S.Tasks.PendingForAgent(ctx, agentID)
}
func (a AgentsDataPlane) CompleteTask(ctx context.Context, id string, result map[string]any, errMsg string) error {
	return a.S.Tasks.Complete(ctx, id, result, errMsg)
}

// Deps bundles what the transport needs.
type Deps struct {
	Auth    ConnectorAuth       // connector credential check
	Devices DeviceResolver      // connector -> bound device
	Plane   DataPlane           // task/inventory persistence
	Metrics DeviceMetricsIngest // performance-sample store (nil = tier off)
	Log     *slog.Logger
}

// Compile-time interface check.
var _ agentv1.AgentServiceServer = (*AgentServer)(nil)

// AgentServer implements agentv1.AgentServiceServer.
type AgentServer struct {
	agentv1.UnimplementedAgentServiceServer
	Deps Deps
}

func ok(n int) *agentv1.SubmitResponse {
	return &agentv1.SubmitResponse{Accepted: true, AcceptedCount: int32(n)}
}

func fail(err error) (*agentv1.SubmitResponse, error) {
	return &agentv1.SubmitResponse{Accepted: false, Error: err.Error()}, nil
}

// boundDevice authenticates the connector credentials from per-call
// metadata and resolves the bound device record. Every data-plane RPC
// starts here: no metadata, no device — no service.
func (s *AgentServer) boundDevice(ctx context.Context) (*domain.Agent, error) {
	if s.Deps.Auth == nil || s.Deps.Devices == nil {
		return nil, status.Error(codes.FailedPrecondition, "authentication not configured")
	}
	md, okMD := metadata.FromIncomingContext(ctx)
	if !okMD {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	ids := md.Get("x-aegis-connector-id")
	secrets := md.Get("x-aegis-connector-secret")
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing connector credentials")
	}
	c, err := s.Deps.Auth.Authenticate(ctx, ids[0], secrets[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	// The endpoint data plane serves every connection performing the
	// agent function: agent-kind connections (the default) and any
	// other kind with `agent.enabled` toggled on in its settings
	// (hybrid operation). AgentEnabled encodes both the
	// kind default and the explicit toggle.
	if !connectors.AgentEnabled(c.Kind, c.Config) {
		return nil, status.Errorf(codes.PermissionDenied,
			"this RPC requires a connection with the agent function enabled (kind %q has it disabled)", string(c.Kind))
	}
	a, err := s.Deps.Devices.ByConnector(ctx, c.ID)
	if err != nil {
		return nil, status.Error(codes.NotFound,
			"no device bound to this connection; run BindDevice first")
	}
	return a, nil
}

// GetConfig returns collection configuration (privacy switches).
func (s *AgentServer) GetConfig(ctx context.Context, _ *agentv1.GetConfigRequest) (*agentv1.AgentConfig, error) {
	if _, err := s.boundDevice(ctx); err != nil {
		return nil, err
	}
	return &agentv1.AgentConfig{
		HeartbeatIntervalSecs: 30,
		Capabilities:          []string{"basic_inventory", "software_inventory", "network_inventory", "security_posture"},
		CollectionLevel:       "basic",
		LocalScanEnabled:      false,
		OfflineBufferMaxBytes: 16 << 20,
		ConfigVersion:         "1",
	}, nil
}

// Heartbeat records liveness.
func (s *AgentServer) Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	_ = s.Deps.Plane.TouchSeen(ctx, a.ID, req.GetAgentVersion())
	return &agentv1.HeartbeatResponse{ServerTime: time.Now().UTC().Format(time.RFC3339)}, nil
}

// SubmitInventory applies authoritative inventory to the linked asset.
func (s *AgentServer) SubmitInventory(ctx context.Context, req *agentv1.InventoryReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	inv := &domain.SystemInventory{
		Hostname: req.GetHostname(), FQDN: req.GetFqdn(),
		OSFamily: req.GetOsFamily(), OSName: req.GetOsName(), OSVersion: req.GetOsVersion(),
		Kernel: req.GetKernel(), Arch: req.GetArch(), UptimeSecs: req.GetUptimeSecs(),
		CPUModel: req.GetCpuModel(), CPUCores: int(req.GetCpuCores()), MemoryTotal: req.GetMemoryTotal(),
		SerialNumber: req.GetSerialNumber(), MachineID: req.GetMachineId(),
		PrimaryIP: req.GetPrimaryIp(),
	}
	for _, i := range req.GetInterfaces() {
		iface := domain.AgentIface{Name: i.GetName(), MAC: i.GetMac(), IPs: i.GetIps(), MTU: int(i.GetMtu()), Status: i.GetStatus()}
		inv.Interfaces = append(inv.Interfaces, iface)
	}
	for _, d := range req.GetDisks() {
		inv.Disks = append(inv.Disks, domain.AgentDisk{Device: d.GetDevice(), MountPoint: d.GetMountpoint(), FSType: d.GetFilesystem(), TotalBytes: d.GetTotalBytes(), FreeBytes: d.GetFreeBytes()})
	}
	if err := s.Deps.Plane.LinkInventory(ctx, a.ID, inv); err != nil {
		return fail(err)
	}
	return ok(1), nil
}

// SubmitSoftware stores package inventory.
func (s *AgentServer) SubmitSoftware(ctx context.Context, req *agentv1.SoftwareReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, p := range req.GetPackages() {
		if p.GetName() == "" {
			continue
		}
		// Package inventory is stored as an agent event and applied to the
		// linked asset by the worker correlation pass (keeps ingest cheap).
		_ = s.Deps.Plane.InsertEvent(ctx, a.ID, "software", map[string]any{
			"name": p.GetName(), "version": p.GetVersion(), "vendor": p.GetVendor(),
			"ecosystem": p.GetEcosystem(), "purl": domain.PURL(p.GetEcosystem(), p.GetName(), p.GetVersion()),
		}, time.Now().UTC())
		n++
	}
	_ = s.Deps.Plane.TouchSeen(ctx, a.ID, "")
	return ok(n), nil
}

// SubmitNetworkState records listening sockets.
func (s *AgentServer) SubmitNetworkState(ctx context.Context, req *agentv1.NetworkStateReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"listening": len(req.GetListeningSockets()), "firewall_enabled": req.GetFirewallEnabled()}
	_ = s.Deps.Plane.InsertEvent(ctx, a.ID, "network_state", payload, time.Now().UTC())
	_ = s.Deps.Plane.TouchSeen(ctx, a.ID, "")
	return ok(1), nil
}

// SubmitSecurityPosture records posture changes.
func (s *AgentServer) SubmitSecurityPosture(ctx context.Context, req *agentv1.SecurityPostureReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"firewall_enabled": req.GetFirewallEnabled(), "av_product": req.GetAvProduct(),
		"disk_encryption": req.GetDiskEncryption(), "auto_updates": req.GetAutoUpdates(),
		"secure_boot": req.GetSecureBoot(),
	}
	_ = s.Deps.Plane.InsertEvent(ctx, a.ID, "security_posture", payload, time.Now().UTC())
	_ = s.Deps.Plane.TouchSeen(ctx, a.ID, "")
	return ok(1), nil
}

// metricsSinkUsable reports whether the injected metrics sink can actually
// store samples. A nil interface means the tier is absent — but a non-nil
// interface holding a nil concrete value (the typed nil a wiring mistake
// produces) must count as absent too: the first sample would otherwise
// panic the server on the nil driver connection.
func metricsSinkUsable(m DeviceMetricsIngest) bool {
	if m == nil {
		return false
	}
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return !v.IsNil()
	default:
		return true
	}
}

// SubmitMetrics stores one performance sample (CPU, memory, network
// throughput) for the bound device. Metrics are advisory telemetry: when
// the analytics tier is not configured the sample is acknowledged and
// dropped, and every other data-plane function keeps working.
func (s *AgentServer) SubmitMetrics(ctx context.Context, req *agentv1.MetricsReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	if !metricsSinkUsable(s.Deps.Metrics) {
		return &agentv1.SubmitResponse{Accepted: true, Error: "metrics storage is not configured; sample dropped"}, nil
	}
	sample := buildMetricSample(a, req)
	if err := s.Deps.Metrics.InsertDeviceMetrics(ctx, []chx.DeviceMetricSample{sample}); err != nil {
		s.Deps.Log.Warn("device metrics insert failed", "agent", a.ID, "err", err)
		return fail(errors.New("metrics storage failed"))
	}
	return ok(1), nil
}

// SubmitMetricsBatch stores every sample the endpoint buffered since its
// last pull as ONE insert. Authentication and device resolution happen
// once per batch; each sample is stamped with the bound device's identity,
// so a client-asserted agent_id (or a forged per-sample one) is ignored
// exactly as in SubmitMetrics.
func (s *AgentServer) SubmitMetricsBatch(ctx context.Context, req *agentv1.MetricsBatchReport) (*agentv1.SubmitResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	samples := req.GetSamples()
	if len(samples) == 0 {
		return ok(0), nil
	}
	if !metricsSinkUsable(s.Deps.Metrics) {
		return &agentv1.SubmitResponse{
			Accepted:      true,
			AcceptedCount: int32(len(samples)),
			Error:         "metrics storage is not configured; samples dropped",
		}, nil
	}
	ins := make([]chx.DeviceMetricSample, 0, len(samples))
	for _, rep := range samples {
		ins = append(ins, buildMetricSample(a, rep))
	}
	if err := s.Deps.Metrics.InsertDeviceMetrics(ctx, ins); err != nil {
		s.Deps.Log.Warn("device metrics batch insert failed", "agent", a.ID, "samples", len(ins), "err", err)
		return fail(errors.New("metrics storage failed"))
	}
	return ok(len(ins)), nil
}

// buildMetricSample maps one wire report onto the analytics-tier sample,
// stamped with the bound device's tenancy (the wire values are ignored).
func buildMetricSample(a *domain.Agent, req *agentv1.MetricsReport) chx.DeviceMetricSample {
	ts := time.Now().UTC()
	if req.GetCollectedAtUnix() > 0 {
		ts = time.Unix(req.GetCollectedAtUnix(), 0).UTC()
	}
	sample := chx.DeviceMetricSample{
		TenantID:     a.OrganizationID,
		SiteID:       a.SiteID,
		AgentID:      a.ID,
		Timestamp:    ts,
		CPUPercent:   req.GetCpuPercent(),
		RxBPS:        0,
		TxBPS:        0,
		MemTotal:     req.GetMemoryTotal(),
		MemUsed:      req.GetMemoryUsed(),
		MemAvailable: req.GetMemoryAvailable(),
		Load1:        req.GetLoad1(),
		Load5:        req.GetLoad5(),
		Load15:       req.GetLoad15(),
		UptimeSecs:   req.GetUptimeSecs(),
	}
	if a.AssetID != nil {
		sample.AssetID = *a.AssetID
	}
	for _, i := range req.GetInterfaces() {
		sample.Interfaces = append(sample.Interfaces, chx.DeviceIfaceSample{
			Name: i.GetName(), MAC: i.GetMac(),
			RxBytes: i.GetRxBytes(), TxBytes: i.GetTxBytes(),
			RxPackets: i.GetRxPackets(), TxPackets: i.GetTxPackets(),
			RxBPS: i.GetRxBps(), TxBPS: i.GetTxBps(),
		})
		sample.RxBPS += i.GetRxBps()
		sample.TxBPS += i.GetTxBps()
	}
	return sample
}

// PollTasks returns pending typed tasks for the bound device.
func (s *AgentServer) PollTasks(ctx context.Context, _ *agentv1.PollTasksRequest) (*agentv1.PollTasksResponse, error) {
	a, err := s.boundDevice(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := s.Deps.Plane.PendingTasks(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	out := &agentv1.PollTasksResponse{}
	for _, t := range pending {
		argsJSON, _ := json.Marshal(t.Args)
		out.Tasks = append(out.Tasks, &agentv1.AgentTask{
			Id: t.ID, Type: string(t.Type), ArgsJson: string(argsJSON),
			IssuedAt: t.IssuedAt.Format(time.RFC3339), ExpiresAt: t.ExpiresAt.Format(time.RFC3339),
		})
	}
	_ = s.Deps.Plane.TouchSeen(ctx, a.ID, "")
	return out, nil
}

// CompleteTask records a task result (bound device only).
func (s *AgentServer) CompleteTask(ctx context.Context, req *agentv1.CompleteTaskRequest) (*agentv1.SubmitResponse, error) {
	if _, err := s.boundDevice(ctx); err != nil {
		return nil, err
	}
	var result map[string]any
	if len(req.GetResultJson()) > 0 && len(req.GetResultJson()) <= maxEventPayload {
		_ = json.Unmarshal([]byte(req.GetResultJson()), &result)
	}
	errMsg := ""
	if !req.GetSuccess() {
		errMsg = req.GetError()
	}
	if err := s.Deps.Plane.CompleteTask(ctx, req.GetTaskId(), result, errMsg); err != nil {
		return fail(err)
	}
	return ok(1), nil
}

// StreamEvents ingests a client-stream of telemetry events.
func (s *AgentServer) StreamEvents(stream agentv1.AgentService_StreamEventsServer) error {
	a, err := s.boundDevice(stream.Context())
	if err != nil {
		return err
	}
	n := 0
	for {
		ev, err := stream.Recv()
		if err != nil {
			break
		}
		if len(ev.GetPayloadJson()) > maxEventPayload {
			continue // drop oversized payloads
		}
		var payload map[string]any
		_ = json.Unmarshal([]byte(ev.GetPayloadJson()), &payload)
		occurred := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, ev.GetOccurredAt()); err == nil {
			occurred = t
		}
		if err := s.Deps.Plane.InsertEvent(stream.Context(), a.ID, ev.GetType(), payload, occurred); err == nil {
			n++
		}
	}
	return stream.SendAndClose(ok(n))
}

// ParseCSR is a small helper for the CA component.
func ParseCSR(pemBytes string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR PEM")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
