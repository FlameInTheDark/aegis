// Package grpcx implements the agent control-plane gRPC transport (spec §136).
// Agents present device certificates (mTLS); the server maps certificate
// identity to agent records and applies tenant isolation.
package grpcx

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// maxEventPayload bounds streamed agent events (§104 oversized events).
const maxEventPayload = 256 << 10

// Deps bundles what the transport needs.
type Deps struct {
	Agents *agents.Service
	Log    *slog.Logger
	// IssueCert signs a CSR with the platform agent CA.
	IssueCert func(csrPEM, agentID string) (certPEM string, err error)
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

// Enroll handles first-contact enrollment.
func (s *AgentServer) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	if req.GetToken() == "" || req.GetCsrPem() == "" {
		return nil, errors.New("token and csr_pem are required")
	}
	resp, err := s.Deps.Agents.Enroll(ctx, agents.EnrollRequest{
		Token:    req.GetToken(),
		Hostname: req.GetHostname(),
		Platform: req.GetPlatform(),
		Version:  req.GetAgentVersion(),
	}, func(csrPEM, agentID string) (string, error) {
		if s.Deps.IssueCert == nil {
			return "", errors.New("agent CA not configured")
		}
		cert, err := s.Deps.IssueCert(csrPEM, agentID)
		if err != nil {
			return "", err
		}
		return cert, nil
	})
	if err != nil {
		s.Deps.Log.Warn("enrollment rejected", "err", err)
		return nil, err
	}
	return &agentv1.EnrollResponse{
		AgentId:               resp.AgentID,
		CertificatePem:        resp.CertificatePEM,
		OrgId:                 resp.OrgID,
		SiteId:                resp.SiteID,
		HeartbeatIntervalSecs: 30,
	}, nil
}

// GetConfig returns collection configuration (privacy switches, §125).
func (s *AgentServer) GetConfig(ctx context.Context, req *agentv1.GetConfigRequest) (*agentv1.AgentConfig, error) {
	agentID := req.GetAgentId()
	if _, err := s.Deps.Agents.Repo.ByID(ctx, "", agentID); err != nil {
		return nil, errors.New("unknown agent")
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
	_ = s.Deps.Agents.Repo.TouchSeen(ctx, req.GetAgentId(), req.GetAgentVersion())
	return &agentv1.HeartbeatResponse{ServerTime: time.Now().UTC().Format(time.RFC3339)}, nil
}

// SubmitInventory applies authoritative inventory to the linked asset.
func (s *AgentServer) SubmitInventory(ctx context.Context, req *agentv1.InventoryReport) (*agentv1.SubmitResponse, error) {
	inv := &domain.SystemInventory{
		Hostname: req.GetHostname(), FQDN: req.GetFqdn(),
		OSFamily: req.GetOsFamily(), OSName: req.GetOsName(), OSVersion: req.GetOsVersion(),
		Kernel: req.GetKernel(), Arch: req.GetArch(), UptimeSecs: req.GetUptimeSecs(),
		CPUModel: req.GetCpuModel(), CPUCores: int(req.GetCpuCores()), MemoryTotal: req.GetMemoryTotal(),
		SerialNumber: req.GetSerialNumber(), MachineID: req.GetMachineId(),
	}
	for _, i := range req.GetInterfaces() {
		iface := domain.AgentIface{Name: i.GetName(), MAC: i.GetMac(), IPs: i.GetIps(), MTU: int(i.GetMtu()), Status: i.GetStatus()}
		inv.Interfaces = append(inv.Interfaces, iface)
	}
	for _, d := range req.GetDisks() {
		inv.Disks = append(inv.Disks, domain.AgentDisk{Device: d.GetDevice(), MountPoint: d.GetMountpoint(), FSType: d.GetFilesystem(), TotalBytes: d.GetTotalBytes(), FreeBytes: d.GetFreeBytes()})
	}
	if err := s.Deps.Agents.LinkInventory(ctx, req.GetAgentId(), inv, nil, nil, nil); err != nil {
		return fail(err)
	}
	return ok(1), nil
}

// SubmitSoftware stores package inventory.
func (s *AgentServer) SubmitSoftware(ctx context.Context, req *agentv1.SoftwareReport) (*agentv1.SubmitResponse, error) {
	n := 0
	for _, p := range req.GetPackages() {
		if p.GetName() == "" {
			continue
		}
		// Package inventory is stored as an agent event and applied to the
		// linked asset by the worker correlation pass (keeps ingest cheap).
		_ = s.Deps.Agents.Events.Insert(ctx, req.GetAgentId(), "software", map[string]any{
			"name": p.GetName(), "version": p.GetVersion(), "vendor": p.GetVendor(),
			"ecosystem": p.GetEcosystem(), "purl": domain.PURL(p.GetEcosystem(), p.GetName(), p.GetVersion()),
		}, time.Now().UTC())
		n++
	}
	_ = s.Deps.Agents.Repo.TouchSeen(ctx, req.GetAgentId(), "")
	return ok(n), nil
}

// SubmitNetworkState records listening sockets.
func (s *AgentServer) SubmitNetworkState(ctx context.Context, req *agentv1.NetworkStateReport) (*agentv1.SubmitResponse, error) {
	payload := map[string]any{"listening": len(req.GetListeningSockets()), "firewall_enabled": req.GetFirewallEnabled()}
	_ = s.Deps.Agents.Events.Insert(ctx, req.GetAgentId(), "network_state", payload, time.Now().UTC())
	_ = s.Deps.Agents.Repo.TouchSeen(ctx, req.GetAgentId(), "")
	return ok(1), nil
}

// SubmitSecurityPosture records posture changes.
func (s *AgentServer) SubmitSecurityPosture(ctx context.Context, req *agentv1.SecurityPostureReport) (*agentv1.SubmitResponse, error) {
	payload := map[string]any{
		"firewall_enabled": req.GetFirewallEnabled(), "av_product": req.GetAvProduct(),
		"disk_encryption": req.GetDiskEncryption(), "auto_updates": req.GetAutoUpdates(),
		"secure_boot": req.GetSecureBoot(),
	}
	_ = s.Deps.Agents.Events.Insert(ctx, req.GetAgentId(), "security_posture", payload, time.Now().UTC())
	_ = s.Deps.Agents.Repo.TouchSeen(ctx, req.GetAgentId(), "")
	return ok(1), nil
}

// PollTasks returns pending typed tasks for the agent.
func (s *AgentServer) PollTasks(ctx context.Context, req *agentv1.PollTasksRequest) (*agentv1.PollTasksResponse, error) {
	pending, err := s.Deps.Agents.Tasks.PendingForAgent(ctx, req.GetAgentId())
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
	_ = s.Deps.Agents.Repo.TouchSeen(ctx, req.GetAgentId(), "")
	return out, nil
}

// CompleteTask records a task result.
func (s *AgentServer) CompleteTask(ctx context.Context, req *agentv1.CompleteTaskRequest) (*agentv1.SubmitResponse, error) {
	var result map[string]any
	if len(req.GetResultJson()) > 0 && len(req.GetResultJson()) <= maxEventPayload {
		_ = json.Unmarshal([]byte(req.GetResultJson()), &result)
	}
	errMsg := ""
	if !req.GetSuccess() {
		errMsg = req.GetError()
	}
	if err := s.Deps.Agents.Tasks.Complete(ctx, req.GetTaskId(), result, errMsg); err != nil {
		return fail(err)
	}
	return ok(1), nil
}

// StreamEvents ingests a client-stream of telemetry events.
func (s *AgentServer) StreamEvents(stream agentv1.AgentService_StreamEventsServer) error {
	n := 0
	for {
		ev, err := stream.Recv()
		if err != nil {
			break
		}
		if len(ev.GetPayloadJson()) > maxEventPayload {
			continue // drop oversized payloads (§104)
		}
		var payload map[string]any
		_ = json.Unmarshal([]byte(ev.GetPayloadJson()), &payload)
		occurred := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, ev.GetOccurredAt()); err == nil {
			occurred = t
		}
		if err := s.Deps.Agents.Events.Insert(stream.Context(), ev.GetAgentId(), ev.GetType(), payload, occurred); err == nil {
			n++
		}
	}
	_ = ids.New() // keep ids import when counting only
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

// CertAgentID extracts the agent id from a device certificate CN (format
// "aegis-agent-<id>") — used by the gRPC auth interceptor.
func CertAgentID(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	cn := certs[0].Subject.CommonName
	return strings.TrimPrefix(cn, "aegis-agent-")
}
