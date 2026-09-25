// ConnectorServer implements the aegis.connector.v1 gRPC service: the
// unified enrollment + control protocol for externally connected
// components. Enrollment authenticates with a one-time token; every other
// RPC authenticates with the per-call metadata credentials issued at
// enrollment (x-aegis-connector-id / x-aegis-connector-secret).
package grpcx

import (
	"context"
	"errors"
	"log/slog"
	"time"

	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ConnectorDeps bundles what the connector transport needs. Agents plus
// IssueCert power the device binding of connections performing the agent
// function; when no CA is configured, IssueCert is nil and BindDevice
// reports it clearly.
type ConnectorDeps struct {
	Connectors *connectors.Service
	Agents     *agents.Service
	IssueCert  func(csrPEM, agentID string) (string, error)
	Log        *slog.Logger
}

// Compile-time interface check.
var _ connectorv1.ConnectorServiceServer = (*ConnectorServer)(nil)

// ConnectorServer implements connectorv1.ConnectorServiceServer.
type ConnectorServer struct {
	connectorv1.UnimplementedConnectorServiceServer
	Deps ConnectorDeps
}

// RegisterConnectorService wires the service into a gRPC server.
func RegisterConnectorService(s *grpc.Server, deps ConnectorDeps) {
	connectorv1.RegisterConnectorServiceServer(s, &ConnectorServer{Deps: deps})
}

// connectorAuth authenticates the per-call credentials from metadata.
func (s *ConnectorServer) connectorAuth(ctx context.Context) (*domain.Connector, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	ids := md.Get("x-aegis-connector-id")
	secrets := md.Get("x-aegis-connector-secret")
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing connector credentials")
	}
	c, err := s.Deps.Connectors.Authenticate(ctx, ids[0], secrets[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return c, nil
}

// Enroll handles first contact: one-time token -> secret + endpoint info.
func (s *ConnectorServer) Enroll(ctx context.Context, req *connectorv1.EnrollRequest) (*connectorv1.EnrollResponse, error) {
	res, err := s.Deps.Connectors.Enroll(ctx, connectors.EnrollRequest{
		Token:        req.GetToken(),
		ExpectedKind: req.GetExpectedKind(),
		Hostname:     req.GetHostname(),
		Platform:     req.GetPlatform(),
		Arch:         req.GetArch(),
		Version:      req.GetVersion(),
		Capabilities: req.GetCapabilities(),
	})
	if err != nil {
		s.Deps.Log.Warn("connector enroll rejected", "err", err)
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &connectorv1.EnrollResponse{
		ConnectorId:           res.Connector.ID,
		Secret:                res.Secret,
		GrpcEndpoint:          res.Endpoint,
		Tls:                   false, // TLS terminated upstream in production deployments
		Config:                configToProto(res.Config),
		HeartbeatIntervalSecs: int32(res.HeartbeatSecs),
		Name:                  res.Connector.Name,
		Kind:                  string(res.Connector.Kind),
	}, nil
}

// GetConfig returns the current configuration (called on every connect).
func (s *ConnectorServer) GetConfig(ctx context.Context, _ *connectorv1.GetConfigRequest) (*connectorv1.ConnectorConfig, error) {
	c, err := s.connectorAuth(ctx)
	if err != nil {
		return nil, err
	}
	return configToProto(s.Deps.Connectors.Config(c)), nil
}

// WatchConfig streams config updates: one snapshot, then live updates.
func (s *ConnectorServer) WatchConfig(req *connectorv1.WatchConfigRequest, stream connectorv1.ConnectorService_WatchConfigServer) error {
	c, err := s.connectorAuth(stream.Context())
	if err != nil {
		return err
	}
	updates, cancel := s.Deps.Connectors.Subscribe(c.ID)
	defer cancel()

	// Initial snapshot: the current configuration at watch time. When the
	// client already knows this version the settings are omitted so the
	// snapshot is a cheap "you are current" marker.
	current := s.Deps.Connectors.Config(c)
	snapshot := req.GetKnownVersion() != current.Version
	if snapshot {
		current.Snapshot = true
	}
	if err := stream.Send(updateToProto(current, snapshot)); err != nil {
		return err
	}
	s.Deps.Log.Info("connector watching config", "connector", c.ID, "version", current.Version)
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case upd, ok := <-updates:
			if !ok {
				return nil
			}
			if err := stream.Send(updateToProto(upd, true)); err != nil {
				return err
			}
		}
	}
}

// Heartbeat records liveness and role status; returns config drift info.
func (s *ConnectorServer) Heartbeat(ctx context.Context, req *connectorv1.HeartbeatRequest) (*connectorv1.HeartbeatResponse, error) {
	c, err := s.connectorAuth(ctx)
	if err != nil {
		return nil, err
	}
	statusJSON := []byte(req.GetStatusJson())
	if len(statusJSON) > 16<<10 {
		return nil, status.Error(codes.InvalidArgument, "status payload too large")
	}
	version, err := s.Deps.Connectors.Touch(ctx, c.ID, req.GetVersion(), req.GetState(), statusJSON)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "connector is not active")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &connectorv1.HeartbeatResponse{
		ServerTime:    time.Now().UTC().Format(time.RFC3339),
		ConfigVersion: version,
	}, nil
}

// GetSelf returns the connector's own record (status command).
func (s *ConnectorServer) GetSelf(ctx context.Context, _ *connectorv1.GetSelfRequest) (*connectorv1.ConnectorSelf, error) {
	c, err := s.connectorAuth(ctx)
	if err != nil {
		return nil, err
	}
	lastSeen := ""
	if c.LastSeen != nil {
		lastSeen = c.LastSeen.UTC().Format(time.RFC3339)
	}
	return &connectorv1.ConnectorSelf{
		ConnectorId:    c.ID,
		Name:           c.Name,
		Kind:           string(c.Kind),
		Status:         c.Status,
		Hostname:       c.Hostname,
		Platform:       c.Platform,
		Arch:           c.Arch,
		Version:        c.Version,
		ConfigVersion:  c.ConfigVersion,
		LastSeen:       lastSeen,
		OrganizationId: c.OrganizationID,
	}, nil
}

// BindDevice attaches (or refreshes) the device identity of a connection
// performing the agent function. The CSR is generated on the endpoint; the
// private key never leaves it. The device record is bound 1:1 to this
// connector.
func (s *ConnectorServer) BindDevice(ctx context.Context, req *connectorv1.BindDeviceRequest) (*connectorv1.BindDeviceResponse, error) {
	c, err := s.connectorAuth(ctx)
	if err != nil {
		return nil, err
	}
	if s.Deps.Agents == nil {
		return nil, status.Error(codes.FailedPrecondition, "device binding unavailable")
	}
	if req.GetCsrPem() == "" {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}
	binding, err := s.Deps.Agents.EnsureForConnector(ctx, c, agents.DeviceRequest{
		CSR:         req.GetCsrPem(),
		Hostname:    req.GetHostname(),
		Platform:    req.GetPlatform(),
		PlatformVer: req.GetPlatformVersion(),
		Arch:        req.GetArch(),
		Version:     req.GetAgentVersion(),
		MachineID:   req.GetMachineId(),
	}, func(csrPEM, agentID string) (string, error) {
		if s.Deps.IssueCert == nil {
			return "", errors.New("agent CA not configured")
		}
		return s.Deps.IssueCert(csrPEM, agentID)
	})
	if err != nil {
		s.Deps.Log.Warn("device bind rejected", "connector", c.ID, "err", err)
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if s.Deps.Agents.DB != nil {
		// Reliable transition: a device is now bound to this connection.
		// The asset link may not exist yet (inventory application follows);
		// the event keys on the agent id.
		_ = alerting.EmitDeviceBound(ctx, s.Deps.Agents.DB, binding.OrgID, binding.SiteID, "", binding.AgentID)
	}
	return &connectorv1.BindDeviceResponse{
		AgentId:               binding.AgentID,
		CertificatePem:        binding.CertificatePEM,
		OrgId:                 binding.OrgID,
		SiteId:                binding.SiteID,
		HeartbeatIntervalSecs: int32(binding.HeartbeatSecs),
	}, nil
}

func configToProto(u connectors.ConfigUpdate) *connectorv1.ConnectorConfig {
	return &connectorv1.ConnectorConfig{
		Version:               u.Version,
		SettingsJson:          string(u.Settings),
		HeartbeatIntervalSecs: int32(u.HeartbeatSecs),
	}
}

func updateToProto(u connectors.ConfigUpdate, snapshot bool) *connectorv1.ConfigUpdate {
	return &connectorv1.ConfigUpdate{
		Version:               u.Version,
		SettingsJson:          string(u.Settings),
		HeartbeatIntervalSecs: int32(u.HeartbeatSecs),
		Snapshot:              snapshot,
	}
}
