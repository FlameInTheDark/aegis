// Package agentclient implements the endpoint side of the control-plane
// data protocol. It speaks gRPC to the server. Transport security:
// TLS when the server URL is https, plaintext only for explicit local
// development (documented warning).
//
// Since v1.24.0 every call carries the connector credentials as per-call
// metadata (x-aegis-connector-id / x-aegis-connector-secret); the server
// resolves the caller's bound device and ignores client-asserted ids.
package agentclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/endpoint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
)

// Client implements the endpoint data plane (agentv1) plus the device
// binding call (connectorv1) over one gRPC connection.
type Client struct {
	conn     *grpc.ClientConn
	stub     agentv1.AgentServiceClient
	connStub connectorv1.ConnectorServiceClient
	target   string
}

// New dials the control plane. The server URL maps: http://host:8080 ->
// gRPC at host:9090 (insecure), https://... -> gRPC with TLS. Connector
// credentials from the config are attached to EVERY call via interceptors.
func New(cfg *endpoint.Config) (*Client, error) {
	target, useTLS, err := grpcTarget(cfg.ServerURL)
	if err != nil {
		return nil, err
	}
	var creds credentials.TransportCredentials
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}
	var unary, stream grpc.DialOption
	if cfg.ConnectorID != "" && cfg.ConnectorSecret != "" {
		inject := func(ctx context.Context) context.Context {
			return metadata.AppendToOutgoingContext(ctx,
				"x-aegis-connector-id", cfg.ConnectorID,
				"x-aegis-connector-secret", cfg.ConnectorSecret)
		}
		unary = grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(inject(ctx), method, req, reply, cc, opts...)
		})
		stream = grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return streamer(inject(ctx), desc, cc, method, opts...)
		})
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds), unary, stream)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, stub: agentv1.NewAgentServiceClient(conn), connStub: connectorv1.NewConnectorServiceClient(conn), target: target}, nil
}

// Target is the resolved gRPC dial address (host:port) the client talks to.
func (c *Client) Target() string { return c.target }

func grpcTarget(serverURL string) (string, bool, error) {
	u := strings.TrimPrefix(serverURL, "http://")
	useTLS := false
	if strings.HasPrefix(serverURL, "https://") {
		u = strings.TrimPrefix(serverURL, "https://")
		useTLS = true
	}
	if u == "" || len(u) > 256 {
		return "", false, fmt.Errorf("invalid server URL")
	}
	if !strings.Contains(u, ":") {
		if useTLS {
			u += ":9443"
		} else {
			u += ":9090"
		}
	}
	return u, useTLS, nil
}

// BindDevice exchanges the locally-generated CSR (public key only) for the
// device identity bound to this connector. Requires connector credentials.
func (c *Client) BindDevice(ctx context.Context, req *endpoint.BindRequest) (*endpoint.BindResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.connStub.BindDevice(cctx, &connectorv1.BindDeviceRequest{
		CsrPem: req.CSR, Hostname: req.Hostname, Platform: req.Platform,
		PlatformVersion: req.PlatformVer, Arch: req.Arch,
		AgentVersion: req.Version, MachineId: req.MachineID,
	})
	if err != nil {
		return nil, err
	}
	return &endpoint.BindResult{
		AgentID:        resp.GetAgentId(),
		CertificatePEM: resp.GetCertificatePem(),
		SiteID:         resp.GetSiteId(),
		HeartbeatSecs:  int(resp.GetHeartbeatIntervalSecs()),
	}, nil
}

// GetConfig fetches collection configuration.
func (c *Client) GetConfig(ctx context.Context, agentID string) (*agentv1.AgentConfig, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.stub.GetConfig(cctx, &agentv1.GetConfigRequest{AgentId: agentID})
}

// Heartbeat reports liveness.
func (c *Client) Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.stub.Heartbeat(cctx, req)
}

// SubmitInventory sends system inventory.
func (c *Client) SubmitInventory(ctx context.Context, req *agentv1.InventoryReport) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitInventory(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("inventory rejected: %s", resp.GetError())
	}
	return nil
}

// SubmitSoftware sends package inventory.
func (c *Client) SubmitSoftware(ctx context.Context, req *agentv1.SoftwareReport) error {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitSoftware(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("software rejected: %s", resp.GetError())
	}
	return nil
}

// SubmitNetworkState sends socket/interface state.
func (c *Client) SubmitNetworkState(ctx context.Context, req *agentv1.NetworkStateReport) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitNetworkState(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("network state rejected: %s", resp.GetError())
	}
	return nil
}

// SubmitSecurityPosture sends posture data.
func (c *Client) SubmitSecurityPosture(ctx context.Context, req *agentv1.SecurityPostureReport) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitSecurityPosture(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("posture rejected: %s", resp.GetError())
	}
	return nil
}

// SubmitMetrics sends one performance sample. When the server runs without
// the analytics tier it acknowledges with a note and the sample is dropped:
// surfaced as endpoint.ErrMetricsStorageDisabled so callers can log once.
func (c *Client) SubmitMetrics(ctx context.Context, req *agentv1.MetricsReport) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitMetrics(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("metrics rejected: %s", resp.GetError())
	}
	if msg := resp.GetError(); msg != "" {
		return fmt.Errorf("%w: %s", endpoint.ErrMetricsStorageDisabled, msg)
	}
	return nil
}

// SubmitMetricsBatch sends every sample collected since the last pull in
// ONE call. Two degradations are mapped onto endpoint sentinel errors: an
// Unimplemented status means the hub predates the batch RPC
// (endpoint.ErrMetricsBatchUnsupported — the runtime falls back to
// per-sample SubmitMetrics), an accepted-but-noted response means the
// analytics tier is absent (endpoint.ErrMetricsStorageDisabled).
func (c *Client) SubmitMetricsBatch(ctx context.Context, req *agentv1.MetricsBatchReport) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.stub.SubmitMetricsBatch(cctx, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return fmt.Errorf("%w: %v", endpoint.ErrMetricsBatchUnsupported, err)
		}
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("metrics batch rejected: %s", resp.GetError())
	}
	if msg := resp.GetError(); msg != "" {
		return fmt.Errorf("%w: %s", endpoint.ErrMetricsStorageDisabled, msg)
	}
	return nil
}

// PollTasks fetches pending typed tasks.
func (c *Client) PollTasks(ctx context.Context, agentID string) ([]*agentv1.AgentTask, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := c.stub.PollTasks(cctx, &agentv1.PollTasksRequest{AgentId: agentID})
	if err != nil {
		return nil, err
	}
	return resp.GetTasks(), nil
}

// CompleteTask reports a task result.
func (c *Client) CompleteTask(ctx context.Context, req *agentv1.CompleteTaskRequest) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.stub.CompleteTask(cctx, req)
	if err != nil {
		return err
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("task completion rejected: %s", resp.GetError())
	}
	return nil
}
