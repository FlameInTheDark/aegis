// Package agentclient implements the agent side of the control-plane
// protocol. It speaks gRPC to the server (spec §136). Transport security:
// TLS when the server URL is https, plaintext only for explicit local
// development (documented warning).
package agentclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/endpoint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// Client implements endpoint.Client over gRPC.
type Client struct {
	conn *grpc.ClientConn
	stub agentv1.AgentServiceClient
}

// New dials the control plane. The server URL maps: http://host:8080 ->
// gRPC at host:9090 (insecure), https://... -> gRPC with TLS.
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
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, stub: agentv1.NewAgentServiceClient(conn)}, nil
}

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

// Enroll exchanges the one-time token + CSR for a device cert.
func (c *Client) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.stub.Enroll(cctx, req)
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
