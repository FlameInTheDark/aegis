package connectorapp

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Client is the connector side of aegis.connector.v1. Continued-run
// authentication rides as per-call metadata (connector id + secret).
type Client struct {
	conn *grpc.ClientConn
	stub connectorv1.ConnectorServiceClient
	id   string
	sec  string
}

// ParseConnectTarget splits a --connect specification into its endpoint
// and TLS flag. Accepted forms:
//
//	host:port/token      plaintext (local development)
//	tls://host:port/token
//	host:port            (token optional here; connect passes it separately)
func ParseConnectTarget(spec string) (endpoint string, token string, useTLS bool, err error) {
	rest := strings.TrimSpace(spec)
	if rest == "" {
		return "", "", false, fmt.Errorf("empty connect target")
	}
	if strings.HasPrefix(rest, "tls://") {
		useTLS = true
		rest = strings.TrimPrefix(rest, "tls://")
	} else if strings.HasPrefix(rest, "https://") {
		useTLS = true
		rest = strings.TrimPrefix(rest, "https://")
	} else {
		rest = strings.TrimPrefix(rest, "http://")
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		token = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" || len(rest) > 256 {
		return "", "", false, fmt.Errorf("invalid connect target endpoint")
	}
	if !strings.Contains(rest, ":") {
		if useTLS {
			rest += ":443"
		} else {
			rest += ":9090"
		}
	}
	if token != "" && len(token) > 512 {
		return "", "", false, fmt.Errorf("connect target token too long")
	}
	return rest, token, useTLS, nil
}

// Dial opens the gRPC connection. TLS is used when requested by the target
// scheme or the saved config; plaintext is accepted for development only
// and logs a warning.
func Dial(server string, useTLS bool) (*Client, error) {
	var creds credentials.TransportCredentials
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	return &Client{conn: conn, stub: connectorv1.NewConnectorServiceClient(conn)}, nil
}

// SetCredentials attaches the continued-connection credentials.
func (c *Client) SetCredentials(id, secret string) { c.id, c.sec = id, secret }

// Ctx returns ctx with the connector credential metadata attached.
func (c *Client) Ctx(ctx context.Context) context.Context {
	if c.id == "" && c.sec == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx,
		"x-aegis-connector-id", c.id,
		"x-aegis-connector-secret", c.sec,
	)
}

// Enroll exchanges the one-time token for the allow message (secret +
// endpoint info + initial config).
func (c *Client) Enroll(ctx context.Context, req *connectorv1.EnrollRequest) (*connectorv1.EnrollResponse, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.stub.Enroll(cctx, req)
}

// GetConfig fetches the current configuration.
func (c *Client) GetConfig(ctx context.Context) (*connectorv1.ConnectorConfig, error) {
	cctx, cancel := context.WithTimeout(c.Ctx(ctx), 15*time.Second)
	defer cancel()
	return c.stub.GetConfig(cctx, &connectorv1.GetConfigRequest{})
}

// WatchConfig opens the server-streaming config watch.
func (c *Client) WatchConfig(ctx context.Context, knownVersion int64) (connectorv1.ConnectorService_WatchConfigClient, error) {
	return c.stub.WatchConfig(c.Ctx(ctx), &connectorv1.WatchConfigRequest{KnownVersion: knownVersion})
}

// Heartbeat reports liveness + role status.
func (c *Client) Heartbeat(ctx context.Context, req *connectorv1.HeartbeatRequest) (*connectorv1.HeartbeatResponse, error) {
	cctx, cancel := context.WithTimeout(c.Ctx(ctx), 15*time.Second)
	defer cancel()
	return c.stub.Heartbeat(cctx, req)
}

// GetSelf fetches the connector's own record.
func (c *Client) GetSelf(ctx context.Context) (*connectorv1.ConnectorSelf, error) {
	cctx, cancel := context.WithTimeout(c.Ctx(ctx), 15*time.Second)
	defer cancel()
	return c.stub.GetSelf(cctx, &connectorv1.GetSelfRequest{})
}

// Close tears down the connection.
func (c *Client) Close() { _ = c.conn.Close() }

// BindDevice attaches or refreshes the device identity of an agent-kind
// connector (CSR generated on the endpoint; private key never leaves).
func (c *Client) BindDevice(ctx context.Context, req *connectorv1.BindDeviceRequest) (*connectorv1.BindDeviceResponse, error) {
	cctx, cancel := context.WithTimeout(c.Ctx(ctx), 30*time.Second)
	defer cancel()
	return c.stub.BindDevice(cctx, req)
}
