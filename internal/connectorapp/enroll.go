package connectorapp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
)

// EnrollAndSave runs the first-contact flow against the endpoint in the
// --connect specification:
//
//	connect target + one-time token -> Enroll -> (allow message) ->
//	persist the credential file -> return it.
//
// On rejection the error carries the backend's message so the CLI can
// terminate with it (the protocol requires the token to be single-use).
func EnrollAndSave(ctx context.Context, server, token string, useTLS bool, kindHint, cfgPath string, log *slog.Logger) (*LocalConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("enrollment token is required (aegis-connector --connect <host:port>/<token>)")
	}
	client, err := Dial(server, useTLS)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	hostname, _ := os.Hostname()
	resp, err := client.Enroll(ctx, &connectorv1.EnrollRequest{
		Token:        token,
		ExpectedKind: kindHint,
		Hostname:     hostname,
		Platform:     runtime.GOOS,
		Arch:         runtime.GOARCH,
		Version:      Version,
		Capabilities: []string{"status_reporting", "config_hot_reload"},
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %v", err)
	}
	cfg := &LocalConfig{
		Server:        server,
		TLS:           useTLS || resp.GetTls(),
		ConnectorID:   resp.GetConnectorId(),
		Secret:        resp.GetSecret(),
		Kind:          resp.GetKind(),
		Name:          resp.GetName(),
		GrpcEndpoint:  resp.GetGrpcEndpoint(),
		ConfigVersion: resp.GetConfig().GetVersion(),
		HeartbeatSecs: int(resp.GetHeartbeatIntervalSecs()),
	}
	if cfg.HeartbeatSecs < 10 {
		cfg.HeartbeatSecs = 30
	}
	if err := Save(cfgPath, cfg); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}
	log.Info("enrollment accepted",
		"connector", cfg.ConnectorID, "name", cfg.Name, "kind", cfg.Kind,
		"config_path", cfgPath, "config_version", cfg.ConfigVersion)
	return cfg, nil
}

// PrintSummary logs the operator-facing enrollment summary.
func PrintSummary(cfg *LocalConfig, cfgPath string, log *slog.Logger) {
	kind := cfg.Kind
	if kind == "" {
		kind = "generic"
	}
	log.Info("connector ready",
		"connector", cfg.ConnectorID,
		"name", cfg.Name,
		"kind", kind,
		"endpoint", cfg.Server,
		"tls", cfg.TLS,
		"config_path", cfgPath,
		"run", "aegis-connector start --config "+cfgPath,
		"install", "aegis-connector install --config "+cfgPath,
	)
}
