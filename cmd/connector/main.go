// Command connector is the unified external-connector binary
// (aegis-connector). Endpoint agents, remote scanners and external
// collectors all use this one binary: identical connection protocol,
// per-kind role logic on top.
//
// First contact (from the UI connect command):
//
//	aegis-connector --connect host:port/<one-time-token>
//
// Continuous run (after enrollment saved the credential file):
//
//	aegis-connector start
//
// Reconnect after a backend address change or lost credentials (new token
// from the UI "Reconnect" action):
//
//	aegis-connector reconnect --connect host:port/<new-one-time-token>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/FlameInTheDark/aegis/internal/connectorapp"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/urfave/cli/v3"
)

// version is overridden at build time: -ldflags "-X main.version=$(cat VERSION)".
var version = "dev"

func main() {
	cmd := &cli.Command{
		Name:    "aegis-connector",
		Usage:   "connect an external component (agent, scanner, collector) to the Aegis platform",
		Version: version,
		Description: "All externally connected components share the same connection protocol:\n" +
			"one-time token enrollment over gRPC, a long-lived connector secret,\n" +
			"configuration hot reload and heartbeat liveness. Different logic per\n" +
			"kind runs on top of that shared protocol.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "connect",
				Usage: "enroll and start: --connect <host:port>/<one-time-token> (prefix tls:// for TLS)",
			},
			&cli.StringFlag{
				Name:    "config",
				Usage:   "path to the local credential file",
				Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG"),
			},
			&cli.StringFlag{
				Name:  "kind",
				Usage: "optional safety check: reject enrollment unless the connection record is of this kind (agent|scanner|collector)",
			},
			&cli.BoolFlag{
				Name:  "install",
				Usage: "with --connect: install as a system service (systemd) after enrollment",
			},
			&cli.BoolFlag{
				Name:  "no-start",
				Usage: "with --connect/--reconnect: save credentials and exit without starting work",
			},
			&cli.BoolFlag{
				Name:  "agent",
				Usage: "run ONLY the endpoint-collection function, ignoring the connection's function toggles",
			},
			&cli.BoolFlag{
				Name:  "scanner",
				Usage: "run ONLY the remote-scanning function, ignoring the connection's function toggles",
			},
		},
		Action: rootAction,
		Commands: []*cli.Command{
			connectCommand(),
			startCommand(),
			statusCommand(),
			reconnectCommand(),
			installCommand(),
			uninstallCommand(),
			resetCommand(),
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// rootAction handles `aegis-connector --connect host:port/token` (the
// connection string rendered by the UI). Without --connect it shows help.
func rootAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.String("connect") == "" {
		return cli.ShowAppHelp(cmd)
	}
	return enrollAndWork(ctx, cmd)
}

func connectCommand() *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "enroll with a one-time token, save the credential file and start work",
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "connect", Usage: "<host:port>/<one-time-token> (prefix tls:// for TLS)"},
			&cli.StringFlag{Name: "server", Usage: "gRPC endpoint host:port (alternative to --connect)"},
			&cli.StringFlag{Name: "token", Usage: "one-time enrollment token (alternative to --connect)"},
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
			&cli.StringFlag{Name: "kind"},
			&cli.BoolFlag{Name: "install"},
			&cli.BoolFlag{Name: "no-start"},
		}, functionFlags()...),
		Action: enrollAndWork,
	}
}

func reconnectCommand() *cli.Command {
	return &cli.Command{
		Name:  "reconnect",
		Usage: "re-enroll with a NEW one-time token (from the UI reconnect action) and replace saved credentials",
		Description: "Use when the backend address changed, the secret was lost, or the\n" +
			"connection was revoked. The old credential is replaced by the fresh\n" +
			"enrollment; the connector identity (name/kind/config) is preserved.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "connect", Usage: "<host:port>/<new-one-time-token> (prefix tls:// for TLS)"},
			&cli.StringFlag{Name: "server", Usage: "gRPC endpoint host:port (alternative to --connect)"},
			&cli.StringFlag{Name: "token", Usage: "new one-time enrollment token (alternative to --connect)"},
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
			&cli.StringFlag{Name: "kind"},
			&cli.BoolFlag{Name: "no-start"},
		}, functionFlags()...),
		Action: enrollAndWork,
	}
}

// enrollAndWork implements connect/reconnect/root --connect.
func enrollAndWork(ctx context.Context, cmd *cli.Command) error {
	log := logging.New("info", "console")
	override, err := functionOverride(cmd)
	if err != nil {
		return err
	}
	spec := cmd.String("connect")
	server, token := cmd.String("server"), cmd.String("token")
	useTLS := false
	if spec != "" {
		var err error
		server, token, useTLS, err = connectorapp.ParseConnectTarget(spec)
		if err != nil {
			return err
		}
	}
	if server == "" || token == "" {
		return fmt.Errorf("a one-time token and endpoint are required: --connect <host:port>/<token> (or --server + --token)")
	}

	cfgPath := connectorapp.DefaultPath(cmd.String("config"))
	cfg, err := connectorapp.EnrollAndSave(ctx, server, token, useTLS, cmd.String("kind"), cfgPath, log)
	if err != nil {
		return err // enrollment rejected: terminate with the backend's message
	}
	connectorapp.PrintSummary(cfg, cfgPath, log)

	if cmd.Bool("install") {
		if err := connectorapp.InstallService(cfgPath); err != nil {
			return err
		}
		log.Info("service installed; work continues under systemd")
		return nil
	}
	if cmd.Bool("no-start") {
		return nil
	}
	log.Info("starting work loop (ctrl-c to stop)")
	return runWork(ctx, cfg, cfgPath, log, override)
}

func startCommand() *cli.Command {
	return &cli.Command{
		Name:  "start",
		Usage: "run continuously with the saved credentials (reload config on connect, hot reload, heartbeat)",
		Description: "By default the functions this connection performs follow the toggles in the\n" +
			"connection settings on the hub (endpoint collection and/or remote scanning).\n" +
			"Pass --agent or --scanner to run exactly one function regardless of the\n" +
			"toggles (useful for one-off runs and service units).",
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
		}, functionFlags()...),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			log := logging.New("info", "console")
			override, err := functionOverride(cmd)
			if err != nil {
				return err
			}
			cfgPath := connectorapp.DefaultPath(cmd.String("config"))
			cfg, err := connectorapp.Load(cfgPath)
			if err != nil {
				return err
			}
			log.Info("aegis connector starting", "version", connectorapp.Version,
				"connector", cfg.ConnectorID, "kind", cfg.Kind, "server", cfg.Server,
				"config_version", cfg.ConfigVersion)
			return runWork(ctx, cfg, cfgPath, log, override)
		},
	}
}

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "check the connection state of this component from the backend",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfgPath := connectorapp.DefaultPath(cmd.String("config"))
			cfg, err := connectorapp.Load(cfgPath)
			if err != nil {
				return err
			}
			client, err := connectorapp.Dial(cfg.Server, cfg.TLS)
			if err != nil {
				return err
			}
			defer client.Close()
			client.SetCredentials(cfg.ConnectorID, cfg.Secret)
			self, err := client.GetSelf(ctx)
			if err != nil {
				return fmt.Errorf("status check failed: %v", err)
			}
			out := map[string]any{
				"connector_id":   self.GetConnectorId(),
				"name":           self.GetName(),
				"kind":           self.GetKind(),
				"status":         self.GetStatus(),
				"hostname":       self.GetHostname(),
				"platform":       self.GetPlatform(),
				"arch":           self.GetArch(),
				"version":        self.GetVersion(),
				"config_version": self.GetConfigVersion(),
				"last_seen":      self.GetLastSeen(),
				"local_config":   cfgPath,
			}
			enc, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(enc))
			return nil
		},
	}
}

func installCommand() *cli.Command {
	return &cli.Command{
		Name:  "install",
		Usage: "install as a system service (systemd) that runs `aegis-connector start`",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			cfgPath := connectorapp.DefaultPath(cmd.String("config"))
			if _, err := connectorapp.Load(cfgPath); err != nil {
				return err
			}
			return connectorapp.InstallService(cfgPath)
		},
	}
}

func uninstallCommand() *cli.Command {
	return &cli.Command{
		Name:  "uninstall",
		Usage: "stop and remove the system service",
		Action: func(_ context.Context, _ *cli.Command) error {
			return connectorapp.UninstallService()
		},
	}
}

func resetCommand() *cli.Command {
	return &cli.Command{
		Name:  "reset",
		Usage: "remove the saved credential file (revoke does the rest server-side)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("AEGIS_CONNECTOR_CONFIG")},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			cfgPath := connectorapp.DefaultPath(cmd.String("config"))
			if err := connectorapp.Remove(cfgPath); err != nil {
				return err
			}
			fmt.Println("removed:", cfgPath)
			return nil
		},
	}
}

// functionFlags returns the --agent/--scanner override flags shared by the
// run paths (root, connect, reconnect, start).
func functionFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "agent",
			Usage: "run ONLY the endpoint-collection function, ignoring the connection's function toggles",
		},
		&cli.BoolFlag{
			Name:  "scanner",
			Usage: "run ONLY the remote-scanning function, ignoring the connection's function toggles",
		},
	}
}

// functionOverride resolves the --agent/--scanner flags into a single
// function override; passing both is an error (they are mutually exclusive
// by definition: each means "only this one").
func functionOverride(cmd *cli.Command) (string, error) {
	agent, scanner := cmd.Bool("agent"), cmd.Bool("scanner")
	switch {
	case agent && scanner:
		return "", fmt.Errorf("--agent and --scanner are mutually exclusive; run both by removing both flags (the connection settings toggles decide)")
	case agent:
		return connectorapp.FnAgent, nil
	case scanner:
		return connectorapp.FnScanner, nil
	default:
		return "", nil
	}
}

// runWork wires signal handling around the persistent runtime.
func runWork(ctx context.Context, cfg *connectorapp.LocalConfig, _ string, log *slog.Logger, functionOverride string) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	rt := connectorapp.NewRuntime(cfg, log, functionOverride)
	if err := rt.Run(ctx); err != nil {
		if errors.Is(err, connectorapp.ErrCredentialRejected) {
			fmt.Fprintln(os.Stderr, "credentials were rejected by the backend.")
			fmt.Fprintln(os.Stderr, "Run `aegis-connector reconnect --connect <host:port>/<new-token>` with a token from the UI (Reconnect action), then `start` again.")
		}
		return err
	}
	log.Info("connector stopped")
	return nil
}
