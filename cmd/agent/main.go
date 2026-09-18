// Command agent is the endpoint agent binary (spec §5.4, §16-§20). It
// collects bounded inventory, executes only typed tasks, and never sends
// private keys or credentials anywhere.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/FlameInTheDark/aegis/internal/endpoint"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/transport/agentclient"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := ""
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
	}
	cfg, err := endpoint.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := logging.New("info", "console")
	log.Info("aegis agent starting", "version", endpoint.AgentVersion, "platform", endpoint.Platform(), "server", cfg.ServerURL)

	client, err := agentclient.New(cfg)
	if err != nil {
		return fmt.Errorf("agent client: %w", err)
	}
	rt := &endpoint.Runtime{
		Cfg: cfg, Client: client,
		Collector: &endpoint.Collector{Cfg: cfg, Log: log},
		Log:       log,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rt.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("agent stopped")
	return nil
}
