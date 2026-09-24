package connectorapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	connectorv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/connector/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrCredentialRejected is a terminal error: the backend refused the saved
// credentials (revoked/rotated). The loop must not retry forever; the
// operator has to run `aegis-connector reconnect` with a fresh token.
var ErrCredentialRejected = errors.New("connector credentials rejected by backend")

// Runtime is the persistent work loop. On every (re)connection it:
//
//  1. fetches the current configuration (reload-on-connect),
//  2. applies it to the role (hot reload, no restart),
//  3. opens a WatchConfig stream that applies later changes live,
//  4. heartbeats liveness + role status, using the response's
//     config_version to recover from missed watch updates.
type Runtime struct {
	Cfg  *LocalConfig
	Role Role
	Log  *slog.Logger

	// applied carries the live configuration to the heartbeat path.
	applied struct {
		version int64
		hb      int
	}
	intervalCh chan int
	updates    chan func()
}

// NewRuntime wires a runtime for the saved credentials. functionOverride
// is "" to follow the connection settings toggles, or "agent"/"scanner"
// to run exactly that function regardless of the toggles (CLI --agent /
// --scanner).
func NewRuntime(cfg *LocalConfig, log *slog.Logger, functionOverride string) *Runtime {
	role := NewRole(cfg.Kind, log, cfg, functionOverride)
	hb := cfg.HeartbeatSecs
	if hb < 10 {
		hb = 30
	}
	rt := &Runtime{Cfg: cfg, Role: role, Log: log, intervalCh: make(chan int, 1), updates: make(chan func(), 16)}
	rt.applied.version = cfg.ConfigVersion
	rt.applied.hb = hb
	return rt
}

// Run keeps the connector working until ctx is cancelled, reconnecting
// with exponential backoff. Terminal credential failures abort the loop.
// A cancelled context triggers one best-effort "shutting down" heartbeat
// so the backend can show the graceful stop instead of waiting for
// heartbeats to go stale.
func (rt *Runtime) Run(ctx context.Context) error {
	started := time.Now()
	backoff := time.Second
	defer func() {
		if ctx.Err() != nil {
			rt.notifyShutdown()
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := rt.session(ctx, started)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrCredentialRejected) {
			return err
		}
		rt.Log.Warn("connection lost; reconnecting", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// session is one live connection: config reload + watch + heartbeat + role.
func (rt *Runtime) session(ctx context.Context, started time.Time) error {
	client, err := Dial(rt.Cfg.Server, rt.Cfg.TLS)
	if err != nil {
		return err
	}
	defer client.Close()
	client.SetCredentials(rt.Cfg.ConnectorID, rt.Cfg.Secret)

	// 1. Reload configuration on EVERY connection (protocol step: request
	// configuration) so changes made offline take effect immediately.
	if err := rt.reloadConfig(ctx, client); err != nil {
		return rt.mapErr(err)
	}
	rt.Log.Info("connected", "server", rt.Cfg.Server, "connector", rt.Cfg.ConnectorID,
		"kind", rt.Cfg.Kind, "config_version", rt.applied.version)

	// 2. Watch stream for hot reload.
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go rt.watchLoop(watchCtx, client)

	// 3. Role work loop (per-kind logic on top of the config).
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	go func() {
		if err := rt.Role.Run(workCtx, rt.Log); err != nil {
			rt.Log.Warn("role loop stopped", "err", err)
		}
	}()

	// 4. Heartbeat loop with drift recovery + dynamic interval.
	return rt.heartbeatLoop(ctx, client, started)
}

// reloadConfig fetches and applies the current configuration.
func (rt *Runtime) reloadConfig(ctx context.Context, client *Client) error {
	cfg, err := client.GetConfig(ctx)
	if err != nil {
		return err
	}
	return rt.applyConfig(cfg.GetVersion(), cfg.GetSettingsJson(), int(cfg.GetHeartbeatIntervalSecs()))
}

// watchLoop applies configuration updates pushed by the backend.
func (rt *Runtime) watchLoop(ctx context.Context, client *Client) {
	stream, err := client.WatchConfig(ctx, rt.applied.version)
	if err != nil {
		rt.Log.Warn("config watch unavailable (heartbeat drift recovery still active)", "err", err)
		return
	}
	for {
		upd, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				rt.Log.Warn("config watch ended; will re-establish on next heartbeat check", "err", err)
			}
			return
		}
		if err := rt.applyConfig(upd.GetVersion(), upd.GetSettingsJson(), int(upd.GetHeartbeatIntervalSecs())); err != nil {
			rt.Log.Warn("config update rejected", "err", err)
			continue
		}
		if upd.GetSnapshot() {
			rt.Log.Info("configuration applied", "version", upd.GetVersion(), "source", "watch-snapshot")
		} else {
			rt.Log.Info("configuration applied", "version", upd.GetVersion(), "source", "watch-update")
		}
	}
}

// heartbeatLoop reports liveness + role status; the response's
// config_version detects missed watch updates (drift recovery).
func (rt *Runtime) heartbeatLoop(ctx context.Context, client *Client, started time.Time) error {
	timer := time.NewTimer(time.Duration(rt.applied.hb) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case hb := <-rt.intervalCh:
			timer.Reset(time.Duration(hb) * time.Second)
			continue
		case <-timer.C:
		}
		statusJSON, _ := json.Marshal(rt.Role.Status())
		resp, err := client.Heartbeat(ctx, &connectorv1.HeartbeatRequest{
			Version:    Version,
			UptimeSecs: uint64(time.Since(started).Seconds()),
			StatusJson: string(statusJSON),
			State:      "running",
		})
		if err != nil {
			return rt.mapErr(err)
		}
		if resp.GetConfigVersion() != rt.applied.version {
			// Missed watch update — reload directly.
			if err := rt.reloadConfig(ctx, client); err != nil {
				rt.Log.Warn("drift recovery refetch failed", "err", err)
			} else {
				rt.Log.Info("configuration applied", "version", rt.applied.version, "source", "drift-recovery")
			}
		}
		timer.Reset(time.Duration(rt.applied.hb) * time.Second)
	}
}

// applyConfig applies a configuration revision to the role and the local
// snapshot, adjusting the heartbeat interval when it changed.
func (rt *Runtime) applyConfig(version int64, settingsJSON string, hb int) error {
	if hb < 10 || hb > 3600 {
		hb = 30
	}
	settings := json.RawMessage(settingsJSON)
	if err := rt.Role.ApplyConfig(context.Background(), settings); err != nil {
		return err
	}
	prevHb := rt.applied.hb
	rt.applied.version = version
	rt.applied.hb = hb
	rt.Cfg.ConfigVersion = version
	rt.Cfg.HeartbeatSecs = hb
	if hb != prevHb {
		select {
		case rt.intervalCh <- hb:
		default:
		}
	}
	return nil
}

// notifyShutdown best-effort reports state=shutting_down: the backend
// stamps shutdown_at, the UI shows "shutting down" until the grace window
// passes, then the connection degrades to offline. Never blocks the
// shutdown path for more than a few seconds; failures are ignored (the
// stale-heartbeat path yields the same offline state, just slower).
func (rt *Runtime) notifyShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Dial(rt.Cfg.Server, rt.Cfg.TLS)
	if err != nil {
		return
	}
	defer client.Close()
	client.SetCredentials(rt.Cfg.ConnectorID, rt.Cfg.Secret)
	statusJSON, _ := json.Marshal(rt.Role.Status())
	_, _ = client.Heartbeat(ctx, &connectorv1.HeartbeatRequest{
		Version:    Version,
		StatusJson: string(statusJSON),
		State:      "shutting_down",
	})
	rt.Log.Info("graceful shutdown reported")
}

// mapErr translates gRPC failures into runtime decisions.
func (rt *Runtime) mapErr(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
		return fmt.Errorf("%w: %v", ErrCredentialRejected, err)
	default:
		return err
	}
}
