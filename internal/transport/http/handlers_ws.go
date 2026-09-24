// WebSocket streaming endpoint (v1.13.0): realtime job logs, scan state
// and notifications. Replaces the short-polling refresh loops in the UI —
// see docs/API.md "WebSocket streaming" for the wire protocol.
//
// Auth model: browsers hold the access JWT in memory (never cookies or
// storage), and the WS handshake cannot carry custom headers, so the token
// rides the access_token query parameter of the upgrade request. The
// parameter is validated with the same issuer/secret as the HTTP
// middleware; wss:// in production keeps it encrypted in transit.
package httpx

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/joblog"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// wsClient carries per-connection state for the streaming handlers.
type wsClient struct {
	svc    *Services
	claims *auth.Claims
	hub    *joblog.Hub
	sub    *joblog.Sub
	// mu guards the write channel (writer goroutine only) and closed flag.
	mu     sync.Mutex
	closed bool
}

// wsUpgradeGuard authenticates the upgrade request via the access_token
// query parameter and rejects plain HTTP requests early.
func (a *App) wsUpgradeGuard() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Auth FIRST so a plain request without a token gets a clean 401
		// instead of leaking upgrade machinery details.
		token := c.Query("access_token")
		if token == "" {
			// Cookie fallback is intentionally NOT supported for the
			// streaming socket: the refresh cookie would upgrade a stale
			// tab into a live listener. Explicit token only.
			return Unauthorized("access_token query parameter required")
		}
		issuer := auth.NewTokenIssuer(a.svc.Cfg.Auth.JWTSecret, a.svc.Cfg.Auth.AccessTokenTTL, a.svc.Cfg.Auth.RefreshTokenTTL)
		claims, err := issuer.ParseAccess(token)
		if err != nil || claims.HasAudience("refresh") {
			return Unauthorized("invalid or expired token")
		}
		c.Locals("claims", claims)
		if !websocket.IsWebSocketUpgrade(c) {
			// Authenticated but not a websocket handshake: plain GET
			// returns 426 so operators probing with curl get a hint.
			return fiber.NewError(fiber.StatusUpgradeRequired, "websocket upgrade required")
		}
		return c.Next()
	}
}

// handleWSConn runs one streaming connection: hello → subscribe loop →
// event fan-out until the socket drops.
func (a *App) handleWSConn(c *websocket.Conn) {
	claims, _ := c.Locals("claims").(*auth.Claims)
	if claims == nil {
		return // guard middleware ensures claims; defensive
	}
	client := &wsClient{
		svc:    a.svc,
		claims: claims,
		hub:    a.svc.WSHub,
		sub:    a.svc.WSHub.Subscribe(claims.OrganizationID),
	}
	defer client.sub.Unsubscribe()

	_ = c.SetReadDeadline(time.Now().Add(90 * time.Second))
	// hello: identity handshake so the client can verify org scope early.
	_ = c.WriteJSON(map[string]any{
		"type": "hello",
		"org":  claims.OrganizationID,
		"user": claims.Subject,
		"ts":   time.Now().UTC().Format(time.RFC3339),
	})

	// Writer goroutine: hub events → socket.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range client.sub.C() {
			payload := map[string]any{
				"type":    "event",
				"channel": ev.Channel,
				"kind":    ev.Kind,
				"data":    ev.Data,
				"ts":      time.Now().UTC().Format(time.RFC3339),
			}
			client.mu.Lock()
			if client.closed {
				client.mu.Unlock()
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := c.WriteJSON(payload)
			client.mu.Unlock()
			if err != nil {
				_ = c.Conn.Close()
				return
			}
		}
	}()

	// Reader loop: client control messages.
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		if client.handleControl(c, msg) {
			break
		}
	}
	client.mu.Lock()
	client.closed = true
	client.mu.Unlock()
	_ = c.Conn.Close()
	<-done // writer drains after Unsubscribe closes the sub channel
}

// handleControl processes one client frame. Returns true to terminate.
func (w *wsClient) handleControl(c *websocket.Conn, msg []byte) bool {
	var req struct {
		Type    string `json:"type"`
		Channel string `json:"channel"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		_ = c.WriteJSON(map[string]any{"type": "error", "message": "malformed frame"})
		return false
	}
	_ = c.SetReadDeadline(time.Now().Add(90 * time.Second))
	switch req.Type {
	case "ping":
		_ = c.WriteJSON(map[string]any{"type": "pong"})
	case "sub":
		if !w.authorize(req.Channel) {
			_ = c.WriteJSON(map[string]any{"type": "error", "message": "forbidden channel", "channel": req.Channel})
			return false
		}
		if len(strings.Split(req.Channel, ",")) > 32 {
			_ = c.WriteJSON(map[string]any{"type": "error", "message": "too many channels"})
			return false
		}
		w.sub.Join(req.Channel)
		_ = c.WriteJSON(map[string]any{"type": "subscribed", "channel": req.Channel})
	case "unsub":
		w.sub.Leave(req.Channel)
		_ = c.WriteJSON(map[string]any{"type": "unsubscribed", "channel": req.Channel})
	case "close":
		return true
	default:
		_ = c.WriteJSON(map[string]any{"type": "error", "message": "unknown type"})
	}
	return false
}

// authorize validates a subscribe request against the claims. Notify is
// org-scoped inside the hub (publish filter); scan channels are checked
// here against the scan row so foreign ids get an explicit rejection
// instead of silent emptiness.
func (w *wsClient) authorize(channel string) bool {
	if channel == "" || len(channel) > 128 {
		return false
	}
	if channel == "notify" {
		return true
	}
	if scanID, ok := strings.CutPrefix(channel, "scan:"); ok {
		if scanID == "" {
			return false
		}
		if _, err := uuid.Parse(scanID); err != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		scan, err := w.svc.Scans.ByID(ctx, "", scanID)
		return err == nil && scan != nil && scan.OrganizationID == w.claims.OrganizationID
	}
	return false
}
