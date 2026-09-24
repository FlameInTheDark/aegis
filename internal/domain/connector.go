package domain

import (
	"encoding/json"
	"time"
)

// ConnectorKind identifies the role logic an external component runs on
// top of the shared connection protocol. All kinds enroll, authenticate,
// receive configuration and heartbeat identically; only the role behavior
// on top differs.
type ConnectorKind string

const (
	ConnectorAgent     ConnectorKind = "agent"     // endpoint device agent
	ConnectorScanner   ConnectorKind = "scanner"   // remote scanning component
	ConnectorCollector ConnectorKind = "collector" // external telemetry collector
)

// ValidConnectorKinds is the set the UI/API accept at creation time.
var ValidConnectorKinds = map[ConnectorKind]bool{
	ConnectorAgent: true, ConnectorScanner: true, ConnectorCollector: true,
}

// Connector lifecycle statuses. `active` connectors are presented as
// online/offline depending on last_seen freshness (OnlineWindow).
const (
	ConnectorStatusPending = "pending"
	ConnectorStatusActive  = "active"
	ConnectorStatusRevoked = "revoked"
)

// DefaultHeartbeatSecs is the enrollment heartbeat interval hint. 15s
// keeps the derived online/offline state snappy (one missed beat is
// tolerated, two trip the offline state) at negligible RPC cost.
const DefaultHeartbeatSecs = 15

// OnlineWindow returns how long after last_seen a connector with the given
// configuration is still considered online: two heartbeat intervals, with
// a 30s floor so the minimum 10s interval never flaps on transient jitter.
func OnlineWindow(cfg json.RawMessage) time.Duration {
	var hc struct {
		HeartbeatSecs int `json:"heartbeat_secs"`
	}
	if len(cfg) > 0 && json.Unmarshal(cfg, &hc) == nil && hc.HeartbeatSecs >= 10 && hc.HeartbeatSecs <= 3600 {
		w := time.Duration(hc.HeartbeatSecs*2) * time.Second
		if w < 30*time.Second {
			w = 30 * time.Second
		}
		return w
	}
	return time.Duration(DefaultHeartbeatSecs*2) * time.Second
}

// Derived connection states shown in the UI (on top of the lifecycle
// status pending/active/revoked).
const (
	ConnStateOnline       = "online"
	ConnStateShuttingDown = "shutting_down"
	ConnStateOffline      = "offline"
)

// GraceWindow is how long a connector that reported shutting down keeps
// the "shutting_down" state before it degrades to offline.
var GraceWindow = OnlineWindow(nil)

// Connector is a registered external component (agent/scanner/collector).
type Connector struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	SiteID         string          `json:"site_id,omitempty"`
	Kind           ConnectorKind   `json:"kind"`
	Name           string          `json:"name"`
	Status         string          `json:"status"` // pending|active|revoked
	Hostname       string          `json:"hostname,omitempty"`
	Platform       string          `json:"platform,omitempty"`
	Arch           string          `json:"arch,omitempty"`
	Version        string          `json:"version,omitempty"`
	Capabilities   json.RawMessage `json:"capabilities,omitempty"`
	Config         json.RawMessage `json:"config"`
	ConfigVersion  int64           `json:"config_version"`
	EnrolledAt     *time.Time      `json:"enrolled_at,omitempty"`
	LastSeen       *time.Time      `json:"last_seen,omitempty"`
	// ShutdownAt is set by the final heartbeat of a gracefully stopping
	// component (state=shutting_down) and cleared by the next running
	// heartbeat; the derived conn_state shows "shutting down" until it
	// goes stale.
	ShutdownAt *time.Time      `json:"shutdown_at,omitempty"`
	LastStatus json.RawMessage `json:"last_status,omitempty"`
	CreatedBy  string          `json:"created_by,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// Online reports whether the connector is actively connected: an active
// record whose last heartbeat is inside the freshness window derived from
// its configured heartbeat interval and that did not just report a
// graceful shutdown.
func (c *Connector) Online(now time.Time) bool {
	if c.Status != ConnectorStatusActive || c.LastSeen == nil {
		return false
	}
	if c.ShuttingDown(now) {
		return false
	}
	return now.Sub(*c.LastSeen) <= OnlineWindow(c.Config)
}

// ShuttingDown reports whether the connector announced a graceful stop
// recently enough that the UI should show "shutting down" instead of
// offline (it degrades to offline once the grace window passes).
func (c *Connector) ShuttingDown(now time.Time) bool {
	if c.Status != ConnectorStatusActive || c.ShutdownAt == nil {
		return false
	}
	return now.Sub(*c.ShutdownAt) <= GraceWindow
}

// ConnState derives the UI-facing connection state: online (heartbeats
// fresh), shutting_down (graceful stop announced, inside the grace
// window) or offline (heartbeats stale / never seen).
func (c *Connector) ConnState(now time.Time) string {
	if c.Status != ConnectorStatusActive {
		return ConnStateOffline
	}
	if c.ShuttingDown(now) {
		return ConnStateShuttingDown
	}
	if c.LastSeen != nil && now.Sub(*c.LastSeen) <= OnlineWindow(c.Config) {
		return ConnStateOnline
	}
	return ConnStateOffline
}

// ConnectorEnrollToken is a one-time token pre-bound to a connector
// record; it is created by the UI (create/reconnect) and burned by Enroll.
type ConnectorEnrollToken struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	ConnectorID    string     `json:"connector_id"`
	TokenHash      string     `json:"token_hash"`
	CreatedBy      string     `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	UsedAt         *time.Time `json:"used_at,omitempty"`
	Revoked        bool       `json:"revoked"`
}
