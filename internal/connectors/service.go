// Package connectors implements the unified external-connection service:
// enrollment of externally connected components (endpoint agents, remote
// scanners, external collectors) from one-time connect commands, their
// long-lived credential model, configuration distribution with hot reload,
// and liveness tracking. All kinds share the same connection protocol and
// differ only in the role logic that consumes the distributed config.
package connectors

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// MaxConfigBytes bounds the per-connector role configuration.
const MaxConfigBytes = 64 << 10

// Service orchestrates the connector lifecycle.
type Service struct {
	Connectors *pg.ConnectorRepo
	Tokens     *pg.ConnectorTokenRepo
	// Scanners is optional; when set, connectors of kind=scanner materialize
	// and drive a scanners row (the hub's scan-dispatch identity) from the
	// connector lifecycle: enroll creates it, revoke takes it offline,
	// delete cascades it away (FK).
	Scanners *pg.ScannerRepo
	Log      *slog.Logger
	// PublicAddr is the canonical gRPC endpoint advertised in the enroll
	// response and in UI connect commands (host:port of the gRPC listener
	// as reachable from the component's network).
	PublicAddr string
	// TokenTTL is the validity window of one-time connect tokens.
	TokenTTL time.Duration

	mu       sync.Mutex
	watchers map[string]map[chan ConfigUpdate]struct{}
}

// New builds a connector service.
func New(connectors *pg.ConnectorRepo, tokens *pg.ConnectorTokenRepo, log *slog.Logger, publicAddr string, tokenTTL time.Duration) *Service {
	if tokenTTL <= 0 {
		tokenTTL = 24 * time.Hour
	}
	return &Service{
		Connectors: connectors, Tokens: tokens, Log: log,
		PublicAddr: publicAddr, TokenTTL: tokenTTL,
		watchers: map[string]map[chan ConfigUpdate]struct{}{},
	}
}

// ConfigUpdate is one configuration revision pushed to watchers.
type ConfigUpdate struct {
	Version       int64           `json:"version"`
	Settings      json.RawMessage `json:"settings"`
	HeartbeatSecs int             `json:"heartbeat_secs"`
	Snapshot      bool            `json:"snapshot,omitempty"` // true on initial watch snapshot
}

// IssuedToken is the one-time material of a fresh connect command. The raw
// token is returned exactly once and never stored (hash only server-side).
type IssuedToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Command   string    `json:"connect_command"`
}

// CreateRequest is the UI payload for creating an external connection.
type CreateRequest struct {
	Kind   domain.ConnectorKind `json:"kind"`
	Name   string               `json:"name"`
	SiteID string               `json:"site_id"`
}

// Create registers a new external connection in `pending` state and issues
// its first connect command.
func (s *Service) Create(ctx context.Context, orgID, userID string, req CreateRequest) (*domain.Connector, *IssuedToken, error) {
	if !domain.ValidConnectorKinds[req.Kind] {
		return nil, nil, fmt.Errorf("kind must be one of: agent, scanner, collector")
	}
	if req.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	if len(req.Name) > 128 {
		return nil, nil, fmt.Errorf("name too long")
	}
	c := &domain.Connector{
		ID:             "",
		OrganizationID: orgID,
		SiteID:         req.SiteID,
		Kind:           req.Kind,
		Name:           req.Name,
		Status:         domain.ConnectorStatusPending,
		Config:         json.RawMessage(`{}`),
		ConfigVersion:  1,
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := s.Connectors.Create(ctx, c); err != nil {
		return nil, nil, err
	}
	tok, err := s.issueToken(ctx, c.ID, orgID, userID)
	if err != nil {
		return nil, nil, err
	}
	s.Log.Info("connector created", "connector", c.ID, "kind", string(c.Kind), "org", orgID)
	return c, tok, nil
}

// issueToken mints a one-time enrollment token and renders the connect
// command for it. Previous live tokens are invalidated FIRST so at most
// one outstanding connect command exists per connector.
func (s *Service) issueToken(ctx context.Context, connectorID, orgID, userID string) (*IssuedToken, error) {
	if err := s.Tokens.InvalidateConnector(ctx, connectorID); err != nil {
		return nil, err
	}
	raw, err := auth.GenerateToken("aegis_conn_e")
	if err != nil {
		return nil, fmt.Errorf("token generation failed")
	}
	t := &domain.ConnectorEnrollToken{
		OrganizationID: orgID,
		ConnectorID:    connectorID,
		TokenHash:      TokenHash(raw),
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(s.TokenTTL),
	}
	if err := s.Tokens.Create(ctx, t); err != nil {
		return nil, err
	}
	return &IssuedToken{
		Token:     raw,
		ExpiresAt: t.ExpiresAt,
		Command:   ConnectCommand(s.PublicAddr, raw),
	}, nil
}

// RotateToken (re)arms the connect flow: invalidates outstanding tokens
// and issues a fresh one-time token + connect command. Revoked connectors
// are re-activated and their old credential dropped, which is what makes
// the UI "reconnect" flow work after a network/backend move.
func (s *Service) RotateToken(ctx context.Context, orgID, connectorID, userID string) (*domain.Connector, *IssuedToken, error) {
	c, err := s.Connectors.ByID(ctx, orgID, connectorID)
	if err != nil {
		return nil, nil, err
	}
	if c.Status == domain.ConnectorStatusRevoked {
		if err := s.Connectors.ClearSecret(ctx, orgID, connectorID); err != nil {
			return nil, nil, err
		}
		if err := s.Connectors.Activate(ctx, orgID, connectorID); err != nil {
			return nil, nil, err
		}
		c.Status = domain.ConnectorStatusActive
	}
	tok, err := s.issueToken(ctx, c.ID, orgID, userID)
	if err != nil {
		return nil, nil, err
	}
	s.Log.Info("connector token rotated", "connector", connectorID, "org", orgID)
	return c, tok, nil
}

// EnrollResult is the allow message returned to a component that presented
// a valid one-time token: its identity, the long-lived secret, endpoint
// info and the current configuration snapshot.
type EnrollResult struct {
	Connector     *domain.Connector `json:"connector"`
	Secret        string            `json:"secret"`
	Endpoint      string            `json:"grpc_endpoint"`
	HeartbeatSecs int               `json:"heartbeat_secs"`
	Config        ConfigUpdate      `json:"config"`
}

// EnrollRequest is what the component sends on first contact.
type EnrollRequest struct {
	Token        string   `json:"token"`
	ExpectedKind string   `json:"expected_kind"`
	Hostname     string   `json:"hostname"`
	Platform     string   `json:"platform"`
	Arch         string   `json:"arch"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// Enroll validates the one-time token (burning it atomically so replays
// fail), marks the connector connected and issues its long-lived secret.
// On any failure the component must terminate with the returned error.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResult, error) {
	if req.Token == "" {
		return nil, fmt.Errorf("enrollment token is required")
	}
	// Pre-validate BEFORE burning: a rejected enrollment must not consume
	// the one-time token (the operator would have to rotate for nothing).
	tok, err := s.Tokens.ByHash(ctx, TokenHash(req.Token))
	if err != nil || tok.Revoked || tok.UsedAt != nil || time.Now().UTC().After(tok.ExpiresAt) {
		return nil, fmt.Errorf("enrollment rejected: token is invalid, expired or already used")
	}
	c, err := s.Connectors.ByID(ctx, "", tok.ConnectorID)
	if err != nil {
		return nil, fmt.Errorf("enrollment rejected: connection record missing")
	}
	if c.Status == domain.ConnectorStatusRevoked {
		return nil, fmt.Errorf("enrollment rejected: connection is revoked")
	}
	if req.ExpectedKind != "" && req.ExpectedKind != string(c.Kind) {
		return nil, fmt.Errorf("enrollment rejected: this connect command is for a %q connection, not %q", string(c.Kind), req.ExpectedKind)
	}
	// Atomic claim: only the first concurrent caller with this token wins;
	// replays and races land here with used_at already set.
	if _, err := s.Tokens.Burn(ctx, TokenHash(req.Token)); err != nil {
		return nil, fmt.Errorf("enrollment rejected: token is invalid, expired or already used")
	}
	secret, err := newSecret()
	if err != nil {
		return nil, fmt.Errorf("secret generation failed")
	}
	if err := s.Connectors.Enroll(ctx, c.ID, TokenHash(secret),
		req.Hostname, req.Platform, req.Arch, req.Version,
		mustJSON(req.Capabilities), heartbeatFromConfig(c.Config)); err != nil {
		return nil, err
	}
	c, err = s.Connectors.ByID(ctx, "", c.ID)
	if err != nil {
		return nil, err
	}
	s.materializeScanner(ctx, c)
	s.Log.Info("connector enrolled", "connector", c.ID, "kind", string(c.Kind),
		"hostname", req.Hostname, "platform", req.Platform, "version", req.Version)
	return &EnrollResult{
		Connector:     c,
		Secret:        secret,
		Endpoint:      s.PublicAddr,
		HeartbeatSecs: heartbeatFromConfig(c.Config),
		Config:        configUpdateFor(c),
	}, nil
}

// Authenticate verifies continued-connection credentials (connector id +
// secret) and returns the connector record. Revoked connectors are
// rejected; revoked secrets were replaced at the last enrollment.
func (s *Service) Authenticate(ctx context.Context, connectorID, secret string) (*domain.Connector, error) {
	if connectorID == "" || secret == "" {
		return nil, fmt.Errorf("missing connector credentials")
	}
	hash, status, err := s.Connectors.AuthState(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("unknown connector")
	}
	if status != domain.ConnectorStatusActive {
		return nil, fmt.Errorf("connection is %s", status)
	}
	expected := TokenHash(secret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) != 1 {
		return nil, fmt.Errorf("invalid connector secret")
	}
	return s.Connectors.ByID(ctx, "", connectorID)
}

// Config returns the current configuration snapshot for a connector.
func (s *Service) Config(c *domain.Connector) ConfigUpdate { return configUpdateFor(c) }

// UpdateConfig validates and stores a new role configuration, bumps the
// version and pushes the update to every live watch stream (hot reload).
func (s *Service) UpdateConfig(ctx context.Context, orgID, connectorID string, settings json.RawMessage) (*domain.Connector, ConfigUpdate, error) {
	if err := ValidateSettings(settings); err != nil {
		return nil, ConfigUpdate{}, err
	}
	version, err := s.Connectors.UpdateConfig(ctx, orgID, connectorID, settings)
	if err != nil {
		return nil, ConfigUpdate{}, err
	}
	c, err := s.Connectors.ByID(ctx, orgID, connectorID)
	if err != nil {
		return nil, ConfigUpdate{}, err
	}
	upd := configUpdateFor(c)
	upd.Version = version
	s.broadcast(connectorID, upd)
	// Function toggles may have flipped: sync the linked scanners row so
	// scan dispatch follows the new enablement immediately (offline when
	// the scanner function was disabled, materialized when enabled).
	s.syncScannerRow(ctx, c)
	s.Log.Info("connector config updated", "connector", connectorID, "version", version,
		"functions", Functions(c.Kind, c.Config))
	return c, upd, nil
}

// Touch records a heartbeat (liveness + role status + lifecycle state)
// and returns the server's current config version for drift detection.
//
// state is ""/"running" for normal operation or "shutting_down" for the
// final graceful-stop heartbeat. For scanner-ENABLED connections (kind
// scanner, or any kind with the scanner function toggled on) the heartbeat
// also cascades onto the linked scanners row (healthy + fresh last_seen,
// offline on shutdown) so the scan UI reflects connector liveness within
// one heartbeat instead of waiting for the hub stream's slower path —
// and creates the row on demand for connections that enrolled before the
// materialization logic existed.
func (s *Service) Touch(ctx context.Context, connectorID, version, state string, status json.RawMessage) (int64, error) {
	if len(status) > 16<<10 {
		return 0, fmt.Errorf("status payload too large")
	}
	if state != "" && state != "running" && state != "shutting_down" {
		return 0, fmt.Errorf("state must be running or shutting_down")
	}
	info, err := s.Connectors.TouchSeen(ctx, connectorID, version, state, status)
	if err != nil {
		return 0, err
	}
	if s.Scanners != nil && ScannerEnabled(info.Kind, info.Config) {
		health := "healthy"
		if state == "shutting_down" {
			health = "offline"
		}
		ok, err := s.Scanners.TouchConnector(ctx, connectorID, health)
		if err != nil {
			s.Log.Warn("connector: scanner liveness cascade failed", "connector", connectorID, "err", err)
		} else if !ok {
			// No linked row (pre-materialization enrollment whose backfill
			// insert collided, or a manually removed row): create it now.
			s.materializeScanner(ctx, &domain.Connector{
				ID: connectorID, OrganizationID: info.OrganizationID, SiteID: info.SiteID,
				Kind: info.Kind, Name: info.Name, Status: domain.ConnectorStatusActive,
			})
			if _, err := s.Scanners.TouchConnector(ctx, connectorID, health); err != nil {
				s.Log.Warn("connector: scanner liveness cascade (after ensure) failed", "connector", connectorID, "err", err)
			}
		}
	}
	return info.ConfigVersion, nil
}

// Subscribe registers a live watch stream; it receives the current config
// immediately and every later change until cancel is called.
func (s *Service) Subscribe(connectorID string) (<-chan ConfigUpdate, func()) {
	ch := make(chan ConfigUpdate, 8)
	s.mu.Lock()
	if s.watchers[connectorID] == nil {
		s.watchers[connectorID] = map[chan ConfigUpdate]struct{}{}
	}
	s.watchers[connectorID][ch] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		delete(s.watchers[connectorID], ch)
		if len(s.watchers[connectorID]) == 0 {
			delete(s.watchers, connectorID)
		}
		s.mu.Unlock()
	}
	return ch, cancel
}

func (s *Service) broadcast(connectorID string, upd ConfigUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.watchers[connectorID] {
		select {
		case ch <- upd:
		default:
			// slow watcher: drop; heartbeat drift detection re-syncs it
		}
	}
}

// List/Get/Update/Delete — UI management surface.

func (s *Service) List(ctx context.Context, orgID, kind string) ([]*domain.Connector, error) {
	if kind != "" && !domain.ValidConnectorKinds[domain.ConnectorKind(kind)] {
		return nil, fmt.Errorf("unknown kind filter")
	}
	return s.Connectors.List(ctx, orgID, kind)
}

func (s *Service) Get(ctx context.Context, orgID, id string) (*domain.Connector, error) {
	return s.Connectors.ByID(ctx, orgID, id)
}

func (s *Service) Update(ctx context.Context, orgID, id string, fields map[string]any) (*domain.Connector, error) {
	if name, ok := fields["name"].(string); ok && name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}
	if err := s.Connectors.Update(ctx, orgID, id, fields); err != nil {
		return nil, err
	}
	c, err := s.Connectors.ByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// Scanner rows follow their connector's identity (name/site), so the
	// scan UI and the connections page never disagree.
	s.materializeScanner(ctx, c)
	return c, nil
}

func (s *Service) Revoke(ctx context.Context, orgID, id string) (*domain.Connector, error) {
	if err := s.Connectors.Revoke(ctx, orgID, id); err != nil {
		return nil, err
	}
	c, err := s.Connectors.ByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// A revoked scanner-ENABLED connection must vanish from scan targets
	// even before its credentials stop working (the hub rejects them too).
	if s.Scanners != nil && ScannerEnabled(c.Kind, c.Config) {
		if sc, serr := s.Scanners.ByConnectorID(ctx, c.ID); serr == nil {
			_ = s.Scanners.SetHealth(ctx, sc.ID, "offline")
		}
	}
	s.Log.Info("connector revoked", "connector", id, "org", orgID)
	return c, nil
}

func (s *Service) Delete(ctx context.Context, orgID, id string) error {
	return s.Connectors.Delete(ctx, orgID, id)
}

// ---------------------------------------------------------------------------
// helpers

// materializeScanner keeps the scanners row owned by a scanner-ENABLED
// connection in step with the connection record (created at enrollment,
// renamed/re-sited on update; silently skipped for every other kind or
// when no ScannerRepo is wired). Scanner enablement follows the connection
// settings toggle, not just the kind: an agent-kind connection with
// `scanner.enabled` participates in scan dispatch exactly like a
// scanner-kind one.
func (s *Service) materializeScanner(ctx context.Context, c *domain.Connector) {
	if c == nil || s.Scanners == nil || !ScannerEnabled(c.Kind, c.Config) {
		return
	}
	sc := &domain.Scanner{
		OrganizationID: c.OrganizationID, SiteID: c.SiteID,
		Name: c.Name, Transport: "connector", ConnectorID: c.ID,
	}
	// Preserve the existing row identity when one is already linked (the
	// hub streams update health/last_seen separately).
	if existing, err := s.Scanners.ByConnectorID(ctx, c.ID); err == nil {
		sc.ID = existing.ID
		sc.Health = existing.Health
	} else if c.Status == domain.ConnectorStatusActive {
		sc.Capabilities = []string{"connector"}
	}
	if err := s.Scanners.EnsureForConnector(ctx, sc); err != nil {
		s.Log.Warn("connector: scanner row sync failed", "connector", c.ID, "err", err)
	}
}

// syncScannerRow aligns the linked scanners row with the connection's
// scanner toggle after a settings change: enabling materializes (or
// re-sites) the row, disabling marks it offline so scan dispatch skips
// the connection until the toggle flips back (the next heartbeat with
// the scanner function re-enabled restores it to healthy).
func (s *Service) syncScannerRow(ctx context.Context, c *domain.Connector) {
	if c == nil || s.Scanners == nil {
		return
	}
	if ScannerEnabled(c.Kind, c.Config) {
		s.materializeScanner(ctx, c)
		return
	}
	if sc, err := s.Scanners.ByConnectorID(ctx, c.ID); err == nil {
		_ = s.Scanners.SetHealth(ctx, sc.ID, "offline")
	}
}

// TokenHash derives the storable form of enrollment tokens and secrets
// (SHA-256 hex; raw material is never persisted).
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConnectCommand renders the one-time connect command shown in the UI.
func ConnectCommand(publicAddr, token string) string {
	if publicAddr == "" {
		publicAddr = "<aegis-grpc-host>:9090"
	}
	return fmt.Sprintf("aegis-connector --connect %s/%s", publicAddr, token)
}

// newSecret generates the long-lived connector credential.
func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "aegis_conn_s_" + hex.EncodeToString(raw), nil
}

func heartbeatFromConfig(cfg json.RawMessage) int {
	var hc struct {
		HeartbeatSecs int `json:"heartbeat_secs"`
	}
	if len(cfg) > 0 && json.Unmarshal(cfg, &hc) == nil && hc.HeartbeatSecs >= 10 && hc.HeartbeatSecs <= 3600 {
		return hc.HeartbeatSecs
	}
	return domain.DefaultHeartbeatSecs
}

func configUpdateFor(c *domain.Connector) ConfigUpdate {
	return ConfigUpdate{
		Version:       c.ConfigVersion,
		Settings:      c.Config,
		HeartbeatSecs: heartbeatFromConfig(c.Config),
	}
}

// ValidateSettings enforces the role-configuration contract: a JSON object
// within the size bound; keys, when present, are sane. Known keys are
// validated by name/type so typos surface at save time instead of silently
// doing nothing on the component; unknown keys stay allowed (forward
// compatibility with newer binaries).
//
// Two layouts are valid:
//
//   - sections (v1.25+): {"agent": {...}, "scanner": {...}} with per-function
//     `enabled` toggles and function-scoped keys;
//   - legacy flat: top-level engine/ssh_*/... keys applied to the function
//     matching the connection kind.
func ValidateSettings(settings json.RawMessage) error {
	if len(settings) == 0 {
		return nil
	}
	if len(settings) > MaxConfigBytes {
		return fmt.Errorf("configuration too large (max %d bytes)", MaxConfigBytes)
	}
	var probe map[string]any
	if err := json.Unmarshal(settings, &probe); err != nil {
		return fmt.Errorf("configuration must be a valid JSON object")
	}
	if probe == nil {
		return fmt.Errorf("configuration must be a JSON object")
	}
	if v, ok := probe["heartbeat_secs"]; ok {
		n, ok := v.(float64)
		if !ok || n < 10 || n > 3600 || n != float64(int(n)) {
			return fmt.Errorf("heartbeat_secs must be an integer between 10 and 3600")
		}
	}
	if v, ok := probe["engine"]; ok {
		if err := validEngine(v, ""); err != nil {
			return err
		}
	}
	if err := validateScannerKeys(probe, ""); err != nil {
		return err
	}
	if v, ok := probe["agent"]; ok && v != nil {
		sec, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("agent must be an object")
		}
		if e, ok := sec["enabled"]; ok && e != nil {
			if _, isBool := e.(bool); !isBool {
				return fmt.Errorf("agent.enabled must be a boolean")
			}
		}
		if lv, ok := sec["collection_level"]; ok && lv != nil {
			s, isStr := lv.(string)
			if !isStr {
				return fmt.Errorf("agent.collection_level must be a string")
			}
			switch s {
			case "basic", "standard", "full":
			default:
				return fmt.Errorf("agent.collection_level must be one of: basic, standard, full")
			}
		}
		if err := validateRateMs(sec, "probe_rate_ms", "agent.probe_rate_ms"); err != nil {
			return err
		}
		if err := validateRateMs(sec, "pull_rate_ms", "agent.pull_rate_ms"); err != nil {
			return err
		}
		// A pull faster than the probe can never carry data.
		if p, ok := sec["probe_rate_ms"].(float64); ok {
			if l, ok := sec["pull_rate_ms"].(float64); ok && l < p {
				return fmt.Errorf("agent.pull_rate_ms must not be faster than agent.probe_rate_ms")
			}
		}
	}
	if v, ok := probe["scanner"]; ok && v != nil {
		sec, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("scanner must be an object")
		}
		if e, ok := sec["enabled"]; ok && e != nil {
			if _, isBool := e.(bool); !isBool {
				return fmt.Errorf("scanner.enabled must be a boolean")
			}
		}
		if eng, ok := sec["engine"]; ok {
			if err := validEngine(eng, "scanner."); err != nil {
				return err
			}
		}
		if err := validateScannerKeys(sec, "scanner."); err != nil {
			return err
		}
	}
	return nil
}

// validEngine checks an engine value at the given key prefix ("" for the
// legacy top-level key, "scanner." for the section).
func validEngine(v any, prefix string) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%sengine must be a string", prefix)
	}
	switch s {
	case "auto", "nmap", "simulated":
	default:
		return fmt.Errorf("%sengine must be one of: auto, nmap, simulated", prefix)
	}
	return nil
}

// validateRateMs checks an integer millisecond metrics rate within the
// cadence bounds the endpoint runtime enforces anyway (mirrors
// endpoint.MinRateMs/MaxRateMs: 100ms .. 1h) — a bad value surfaces at
// save time instead of silently clamping on the agent.
func validateRateMs(sec map[string]any, key, label string) error {
	v, ok := sec[key]
	if !ok || v == nil {
		return nil
	}
	n, isNum := v.(float64)
	if !isNum || n != float64(int(n)) {
		return fmt.Errorf("%s must be an integer number of milliseconds", label)
	}
	if n < 100 || n > 3600000 {
		return fmt.Errorf("%s must be between 100 and 3600000 milliseconds", label)
	}
	return nil
}

// validateScannerKeys type-checks the SSH/engine-path keys, shared by the
// legacy flat layout and the scanner section (prefix "" or "scanner.").
func validateScannerKeys(m map[string]any, prefix string) error {
	if v, ok := m["nmap_path"]; ok && v != nil {
		s, ok := v.(string)
		if !ok || len(s) > 512 {
			return fmt.Errorf("%snmap_path must be a string of at most 512 characters", prefix)
		}
	}
	for _, key := range []string{"ssh_user", "ssh_password", "ssh_key_path"} {
		if v, ok := m[key]; ok && v != nil {
			s, ok := v.(string)
			if !ok || len(s) > 512 {
				return fmt.Errorf("%s%s must be a string of at most 512 characters", prefix, key)
			}
		}
	}
	if v, ok := m["ssh_timeout_secs"]; ok {
		n, ok := v.(float64)
		if !ok || n < 1 || n > 3600 || n != float64(int(n)) {
			return fmt.Errorf("%sssh_timeout_secs must be an integer between 1 and 3600", prefix)
		}
	}
	if v, ok := m["ssh_insecure"]; ok && v != nil {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%sssh_insecure must be a boolean", prefix)
		}
	}
	if v, ok := m["ssh_pinned_key"]; ok && v != nil {
		s, ok := v.(string)
		if !ok || len(s) > 8192 {
			return fmt.Errorf("%sssh_pinned_key must be a string of at most 8192 characters", prefix)
		}
	}
	if v, ok := m["ssh_hosts"]; ok && v != nil {
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%sssh_hosts must be an array of strings", prefix)
		}
		if len(arr) > 1024 {
			return fmt.Errorf("%sssh_hosts supports at most 1024 entries", prefix)
		}
		for i, item := range arr {
			if s, ok := item.(string); !ok || len(s) > 512 {
				return fmt.Errorf("%sssh_hosts[%d] must be a string of at most 512 characters", prefix, i)
			}
		}
	}
	return nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`[]`)
	}
	return b
}

// ErrNotFound is re-exported for transport layers mapping errors.
var ErrNotFound = pg.ErrNotFound

// IsNotFound reports whether err is the repository not-found sentinel.
func IsNotFound(err error) bool { return errors.Is(err, pg.ErrNotFound) }
