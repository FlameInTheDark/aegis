// Package agents implements endpoint agent enrollment, task management and
// inventory application (spec §16-§20, §136). Enrollment never transmits
// private keys to the control plane; agents keep their keypair locally.
package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service orchestrates agent lifecycle.
type Service struct {
	Repo      *pg.AgentRepo
	Tasks     *pg.AgentTaskRepo
	EnrollTok *pg.EnrollmentRepo
	Events    *pg.AgentEventRepo
	Assets    *pg.AssetRepo
	Log       *slog.Logger
}

// EnrollRequest is the payload of the enrollment handshake.
type EnrollRequest struct {
	Token     string `json:"token"`
	Hostname  string `json:"hostname"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	MachineID string `json:"machine_id"` // stable local machine id
	CSR       string `json:"csr"`        // PEM-encoded CSR (public key only)
}

// EnrollResponse issues the device identity material.
type EnrollResponse struct {
	AgentID        string `json:"agent_id"`
	CertificatePEM string `json:"certificate"`
	OrgID          string `json:"organization_id"`
	SiteID         string `json:"site_id"`
	// Interval hints for the agent loop.
	HeartbeatSecs int `json:"heartbeat_secs"`
}

// Enroll validates a one-time token and issues a device certificate.
// The CSR public key is signed by the platform CA; the private key never
// leaves the endpoint (spec §16).
func (s *Service) Enroll(ctx context.Context, req EnrollRequest, issueCert func(csrPEM, agentID string) (string, error)) (*EnrollResponse, error) {
	if req.Token == "" || req.CSR == "" {
		return nil, fmt.Errorf("token and csr are required")
	}
	hash := TokenHash(req.Token)
	tok, err := s.EnrollTok.ByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment token")
	}
	if tok.Revoked || tok.UsedAt != nil || time.Now().UTC().After(tok.ExpiresAt) {
		return nil, fmt.Errorf("enrollment token is no longer usable")
	}
	// Generate keypair server-side ONLY if the agent could not provide a
	// CSR (rare fallback; documented behavior — the normal path is CSR).
	agentID := ids.New()
	certPEM, err := issueCert(req.CSR, agentID)
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	agent := &domain.Agent{
		ID: agentID, OrganizationID: tok.OrganizationID, SiteID: tok.SiteID,
		Hostname: req.Hostname, Platform: req.Platform, AgentVersion: req.Version,
		Status: "online", EnrolledAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}
	if err := s.Repo.Enroll(ctx, agent); err != nil {
		return nil, err
	}
	if err := s.EnrollTok.MarkUsed(ctx, tok.ID); err != nil {
		s.Log.Warn("token mark-used failed", "err", err)
	}
	_ = s.Events.Insert(ctx, agentID, "enrolled", map[string]any{"platform": req.Platform, "version": req.Version}, time.Now().UTC())
	s.Log.Info("agent enrolled", "agent", agentID, "site", tok.SiteID)
	return &EnrollResponse{
		AgentID: agentID, CertificatePEM: certPEM,
		OrgID: tok.OrganizationID, SiteID: tok.SiteID,
		HeartbeatSecs: 30,
	}, nil
}

// TokenHash derives the storable hash of an enrollment token.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateEnrollmentToken creates a one-time token.
func GenerateEnrollmentToken() (token string, prefix string, err error) {
	raw, err := auth.GenerateToken("aeg_enroll")
	if err != nil {
		return "", "", err
	}
	return raw, raw[:12], nil
}

// IssueTask validates and stores a typed task for an agent (§19: no
// arbitrary shell execution, ever).
func (s *Service) IssueTask(ctx context.Context, orgID, agentID string, typ domain.AgentTaskType, args map[string]any, ttl time.Duration) (*domain.AgentTask, error) {
	if !domain.ValidAgentTaskTypes[typ] {
		return nil, fmt.Errorf("unknown task type %q", typ)
	}
	agent, err := s.Repo.ByID(ctx, orgID, agentID)
	if err != nil {
		return nil, fmt.Errorf("agent not found")
	}
	if agent.Status == "revoked" {
		return nil, fmt.Errorf("agent is revoked")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	t := &domain.AgentTask{
		ID: ids.New(), AgentID: agentID, Type: typ,
		State: "pending", Args: args,
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if err := s.Tasks.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// LinkInventory applies an agent's inventory payload to its asset:
// endpoint data is authoritative over network guesses (spec §15/§17).
func (s *Service) LinkInventory(ctx context.Context, agentID string, inv *domain.SystemInventory, sw []domain.Software, sockets []domain.Socket, posture *domain.SecurityPosture) error {
	agent, err := s.Repo.ByID(ctx, "", agentID)
	if err != nil || agent == nil {
		return fmt.Errorf("agent %s not found", agentID)
	}
	// Ensure the agent is linked to an asset; create one if absent.
	var asset *domain.Asset
	if agent.AssetID != nil {
		asset, err = s.Assets.ByID(ctx, agent.OrganizationID, *agent.AssetID)
	}
	if asset == nil {
		id := ids.New()
		asset = &domain.Asset{
			ID: id, OrganizationID: agent.OrganizationID, SiteID: agent.SiteID,
			Hostname: inv.Hostname, DeviceType: deviceFromPlatform(agent.Platform),
			OSFamily: inv.OSFamily, OSName: inv.OSName, OSVersion: inv.OSVersion,
			KernelVersion: inv.Kernel, Architecture: inv.Arch,
			OSConfidence: 1.0, OSSources: []string{string(domain.SourceAgent)},
			DeviceTypeConf: 1.0, DeviceTypeSrcs: []string{string(domain.SourceAgent)},
			HasAgent: true, Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		if err := s.Assets.Insert(ctx, asset); err != nil {
			return err
		}
		_ = s.Repo.LinkAsset(ctx, agentID, asset.ID)
	} else {
		fields := map[string]any{
			"os_family": inv.OSFamily, "os_name": inv.OSName,
			"os_version": inv.OSVersion, "kernel_version": inv.Kernel,
			"architecture": inv.Arch, "os_confidence": 1.0,
			"has_agent": true, "agent_id": agentID, "last_seen": time.Now().UTC(),
		}
		if inv.Hostname != "" {
			fields["hostname"] = inv.Hostname
		}
		_ = s.Assets.Update(ctx, asset.ID, fields)
	}
	return nil
}

func deviceFromPlatform(platform string) domain.DeviceType {
	switch platform {
	case "windows", "linux", "darwin":
		return domain.DeviceWorkstation
	default:
		return domain.DeviceUnknown
	}
}

// ConstantTimeEqual compares enrollment tokens without timing leaks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewCSRKeyPair is a helper used by the agent binary to create its CSR.
func NewCSRKeyPair(hostnames []string) (csrPEM string, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tpl := &x509.CertificateRequest{
		DNSNames: hostnames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(csr), string(priv), nil
}
