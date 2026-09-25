// Package agents implements endpoint device management: device binding for
// connections performing the agent function, task management and inventory
// application. Private keys are never transmitted; endpoints keep their
// keypair locally.
package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service orchestrates agent lifecycle.
type Service struct {
	Repo   DeviceStore
	Tasks  *pg.AgentTaskRepo
	Events *pg.AgentEventRepo
	Assets AssetStore
	// Ifaces persists agent-reported NICs (authoritative MAC/name/MTU
	// status data); nil disables interface persistence.
	Ifaces *pg.InterfaceRepo
	// Ident stores and resolves asset identity identifiers (MAC, hostname,
	// addresses, machine id); nil disables both identifier persistence and
	// matching an inventory against existing assets.
	Ident IdentifierStore
	// Sites resolves an organization's default site for connections that
	// carry no site assignment; nil disables the fallback (siteless devices
	// then fail inventory application with an explicit error).
	Sites SiteResolver
	// Merger folds an abandoned duplicate asset into the asset the device
	// adopted and deletes it; *pg.AssetRepo implements it. nil disables
	// the cleanup (the duplicate then stays behind as a husk).
	Merger AssetMerger
	// IPStale bounds how long an address observation keeps resolving to an
	// asset during inventory matching (same semantics as assets.Service).
	IPStale time.Duration
	// Software persists agent-reported packages (endpoint software
	// inventory); nil keeps the legacy behavior of dropping them.
	Software *pg.SoftwareRepo
	// DB enables domain-event emission into the alert outbox (asset
	// discovered, software installed); nil disables emission.
	DB  *pg.DB
	Log *slog.Logger
}

// AssetMerger folds a duplicate asset into the canonical one and removes it;
// *pg.AssetRepo implements it. An interface keeps the service unit-testable.
type AssetMerger interface {
	MergeAssets(ctx context.Context, orphanID, targetID string) error
}

// IdentifierStore is the identity-identifier surface used to match an
// inventory against existing assets and to record the device's identifiers
// on the linked asset; *pg.IdentifierRepo implements it.
type IdentifierStore interface {
	Upsert(ctx context.Context, assetID, typ, value string, weight float64) error
	FindByIdentifier(ctx context.Context, orgID, typ, value string) ([]string, error)
}

// DeviceStore is the persistence surface the device lifecycle needs;
// *pg.AgentRepo implements it. An interface keeps the service unit-testable.
type DeviceStore interface {
	ByID(ctx context.Context, orgID, id string) (*domain.Agent, error)
	ByIDAnyOrg(ctx context.Context, id string) (*domain.Agent, error)
	ByConnector(ctx context.Context, connectorID string) (*domain.Agent, error)
	Enroll(ctx context.Context, a *domain.Agent) error
	UpdateDevice(ctx context.Context, a *domain.Agent) error
	LinkAsset(ctx context.Context, agentID, assetID string) error
	// AgentIDsForAsset lists the devices bound to an asset. Identity
	// adoption skips assets another device already claims — two machines
	// reporting the same address must not fight over one asset.
	AgentIDsForAsset(ctx context.Context, assetID string) ([]string, error)
	TouchSeen(ctx context.Context, id, version string) error
	Revoke(ctx context.Context, orgID, id string) error
	MarkOffline(ctx context.Context, staleBefore time.Time) error
}

// AssetStore is the asset-persistence surface of inventory application;
// *pg.AssetRepo implements it.
type AssetStore interface {
	ByID(ctx context.Context, orgID, id string) (*domain.Asset, error)
	Insert(ctx context.Context, a *domain.Asset) error
	Update(ctx context.Context, orgID, id string, fields map[string]any) error
}

// SiteResolver lists an organization's sites; *pg.SiteRepo implements it.
// A connection created without a site assignment binds its device to the
// org's first site — every device and asset must live in one.
type SiteResolver interface {
	List(ctx context.Context, orgID string) ([]domain.Site, error)
}

// DeviceRequest is the payload of device binding (ConnectorService.BindDevice):
// the endpoint's CSR plus the identity facts of the machine.
type DeviceRequest struct {
	CSR         string `json:"csr"` // PEM-encoded CSR (public key only)
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	PlatformVer string `json:"platform_version"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	MachineID   string `json:"machine_id"` // stable local machine id
}

// DeviceBinding is the result of a successful device bind.
type DeviceBinding struct {
	AgentID        string
	CertificatePEM string
	OrgID          string
	SiteID         string
	HeartbeatSecs  int
}

// EnsureForConnector creates or refreshes the device record bound to a
// connection performing the agent function and issues its certificate from
// the endpoint's CSR.
// The private key never leaves the endpoint; only the public-key CSR is
// seen here. Binding is idempotent: a re-bind refreshes identity fields
// and re-issues the certificate for the new CSR, keeping the same device id.
func (s *Service) EnsureForConnector(ctx context.Context, c *domain.Connector, req DeviceRequest, issueCert func(csrPEM, agentID string) (string, error)) (*DeviceBinding, error) {
	// Binding eligibility follows the agent FUNCTION, not the kind: an
	// agent-kind connection carries the function by default, and any
	// other kind with `agent.enabled` toggled on binds a device the
	// same way (hybrid operation). AgentEnabled encodes both.
	if !connectors.AgentEnabled(c.Kind, c.Config) {
		return nil, fmt.Errorf("device binding requires a connection with the agent function enabled (kind %q has it disabled)", string(c.Kind))
	}
	if req.CSR == "" {
		return nil, fmt.Errorf("csr is required")
	}
	// A connection without a site assignment lands its device on the org's
	// first site: a device (and later its asset) cannot exist without one,
	// and the unassigned default is what single-site deployments expect.
	siteID := c.SiteID
	if siteID == "" && s.Sites != nil {
		if sites, err := s.Sites.List(ctx, c.OrganizationID); err == nil && len(sites) > 0 {
			siteID = sites[0].ID
		}
	}
	existing, err := s.Repo.ByConnector(ctx, c.ID)
	fresh := err != nil // not bound yet
	agent := &domain.Agent{
		ConnectorID:    c.ID,
		OrganizationID: c.OrganizationID,
		SiteID:         siteID,
		Hostname:       req.Hostname,
		Platform:       req.Platform,
		PlatformVer:    req.PlatformVer,
		Arch:           req.Arch,
		AgentVersion:   req.Version,
		Status:         "online",
		EnrolledAt:     time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if !fresh {
		agent.ID = existing.ID
		agent.AssetID = existing.AssetID
		agent.EnrolledAt = existing.EnrolledAt
	}
	certPEM, err := issueCert(req.CSR, agent.ID)
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	if fresh {
		if err := s.Repo.Enroll(ctx, agent); err != nil {
			return nil, err
		}
	} else if err := s.Repo.UpdateDevice(ctx, agent); err != nil {
		return nil, err
	}
	// Best-effort audit trail; the event store is an optional dependency.
	if s.Events != nil {
		_ = s.Events.Insert(ctx, agent.ID, "bound", map[string]any{
			"connector": c.ID, "platform": req.Platform, "version": req.Version,
			"machine_id": req.MachineID,
		}, time.Now().UTC())
	}
	s.Log.Info("device bound to connector", "agent", agent.ID, "connector", c.ID,
		"site", siteID, "platform", req.Platform)
	return &DeviceBinding{
		AgentID:        agent.ID,
		CertificatePEM: certPEM,
		OrgID:          c.OrganizationID,
		SiteID:         siteID, // the defaulted site, not just the connector's assignment
		HeartbeatSecs:  30,
	}, nil
}

// IssueTask validates and stores a typed task for an agent (: no
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

// RevokeForConnector revokes the device bound to a connection. Called when
// the connection is deleted: the record stays for audit (revoked flag,
// certificate metadata) but the device is retired. Unbound connections
// have nothing to revoke and return nil.
func (s *Service) RevokeForConnector(ctx context.Context, connectorID string) error {
	a, err := s.Repo.ByConnector(ctx, connectorID)
	if err != nil {
		return nil
	}
	return s.Repo.Revoke(ctx, a.OrganizationID, a.ID)
}

// LinkInventory applies an agent's inventory payload to its asset:
// endpoint data is authoritative over network guesses. The device is
// resolved by id alone — callers come through the data plane, which
// already authenticated the connector and resolved its bound device; an
// org-scoped lookup here would wrongly reject every device whose
// connector carries a non-empty organization id.
//
// Asset identity resolution mirrors the scan pipeline: when the device is
// not linked yet (or its link points at a deleted asset), the inventory's
// identifiers match an existing asset before a new one is created — a
// machine the scanner already discovered gains its endpoint data instead
// of duplicating as a second asset.
func (s *Service) LinkInventory(ctx context.Context, agentID string, inv *domain.SystemInventory, sw []domain.Software, sockets []domain.Socket, posture *domain.SecurityPosture) error {
	agent, err := s.Repo.ByIDAnyOrg(ctx, agentID)
	if err != nil || agent == nil {
		return fmt.Errorf("agent %s not found", agentID)
	}
	// Siteless devices cannot be reflected as assets: the asset insert
	// would die on an empty uuid with an opaque SQL error. Bind-time
	// defaulting assigns the org's first site; this guard keeps a legacy
	// row (bound before that fix) failing with a readable message.
	if agent.SiteID == "" {
		return fmt.Errorf("bound device has no site; assign a site to its connection")
	}
	// Ensure the agent is linked to an asset: keep the current link unless
	// it is dangling (match or create), and re-evaluate a legacy link whose
	// asset may be a pre-identity duplicate of the machine's original.
	var asset *domain.Asset
	if agent.AssetID != nil {
		asset, err = s.Assets.ByID(ctx, agent.OrganizationID, *agent.AssetID)
	}
	matched := false
	if asset == nil {
		asset = s.matchAsset(ctx, agent, inv)
		matched = asset != nil
	} else if better := s.relinkAsset(ctx, agent, inv, asset); better != nil {
		// The device sat on a duplicate asset; adopt the machine's original.
		_ = s.Repo.LinkAsset(ctx, agentID, better.ID)
		// The abandoned duplicate must not stay behind presenting itself
		// as a second device: fold its inventory into the adopted asset
		// and remove it (best-effort — see mergeDuplicate).
		s.mergeDuplicate(ctx, agent.OrganizationID, asset.ID, better.ID)
		asset = better
		matched = true
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
			HasAgent: true, AgentID: &agentID, Exposure: domain.ExposureInternal, Criticality: domain.CriticalityMedium,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		if err := s.Assets.Insert(ctx, asset); err != nil {
			return err
		}
		_ = s.Repo.LinkAsset(ctx, agentID, asset.ID)
		if s.DB != nil {
			// New device joined via the endpoint path — the device.bound
			// event fires separately from BindDevice.
			_ = alerting.EmitAssetDiscovered(ctx, s.DB, agent.OrganizationID, agent.SiteID, asset.ID, inv.Hostname, "agent", string(asset.DeviceType))
		}
	} else {
		if matched {
			_ = s.Repo.LinkAsset(ctx, agentID, asset.ID)
		}
		fields := map[string]any{
			"os_family": inv.OSFamily, "os_name": inv.OSName,
			"os_version": inv.OSVersion, "kernel_version": inv.Kernel,
			"architecture": inv.Arch, "os_confidence": 1.0,
			"has_agent": true, "agent_id": agentID, "last_seen": time.Now().UTC(),
		}
		if inv.Hostname != "" {
			fields["hostname"] = inv.Hostname
		}
		_ = s.Assets.Update(ctx, agent.OrganizationID, asset.ID, fields)
	}
	// Persist agent-reported NICs: MAC, name, MTU and status are
	// authoritative endpoint data (read from the kernel) and the MAC is
	// the strongest identifier the asset correlation keys on, so
	// agent-covered assets carry their interface rows.
	s.persistInterfaces(ctx, agentID, asset.ID, inv.Interfaces, inv.PrimaryIP)
	// Record the device's identity identifiers on the asset (machine id,
	// serial, MACs, hostname, addresses) so the next scan or inventory
	// converges on the same asset instead of creating a copy.
	s.persistIdentifiers(ctx, asset.ID, inv)
	s.persistSoftware(ctx, agent.OrganizationID, agent.SiteID, asset.ID, sw)
	return nil
}

// persistSoftware applies agent-reported packages to the software
// inventory and emits software.installed for genuinely new rows.
func (s *Service) persistSoftware(ctx context.Context, orgID, siteID, assetID string, sw []domain.Software) {
	if s.Software == nil || len(sw) == 0 {
		return
	}
	for i := range sw {
		pkg := sw[i]
		exists, _, err := s.Software.ExistsForAsset(ctx, assetID, pkg.Name, pkg.Version, pkg.Ecosystem)
		if err != nil {
			s.Log.Warn("software existence check failed", "asset", assetID, "err", err)
		}
		pkg.AssetID = assetID
		pkg.Source = string(domain.SourceAgent)
		pkg.LastSeen = time.Now().UTC()
		if err := s.Software.Upsert(ctx, &pkg); err != nil {
			s.Log.Warn("software upsert failed", "asset", assetID, "name", pkg.Name, "err", err)
			continue
		}
		if !exists && s.DB != nil {
			_ = alerting.EmitSoftwareInstalled(ctx, s.DB, orgID, siteID, assetID, pkg.ID, pkg.Name, pkg.Version, pkg.Ecosystem)
		}
	}
}

// matchAsset resolves an inventory to an existing asset of the device's
// organization, strongest identifier first: machine id and serial (device
// identity), then any reported interface MAC (hardware identity), then
// hostname/FQDN (network identity, ambiguous values match nothing), and
// finally the reported addresses within the device's site — the asset that
// last held the address, mirroring the scan pipeline's address resolution.
func (s *Service) matchAsset(ctx context.Context, agent *domain.Agent, inv *domain.SystemInventory) *domain.Asset {
	if s.Ident == nil {
		return nil
	}
	type idpair struct{ typ, val string }
	var pairs []idpair
	add := func(typ, val string) {
		if val = strings.ToLower(strings.TrimSpace(val)); val != "" {
			pairs = append(pairs, idpair{typ, val})
		}
	}
	add("machine_id", inv.MachineID)
	add("serial", inv.SerialNumber)
	for _, mac := range reportedMACs(inv) {
		add("mac", mac)
	}
	add("hostname", inv.Hostname)
	add("fqdn", inv.FQDN)
	for _, p := range pairs {
		ids, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, p.typ, p.val)
		if err != nil || len(ids) == 0 {
			continue
		}
		// Multiple candidates: ambiguous (same hostname reused) — match
		// nothing and let evidence grow, exactly like the scan pipeline.
		if len(ids) > 1 {
			continue
		}
		a, err := s.Assets.ByID(ctx, agent.OrganizationID, ids[0])
		if err != nil || a == nil || a.OrganizationID != agent.OrganizationID {
			continue
		}
		return a
	}
	// Address fallback within the device's site.
	var best *domain.Asset
	for _, ip := range reportedAddresses(inv) {
		candidates, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "ip", ip)
		if err != nil {
			continue
		}
		for _, id := range candidates {
			a, err := s.Assets.ByID(ctx, agent.OrganizationID, id)
			if err != nil || a == nil || a.OrganizationID != agent.OrganizationID || a.SiteID != agent.SiteID {
				continue
			}
			if s.IPStale > 0 && !a.LastSeen.After(time.Now().UTC().Add(-s.IPStale)) {
				continue
			}
			if best == nil || a.LastSeen.After(best.LastSeen) {
				best = a
			}
		}
	}
	return best
}

// relinkAsset re-evaluates the asset link of an already-bound device.
// Devices bound before the endpoint path persisted identifiers sit on
// duplicate assets, and a machine's original asset — typically created by a
// scan — can carry any mix of identity evidence: a same-subnet scan holds
// the MAC, a remote-subnet nmap scan usually holds nothing but the address
// and maybe a resolved hostname. Adoption is therefore evidence-ranked,
// every rank requiring the candidate to hold one of the device's CURRENTLY
// reported addresses (an address the machine has moved away from never
// yanks a link) and to carry no other device's link:
//
//  1. hardware identity — the candidate shares a reported MAC with the
//     device (organization-scoped, oldest first),
//  2. network identity — the candidate's hostname/FQDN identifier equals a
//     reported name (site-scoped, oldest first),
//  3. address identity — the candidate holds a reported address and is the
//     ONLY such asset in the device's site: the converging evidence for
//     scan-created assets that have no MAC and no resolvable name.
//
// A converged link is left alone — when the linked asset already claims one
// of the reported addresses, device and asset agree and nothing is
// reconsidered. Address-only evidence was previously excluded entirely,
// which left the scan-created duplicate pair unfixable forever.
func (s *Service) relinkAsset(ctx context.Context, agent *domain.Agent, inv *domain.SystemInventory, linked *domain.Asset) *domain.Asset {
	if s.Ident == nil {
		return nil
	}
	addrs := reportedAddresses(inv)
	for _, ip := range addrs {
		ids, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "ip", ip)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if id == linked.ID {
				return nil // converged: the linked asset claims this address
			}
		}
	}
	// Rank 1: hardware identity (MAC) + address overlap.
	if best := s.oldestAddressed(ctx, agent,
		s.assetsByMACs(ctx, agent, linked, reportedMACs(inv)), addrs); best != nil {
		return best
	}
	// Rank 2: network identity (hostname/FQDN) + address overlap.
	if best := s.oldestAddressed(ctx, agent,
		s.assetsByNames(ctx, agent, linked, relinkNames(inv)), addrs); best != nil {
		return best
	}
	// Rank 3: address overlap alone — the weakest evidence, so it adopts
	// only when exactly ONE asset in the device's site holds a reported
	// address. Several claimants mean a moved or shared address: match
	// nothing and let evidence grow.
	return s.singleAddressed(ctx, agent,
		s.assetsByAddresses(ctx, agent, linked, addrs), addrs)
}

// relinkNames lists the inventory's usable network names: lowercased
// hostname and FQDN, deduplicated.
func relinkNames(inv *domain.SystemInventory) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{inv.Hostname, inv.FQDN} {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// assetsByMACs resolves candidate assets through the device's reported MAC
// identifiers, organization-scoped, excluding the linked asset.
func (s *Service) assetsByMACs(ctx context.Context, agent *domain.Agent, linked *domain.Asset, macs []string) []*domain.Asset {
	var out []*domain.Asset
	for _, mac := range macs {
		ids, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "mac", mac)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if id == linked.ID {
				continue
			}
			a, err := s.Assets.ByID(ctx, agent.OrganizationID, id)
			if err != nil || a == nil || a.OrganizationID != agent.OrganizationID {
				continue
			}
			out = append(out, a)
		}
	}
	return out
}

// assetsByNames resolves candidate assets through the device's reported
// hostname/FQDN identifiers. Names are weaker than MACs — clones and image
// deployments reuse them freely — so the candidates are additionally
// site-scoped; the address-overlap requirement in oldestAddressed stays the
// real gate.
func (s *Service) assetsByNames(ctx context.Context, agent *domain.Agent, linked *domain.Asset, names []string) []*domain.Asset {
	var out []*domain.Asset
	seen := map[string]bool{}
	for _, name := range names {
		ids, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "hostname", name)
		if err != nil {
			continue
		}
		fqdns, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "fqdn", name)
		if err == nil {
			ids = append(ids, fqdns...)
		}
		for _, id := range ids {
			if id == linked.ID || seen[id] {
				continue
			}
			a, err := s.Assets.ByID(ctx, agent.OrganizationID, id)
			if err != nil || a == nil || a.OrganizationID != agent.OrganizationID || a.SiteID != agent.SiteID {
				continue
			}
			seen[id] = true
			out = append(out, a)
		}
	}
	return out
}

// assetsByAddresses resolves candidate assets through the device's currently
// reported addresses, organization- and site-scoped, excluding the linked
// asset (the converged case already returned earlier).
func (s *Service) assetsByAddresses(ctx context.Context, agent *domain.Agent, linked *domain.Asset, addrs []string) []*domain.Asset {
	var out []*domain.Asset
	seen := map[string]bool{}
	for _, ip := range addrs {
		ids, err := s.Ident.FindByIdentifier(ctx, agent.OrganizationID, "ip", ip)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if id == linked.ID || seen[id] {
				continue
			}
			a, err := s.Assets.ByID(ctx, agent.OrganizationID, id)
			if err != nil || a == nil || a.OrganizationID != agent.OrganizationID || a.SiteID != agent.SiteID {
				continue
			}
			seen[id] = true
			out = append(out, a)
		}
	}
	return out
}

// oldestAddressed picks the adoption target from the candidates: each must
// hold one of the device's currently reported addresses (ip identifier) and
// must not carry another device's link. Oldest asset wins — the machine's
// original identity is the one every later observation should converge on.
func (s *Service) oldestAddressed(ctx context.Context, agent *domain.Agent, candidates []*domain.Asset, addrs []string) *domain.Asset {
	var best *domain.Asset
	for _, a := range candidates {
		if !assetHoldsAddress(ctx, s.Ident, agent.OrganizationID, a.ID, addrs) {
			continue
		}
		claims, err := s.Repo.AgentIDsForAsset(ctx, a.ID)
		if err != nil {
			continue
		}
		stolen := false
		for _, id := range claims {
			if id != agent.ID {
				stolen = true // another device lives on this asset
				break
			}
		}
		if stolen {
			continue
		}
		if best == nil || a.FirstSeen.Before(best.FirstSeen) ||
			(a.FirstSeen.Equal(best.FirstSeen) && a.ID < best.ID) {
			best = a
		}
	}
	return best
}

// singleAddressed adopts only when exactly one candidate survives the
// oldestAddressed gates. Address-only evidence is deliberately strict: two
// assets claiming the same current address cannot be told apart by address
// data alone, and a wrong adoption is worse than a delayed one.
func (s *Service) singleAddressed(ctx context.Context, agent *domain.Agent, candidates []*domain.Asset, addrs []string) *domain.Asset {
	var only *domain.Asset
	for _, a := range candidates {
		if !assetHoldsAddress(ctx, s.Ident, agent.OrganizationID, a.ID, addrs) {
			continue
		}
		if only != nil {
			return nil // several claimants: ambiguous
		}
		only = a
	}
	if only == nil {
		return nil
	}
	claims, err := s.Repo.AgentIDsForAsset(ctx, only.ID)
	if err != nil {
		return nil
	}
	for _, id := range claims {
		if id != agent.ID {
			return nil // another device lives on this asset
		}
	}
	return only
}

// mergeDuplicate folds the abandoned duplicate asset into the adopted one.
// Best-effort by design: a failed merge never fails the inventory
// application — the device stays on the adopted asset, and the duplicate at
// least loses its endpoint flags so it stops presenting as the live machine.
func (s *Service) mergeDuplicate(ctx context.Context, orgID, orphanID, targetID string) {
	if s.Merger == nil {
		return
	}
	if err := s.Merger.MergeAssets(ctx, orphanID, targetID); err != nil {
		s.Log.Warn("duplicate asset merge failed",
			"orphan", orphanID, "target", targetID, "err", err)
		if s.Assets != nil {
			_ = s.Assets.Update(ctx, orgID, orphanID, map[string]any{"has_agent": false, "agent_id": nil})
		}
		return
	}
	s.Log.Info("duplicate asset merged into the adopted asset",
		"orphan", orphanID, "target", targetID)
}

// assetHoldsAddress reports whether any of the addresses is already
// recorded as an ip identifier of the asset.
func assetHoldsAddress(ctx context.Context, ident IdentifierStore, orgID, assetID string, addrs []string) bool {
	for _, ip := range addrs {
		ids, err := ident.FindByIdentifier(ctx, orgID, "ip", ip)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if id == assetID {
				return true
			}
		}
	}
	return false
}

// persistIdentifiers records the device's identity identifiers on its
// asset: machine id and serial, every interface MAC, hostname/FQDN, and
// every reportable address. The endpoint-reported management address is
// stored at the primary weight so the asset's displayed IP is the address
// the device actually talks on — not whichever NIC enumerated first.
func (s *Service) persistIdentifiers(ctx context.Context, assetID string, inv *domain.SystemInventory) {
	if s.Ident == nil {
		return
	}
	if v := strings.ToLower(strings.TrimSpace(inv.MachineID)); v != "" {
		_ = s.Ident.Upsert(ctx, assetID, "machine_id", v, domain.IdentifierWeights["machine_id"])
	}
	if v := strings.ToLower(strings.TrimSpace(inv.SerialNumber)); v != "" {
		_ = s.Ident.Upsert(ctx, assetID, "serial", v, domain.IdentifierWeights["serial"])
	}
	if v := strings.ToLower(strings.TrimSpace(inv.Hostname)); v != "" {
		_ = s.Ident.Upsert(ctx, assetID, "hostname", v, domain.IdentifierWeights["hostname"])
	}
	if v := strings.ToLower(strings.TrimSpace(inv.FQDN)); v != "" {
		_ = s.Ident.Upsert(ctx, assetID, "fqdn", v, domain.IdentifierWeights["fqdn"])
	}
	for _, ifc := range inv.Interfaces {
		if mac := strings.ToLower(strings.TrimSpace(ifc.MAC)); mac != "" && mac != zeroMAC {
			_ = s.Ident.Upsert(ctx, assetID, "mac", mac, domain.IdentifierWeights["mac"])
		}
	}
	primary := normalizeAddr(inv.PrimaryIP)
	for _, ip := range reportedAddresses(inv) {
		w := domain.IdentifierWeights["ip"]
		if ip == primary {
			w = domain.PrimaryIPWeight
		}
		_ = s.Ident.Upsert(ctx, assetID, "ip", ip, w)
	}
}

// normalizeAddr reduces an interface address to a plain IP literal: the
// prefix length ("/24") and the IPv6 zone ("%eth0") are removed. gopsutil
// reports addresses in CIDR form and connectors shipped before the
// normalization still send it; every strict parse downstream must see a
// bare literal.
func normalizeAddr(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if i := strings.LastIndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	return strings.TrimSpace(addr)
}

// reportedAddresses collects the inventory's usable network addresses:
// normalized to plain literals, with loopback, link-local and unspecified
// addresses removed — those identify nothing beyond the host itself.
func reportedAddresses(inv *domain.SystemInventory) []string {
	var out []string
	seen := map[string]bool{}
	for _, ifc := range inv.Interfaces {
		for _, addr := range ifc.IPs {
			host := normalizeAddr(addr)
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			if !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	return out
}

// reportedMACs lists the inventory's usable interface MACs: lowercased,
// zero-MAC excluded, one entry per address.
func reportedMACs(inv *domain.SystemInventory) []string {
	var out []string
	seen := map[string]bool{}
	for _, ifc := range inv.Interfaces {
		mac := strings.ToLower(strings.TrimSpace(ifc.MAC))
		if mac == "" || mac == zeroMAC || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
	}
	return out
}

const zeroMAC = "00:00:00:00:00:00"

// persistInterfaces upserts agent-reported interfaces and their
// addresses: every parseable address the endpoint sees on a NIC is
// recorded — IPv4 and IPv6, global and link-local — so the interface
// table is a complete view of the host's addressing. Matching is by MAC;
// a NIC reported without a MAC still records its addresses (the interface
// table keys on MAC, so a macless NIC converges on the asset's single
// anonymous row).
//
// Each interface's primary address is chosen deterministically
// (pickIfacePrimary), not by report order: the endpoint's management
// address wins when this interface carries it, else the first global
// IPv4, else the first global IPv6 — the displayed address is the one the
// machine is actually reachable on, never "whatever enumerated first".
func (s *Service) persistInterfaces(ctx context.Context, agentID, assetID string, ifaces []domain.AgentIface, mgmtIP string) {
	if s.Ifaces == nil {
		return
	}
	mgmtIP = normalizeAddr(mgmtIP)
	for _, ifc := range ifaces {
		mac := strings.ToLower(strings.TrimSpace(ifc.MAC))
		ips := make([]string, 0, len(ifc.IPs))
		for _, ip := range ifc.IPs {
			ip = normalizeAddr(ip)
			if ip != "" && net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
		if mac == "" && ifc.Name == "" && len(ips) == 0 {
			continue // nothing identifiable to record
		}
		now := time.Now().UTC()
		nic := &domain.Interface{
			ID: ids.New(), AssetID: assetID, MAC: mac, Name: ifc.Name,
			MTU: ifc.MTU, Status: ifc.Status, FirstSeen: now, LastSeen: now,
		}
		if mac != "" {
			if list, err := s.Ifaces.ListForAsset(ctx, assetID); err == nil {
				for i := range list {
					if list[i].MAC == mac {
						nic.ID = list[i].ID // reuse: keeps first_seen and bound ip rows
						nic.FirstSeen = list[i].FirstSeen
						if nic.Name == "" {
							nic.Name = list[i].Name
						}
						break
					}
				}
			}
		}
		if err := s.Ifaces.Upsert(ctx, nic); err != nil {
			s.Log.Warn("agent interface upsert failed", "agent", agentID, "mac", mac, "err", err)
			continue
		}
		for _, ip := range ips {
			_ = s.Ifaces.AddIP(ctx, nic.ID, ip, false)
		}
		// Primary is recomputed on every report: the flag column only
		// reflects the selection below, and earlier reports (or connectors
		// that flagged by position) converge to exactly one primary.
		_ = s.Ifaces.SetPrimaryIP(ctx, nic.ID, pickIfacePrimary(ips, mgmtIP))
	}
}

// pickIfacePrimary selects the address a NIC is presented by: the device's
// management address when this interface carries it, else the first global
// (routable) IPv4, else the first global IPv6, else the first remaining
// address — link-local entries are still shown when they are all the
// interface has. Deterministic regardless of the OS's enumeration order,
// which on Windows frequently reports IPv6 (often link-local) before IPv4.
func pickIfacePrimary(ips []string, mgmtIP string) string {
	if mgmtIP != "" {
		for _, ip := range ips {
			if ip == mgmtIP {
				return ip
			}
		}
	}
	isGlobal := func(ip string) bool {
		p := net.ParseIP(ip)
		return p != nil && !p.IsLoopback() && !p.IsUnspecified() && !p.IsLinkLocalUnicast()
	}
	for _, ip := range ips { // IPv4 first: the management-facing family in most deployments
		if p := net.ParseIP(ip); p != nil && p.To4() != nil && isGlobal(ip) {
			return ip
		}
	}
	for _, ip := range ips {
		if isGlobal(ip) {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

func deviceFromPlatform(platform string) domain.DeviceType {
	switch platform {
	case "windows", "linux", "darwin":
		return domain.DeviceWorkstation
	default:
		return domain.DeviceUnknown
	}
}

// NewCSRKeyPair is a helper for tests and tooling that need a throwaway
// endpoint keypair/CSR.
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
