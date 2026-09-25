package agents

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Binding eligibility follows the agent FUNCTION, not the kind: agent-kind
// connections carry the function by default, and any kind with
// `agent.enabled` toggled on binds a device the same way (hybrid operation).
// The service is constructed without repositories — every case below must
// be decided by the function gate (or the CSR check behind it) before any
// persistence is touched.

func TestEnsureForConnectorRequiresAgentFunction(t *testing.T) {
	s := &Service{}
	c := &domain.Connector{ID: "c1", Kind: domain.ConnectorScanner}
	_, err := s.EnsureForConnector(context.Background(), c, DeviceRequest{CSR: "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "agent function enabled") || !strings.Contains(err.Error(), `"scanner"`) {
		t.Fatalf("scanner-kind connection without the toggle must be rejected by the function gate, got %v", err)
	}
}

func TestEnsureForConnectorAllowsAgentEnabledScannerKind(t *testing.T) {
	s := &Service{}
	c := &domain.Connector{
		ID:   "c1",
		Kind: domain.ConnectorScanner,
		// An empty CSR is rejected by the NEXT guard behind the function
		// gate — reaching "csr is required" proves the gate opened for a
		// scanner-kind connection with the agent function enabled.
		Config: json.RawMessage(`{"agent":{"enabled":true}}`),
	}
	_, err := s.EnsureForConnector(context.Background(), c, DeviceRequest{}, nil)
	if err == nil || !strings.Contains(err.Error(), "csr is required") {
		t.Fatalf("agent-enabled scanner-kind connection must pass the function gate (next guard: csr), got %v", err)
	}
}

func TestEnsureForConnectorAllowsAgentKindDefault(t *testing.T) {
	s := &Service{}
	c := &domain.Connector{ID: "c1", Kind: domain.ConnectorAgent}
	_, err := s.EnsureForConnector(context.Background(), c, DeviceRequest{}, nil)
	if err == nil || !strings.Contains(err.Error(), "csr is required") {
		t.Fatalf("agent-kind connection must pass the function gate by default (next guard: csr), got %v", err)
	}
}

func TestEnsureForConnectorRejectsAgentDisabledAgentKind(t *testing.T) {
	s := &Service{}
	c := &domain.Connector{
		ID:     "c1",
		Kind:   domain.ConnectorAgent,
		Config: json.RawMessage(`{"agent":{"enabled":false},"scanner":{"enabled":true}}`),
	}
	_, err := s.EnsureForConnector(context.Background(), c, DeviceRequest{CSR: "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "agent function enabled") || !strings.Contains(err.Error(), `"agent"`) {
		t.Fatalf("agent-kind connection with the agent function disabled must be rejected, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// LinkInventory: device lookup + asset application (fakes, no database).

type fakeDeviceStore struct {
	device      *domain.Agent
	err         error
	linkedAsset string
	// agentsByAsset routes AgentIDsForAsset: asset id -> device ids
	// (used to model an asset another device already claims).
	agentsByAsset map[string][]string
}

func (f *fakeDeviceStore) ByIDAnyOrg(context.Context, string) (*domain.Agent, error) {
	return f.device, f.err
}
func (f *fakeDeviceStore) ByConnector(context.Context, string) (*domain.Agent, error) {
	return f.device, f.err
}
func (f *fakeDeviceStore) Enroll(context.Context, *domain.Agent) error { return nil }
func (f *fakeDeviceStore) UpdateDevice(context.Context, *domain.Agent) error {
	return nil
}
func (f *fakeDeviceStore) LinkAsset(_ context.Context, _, assetID string) error {
	f.linkedAsset = assetID
	return nil
}

func (f *fakeDeviceStore) AgentIDsForAsset(_ context.Context, assetID string) ([]string, error) {
	return f.agentsByAsset[assetID], nil
}
func (f *fakeDeviceStore) TouchSeen(context.Context, string, string) error { return nil }
func (f *fakeDeviceStore) Revoke(context.Context, string, string) error    { return nil }
func (f *fakeDeviceStore) MarkOffline(context.Context, time.Time) error    { return nil }

type fakeAssetStore struct {
	asset    *domain.Asset
	byIDErr  error
	inserted *domain.Asset
	updates  []map[string]any
	// byID routes ByID calls by asset id; nil keeps the single-asset
	// behavior the legacy tests rely on.
	byID map[string]*domain.Asset
}

func (f *fakeAssetStore) ByID(_ context.Context, _, id string) (*domain.Asset, error) {
	if f.byIDErr != nil {
		return nil, f.byIDErr
	}
	if f.byID != nil {
		return f.byID[id], nil
	}
	return f.asset, nil
}
func (f *fakeAssetStore) Insert(_ context.Context, a *domain.Asset) error {
	f.inserted = a
	return nil
}
func (f *fakeAssetStore) Update(_ context.Context, _ string, _ string, fields map[string]any) error {
	f.updates = append(f.updates, fields)
	return nil
}

// Regression: inventory submission used to resolve the device with an
// org-scoped lookup called with an EMPTY org, so every bound device whose
// connector carried a real organization id failed with "agent not found"
// and the endpoint collected nothing. The data plane has already
// authenticated the connector and resolved its bound device, so the
// service must look the device up by id alone.
func TestLinkInventoryAppliesToDeviceWithOrganization(t *testing.T) {
	agentID := "01a0cfef-879b-7b09-ad4b-d823e7b8aca2"
	devices := &fakeDeviceStore{device: &domain.Agent{
		ID: agentID, OrganizationID: "org-1", SiteID: "site-1", Platform: "windows",
	}}
	assets := &fakeAssetStore{}
	s := &Service{Repo: devices, Assets: assets}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname: "vikto-pc", OSFamily: "windows", OSName: "Windows 11",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory for a device whose connector has an organization must be applied, got %v", err)
	}
	if assets.inserted == nil {
		t.Fatal("expected a new asset to be created for the unlinked device")
	}
	if assets.inserted.Hostname != "vikto-pc" || assets.inserted.OrganizationID != "org-1" {
		t.Fatalf("asset identity fields not applied: %+v", assets.inserted)
	}
	if assets.inserted.AgentID == nil || *assets.inserted.AgentID != agentID {
		t.Fatalf("new asset must carry the agent_id link, got %+v", assets.inserted.AgentID)
	}
	if devices.linkedAsset == "" {
		t.Fatal("device must be linked to the created asset")
	}
	if !assets.inserted.HasAgent {
		t.Fatal("agent-created asset must be flagged has_agent")
	}
}

func TestLinkInventoryUpdatesExistingAsset(t *testing.T) {
	agentID := "device-2"
	assetID := "asset-2"
	devices := &fakeDeviceStore{device: &domain.Agent{
		ID: agentID, OrganizationID: "org-1", SiteID: "site-1",
		AssetID: &assetID, Platform: "linux",
	}}
	assets := &fakeAssetStore{asset: &domain.Asset{ID: assetID, Hostname: "old"}}
	s := &Service{Repo: devices, Assets: assets}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname: "new-host", OSFamily: "ubuntu",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory for an already-linked device must update in place, got %v", err)
	}
	if assets.inserted != nil {
		t.Fatal("existing asset must not be re-created")
	}
	if len(assets.updates) != 1 {
		t.Fatalf("expected exactly one asset update, got %d", len(assets.updates))
	}
	fields := assets.updates[0]
	if fields["hostname"] != "new-host" || fields["has_agent"] != true || fields["agent_id"] != agentID {
		t.Fatalf("update fields missing endpoint identity: %+v", fields)
	}
}

func TestLinkInventoryUnknownDeviceStillRejected(t *testing.T) {
	s := &Service{Repo: &fakeDeviceStore{err: errors.New("no rows")}, Assets: &fakeAssetStore{}}
	err := s.LinkInventory(context.Background(), "ghost", &domain.SystemInventory{Hostname: "x"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown device must still be rejected, got %v", err)
	}
}

func (f *fakeDeviceStore) ByID(context.Context, string, string) (*domain.Agent, error) {
	return f.device, f.err
}

// ---------------------------------------------------------------------------
// Asset identity resolution: matching an inventory against existing assets
// and identifier persistence (fakes, no database).

type fakeIdent struct {
	// index keyed "type|value" -> asset ids
	index  map[string][]string
	upsert []struct {
		assetID, typ, val string
		weight            float64
	}
}

func newFakeIdent() *fakeIdent { return &fakeIdent{index: map[string][]string{}} }

func (f *fakeIdent) seed(assetID, typ, val string) {
	f.index[typ+"|"+val] = append(f.index[typ+"|"+val], assetID)
}
func (f *fakeIdent) Upsert(_ context.Context, assetID, typ, val string, weight float64) error {
	f.upsert = append(f.upsert, struct {
		assetID, typ, val string
		weight            float64
	}{assetID, typ, val, weight})
	return nil
}
func (f *fakeIdent) FindByIdentifier(_ context.Context, orgID, typ, val string) ([]string, error) {
	if orgID == "" {
		return nil, nil
	}
	return f.index[typ+"|"+val], nil
}

// An unlinked device whose MAC is already known (the scanner discovered the
// machine earlier) must adopt the existing asset instead of duplicating it.
func TestLinkInventoryMatchesExistingAssetByMAC(t *testing.T) {
	agentID := "device-mac"
	existing := &domain.Asset{ID: "asset-existing", OrganizationID: "org-1", SiteID: "site-1", Hostname: "vikto-pc"}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", Platform: "windows"}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-existing": existing}}
	ident := newFakeIdent()
	ident.seed("asset-existing", "mac", "aa:bb:cc:dd:ee:ff")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname: "vikto-pc",
		Interfaces: []domain.AgentIface{
			{Name: "Ethernet", MAC: "AA:BB:CC:DD:EE:FF", IPs: []string{"192.168.1.20"}},
		},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if assets.inserted != nil {
		t.Fatal("a machine the scanner already discovered must not be duplicated as a new asset")
	}
	if devices.linkedAsset != "asset-existing" {
		t.Fatalf("device must be linked to the matched asset, got %q", devices.linkedAsset)
	}
	// The matched asset gains the endpoint identity fields.
	found := false
	for _, u := range assets.updates {
		if u["agent_id"] == agentID && u["has_agent"] == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("matched asset must be updated with the agent link: %+v", assets.updates)
	}
}

// With no strong identifier in common, a reported address that an existing
// same-site asset last held resolves the inventory to that asset.
func TestLinkInventoryMatchesExistingAssetByAddress(t *testing.T) {
	agentID := "device-ip"
	existing := &domain.Asset{ID: "asset-byip", OrganizationID: "org-1", SiteID: "site-1", LastSeen: time.Now().UTC()}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1"}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-byip": existing}}
	ident := newFakeIdent()
	ident.seed("asset-byip", "ip", "192.168.1.20")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "vikto-pc",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"127.0.0.1", "169.254.9.9", "192.168.1.20", "fe80::1%eth0"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "asset-byip" {
		t.Fatalf("device must adopt the asset that last held its address, got %q", devices.linkedAsset)
	}
	// The recorded addresses exclude loopback, link-local and zone suffixes.
	ips := map[string]float64{}
	for _, u := range ident.upsert {
		if u.typ == "ip" && u.assetID == "asset-byip" {
			ips[u.val] = u.weight
		}
	}
	if _, ok := ips["192.168.1.20"]; !ok {
		t.Fatalf("usable address must be recorded, got %v", ips)
	}
	for _, bad := range []string{"127.0.0.1", "169.254.9.9", "fe80::1"} {
		if _, ok := ips[bad]; ok {
			t.Errorf("address %q must not be recorded as an identifier", bad)
		}
	}
}

// Two assets sharing a hostname make the hostname ambiguous; matching must
// fall through it (and through to the address) rather than guess.
func TestLinkInventoryAmbiguousHostnameDoesNotMatch(t *testing.T) {
	agentID := "device-amb"
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1"}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{}}
	ident := newFakeIdent()
	ident.seed("asset-a", "hostname", "pc")
	ident.seed("asset-b", "hostname", "pc")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "pc",
		Interfaces: []domain.AgentIface{{Name: "eth0", MAC: "aa:bb:cc:00:00:01", IPs: []string{"10.0.0.99"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if assets.inserted == nil {
		t.Fatal("ambiguous identity must create a new asset, not pick a winner")
	}
}

// An asset of a different organization must never be matched, whatever it
// shares with the device.
func TestLinkInventoryNeverMatchesAcrossOrganizations(t *testing.T) {
	agentID := "device-org"
	existing := &domain.Asset{ID: "asset-other-org", OrganizationID: "org-2", SiteID: "site-1"}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1"}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-other-org": existing}}
	ident := newFakeIdent()
	ident.seed("asset-other-org", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-other-org", "ip", "192.168.1.20")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "vikto-pc",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.20"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if assets.inserted == nil || devices.linkedAsset == "asset-other-org" {
		t.Fatal("another organization's asset must never be adopted")
	}
}

// A device whose linked asset was deleted (dangling link) re-resolves its
// asset from the inventory instead of erroring or re-creating blindly.
func TestLinkInventoryDanglingLinkRematches(t *testing.T) {
	agentID := "device-dangling"
	gone := "asset-deleted"
	existing := &domain.Asset{ID: "asset-live", OrganizationID: "org-1", SiteID: "site-1", LastSeen: time.Now().UTC()}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &gone}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-live": existing}}
	ident := newFakeIdent()
	ident.seed("asset-live", "ip", "192.168.1.20")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "vikto-pc",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.20"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply over a dangling link, got %v", err)
	}
	if devices.linkedAsset != "asset-live" {
		t.Fatalf("device must re-link to the matched asset, got %q", devices.linkedAsset)
	}
}

// The endpoint-reported management address is stored at the primary weight
// so it outranks the device's other addresses on the asset.
func TestLinkInventoryPrimaryAddressOutranksOthers(t *testing.T) {
	agentID := "device-primary"
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1"}}
	assets := &fakeAssetStore{}
	ident := newFakeIdent()
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "vikto-pc",
		MachineID:  "machine-1",
		PrimaryIP:  "192.168.1.20",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.20", "10.8.0.2"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	weights := map[string]float64{}
	for _, u := range ident.upsert {
		switch u.typ {
		case "ip":
			weights[u.val] = u.weight
		case "machine_id":
			if u.weight != domain.IdentifierWeights["machine_id"] {
				t.Errorf("machine_id weight = %v", u.weight)
			}
		case "mac":
			if u.weight != domain.IdentifierWeights["mac"] {
				t.Errorf("mac weight = %v", u.weight)
			}
		}
	}
	if weights["192.168.1.20"] != domain.PrimaryIPWeight {
		t.Errorf("management address weight = %v, want %v", weights["192.168.1.20"], domain.PrimaryIPWeight)
	}
	if weights["10.8.0.2"] != domain.IdentifierWeights["ip"] {
		t.Errorf("secondary address weight = %v, want %v", weights["10.8.0.2"], domain.IdentifierWeights["ip"])
	}
}

// ---------------------------------------------------------------------------
// Re-linking already-bound devices: a device bound before the endpoint path
// persisted identifiers sits on a duplicate asset (hostname shown as the
// address, no correlation data). When the machine's original asset —
// created by a scan, holding the device's MAC and management address —
// exists, the device must adopt it instead of staying on the duplicate.

func TestLinkInventoryRelinksLegacyDuplicateToOriginalAsset(t *testing.T) {
	agentID := "device-dup"
	now := time.Now().UTC()
	dup := &domain.Asset{ID: "asset-dup", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-24 * time.Hour)}
	original := &domain.Asset{ID: "asset-original", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-14 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &dup.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-dup": dup, "asset-original": original}}
	ident := newFakeIdent()
	// The duplicate carries the hardware identity the v1.26.2 endpoint path
	// wrote (MAC, hostname) but no usable address; the original scan asset
	// holds the machine's MAC and its address.
	ident.seed("asset-dup", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-original", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-original", "ip", "192.168.1.80")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	// Interfaces arrive in gopsutil's CIDR form: pre-normalization
	// connectors report raw system addresses and the hub must still
	// correlate them.
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "AA:BB:CC:DD:EE:FF", IPs: []string{"192.168.1.80/24", "fe80::1%12"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "asset-original" {
		t.Fatalf("device must be re-linked to the machine's original asset, got %q", devices.linkedAsset)
	}
	if assets.inserted != nil {
		t.Fatal("re-linking must not create another asset")
	}
	// The device's identity lands on the adopted asset.
	foundIP := false
	for _, u := range ident.upsert {
		if u.assetID == "asset-original" && u.typ == "ip" && u.val == "192.168.1.80" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("adopted asset must receive the device's address identifier: %+v", ident.upsert)
	}
}

// A converged link — the linked asset already claims one of the reported
// addresses — must never be re-evaluated.
func TestLinkInventoryKeepsConvergedLink(t *testing.T) {
	agentID := "device-converged"
	now := time.Now().UTC()
	linked := &domain.Asset{ID: "asset-original", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-14 * 24 * time.Hour)}
	older := &domain.Asset{ID: "asset-older", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-30 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &linked.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-original": linked, "asset-older": older}}
	ident := newFakeIdent()
	ident.seed("asset-original", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-original", "ip", "192.168.1.80")
	ident.seed("asset-older", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-older", "ip", "192.168.1.80")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "" {
		t.Fatalf("converged link must not be re-linked (re-link call recorded: %q)", devices.linkedAsset)
	}
	if assets.inserted != nil {
		t.Fatal("converged link must not create assets")
	}
}

// Shared MAC alone is not enough: an older asset that does not hold one of
// the device's current addresses stays untouched (a duplicate husk must
// not win over the properly linked asset).
func TestLinkInventoryDoesNotRelinkOnMACAlone(t *testing.T) {
	agentID := "device-macalone"
	now := time.Now().UTC()
	linked := &domain.Asset{ID: "asset-linked", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-7 * 24 * time.Hour)}
	older := &domain.Asset{ID: "asset-mac-only", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-30 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &linked.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-linked": linked, "asset-mac-only": older}}
	ident := newFakeIdent()
	ident.seed("asset-linked", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-mac-only", "mac", "aa:bb:cc:dd:ee:ff")
	s := &Service{Repo: devices, Assets: assets, Ident: ident}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "" {
		t.Fatalf("MAC-only overlap must not re-link (re-link call recorded: %q)", devices.linkedAsset)
	}
}

// ---------------------------------------------------------------------------
// Address-evidence re-linking and duplicate cleanup: a machine's original
// asset created by a remote-subnet nmap scan carries no MAC (ARP resolves
// only on the scanner's own link) and often no resolvable name — nothing
// but the address. The device must still adopt it, and the abandoned
// duplicate must be folded into the original and removed instead of
// presenting itself as a second device.

type fakeMerger struct {
	calls []struct{ orphan, target string }
	err   error
}

func (f *fakeMerger) MergeAssets(_ context.Context, orphanID, targetID string) error {
	f.calls = append(f.calls, struct{ orphan, target string }{orphanID, targetID})
	return f.err
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The reported scenario: the machine's asset was created by a scan (holds
// the address, no MAC, no name) and the device sits on its own agent-created
// duplicate. The device must adopt the scan asset by address evidence and
// the duplicate must be merged away.
func TestLinkInventoryRelinksScanAssetByAddress(t *testing.T) {
	agentID := "device-scan-dup"
	now := time.Now().UTC()
	dup := &domain.Asset{ID: "asset-dup", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-1 * time.Hour)}
	original := &domain.Asset{ID: "asset-original", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-7 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &dup.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-dup": dup, "asset-original": original}}
	ident := newFakeIdent()
	// The duplicate (agent-created) holds the device's MAC and name but no
	// usable address; the scan asset holds nothing but the address.
	ident.seed("asset-dup", "mac", "aa:bb:cc:dd:ee:ff")
	ident.seed("asset-dup", "hostname", "desktop-rufjn45")
	ident.seed("asset-original", "ip", "192.168.1.80")
	merger := &fakeMerger{}
	s := &Service{Repo: devices, Assets: assets, Ident: ident, Merger: merger, Log: quietLog()}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "DESKTOP-RUFJN45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80/24"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "asset-original" {
		t.Fatalf("device must adopt the scan-created asset by address evidence, got %q", devices.linkedAsset)
	}
	if len(merger.calls) != 1 || merger.calls[0].orphan != "asset-dup" || merger.calls[0].target != "asset-original" {
		t.Fatalf("the abandoned duplicate must be merged into the adopted asset, calls: %+v", merger.calls)
	}
	// The device's identity lands on the adopted asset.
	foundIP := false
	for _, u := range ident.upsert {
		if u.assetID == "asset-original" && u.typ == "ip" && u.val == "192.168.1.80" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("adopted asset must receive the device's address identifier: %+v", ident.upsert)
	}
}

// A scan asset that resolved the machine's hostname (PTR) converges through
// the hostname rank even before the address rank is considered.
func TestLinkInventoryRelinksScanAssetByHostnameAndAddress(t *testing.T) {
	agentID := "device-name-dup"
	now := time.Now().UTC()
	dup := &domain.Asset{ID: "asset-dup", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-2 * time.Hour)}
	original := &domain.Asset{ID: "asset-original", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-9 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &dup.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-dup": dup, "asset-original": original}}
	ident := newFakeIdent()
	ident.seed("asset-original", "hostname", "desktop-rufjn45")
	ident.seed("asset-original", "ip", "192.168.1.80")
	merger := &fakeMerger{}
	s := &Service{Repo: devices, Assets: assets, Ident: ident, Merger: merger, Log: quietLog()}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "DESKTOP-RUFJN45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "asset-original" {
		t.Fatalf("device must adopt the asset that carries its name and address, got %q", devices.linkedAsset)
	}
	if len(merger.calls) != 1 || merger.calls[0].orphan != "asset-dup" {
		t.Fatalf("the duplicate must be merged away, calls: %+v", merger.calls)
	}
}

// Two different assets hold the device's reported addresses: ambiguous —
// address evidence alone matches nothing.
func TestLinkInventoryAmbiguousAddressMatchesNothing(t *testing.T) {
	agentID := "device-ambiguous"
	now := time.Now().UTC()
	linked := &domain.Asset{ID: "asset-linked", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-1 * time.Hour)}
	first := &domain.Asset{ID: "asset-a", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-10 * 24 * time.Hour)}
	second := &domain.Asset{ID: "asset-b", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-20 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &linked.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-linked": linked, "asset-a": first, "asset-b": second}}
	ident := newFakeIdent()
	ident.seed("asset-a", "ip", "192.168.1.80")
	ident.seed("asset-b", "ip", "192.168.1.80")
	merger := &fakeMerger{}
	s := &Service{Repo: devices, Assets: assets, Ident: ident, Merger: merger, Log: quietLog()}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "" {
		t.Fatalf("ambiguous address evidence must not re-link (re-linked to %q)", devices.linkedAsset)
	}
	if len(merger.calls) != 0 {
		t.Fatalf("nothing may be merged without an adoption, calls: %+v", merger.calls)
	}
}

// An asset already claimed by another device is never stolen, regardless of
// the address overlap.
func TestLinkInventoryDoesNotStealAnotherDevicesAsset(t *testing.T) {
	agentID := "device-thief"
	now := time.Now().UTC()
	linked := &domain.Asset{ID: "asset-linked", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-1 * time.Hour)}
	claimed := &domain.Asset{ID: "asset-claimed", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-10 * 24 * time.Hour)}
	devices := &fakeDeviceStore{
		device:        &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &linked.ID},
		agentsByAsset: map[string][]string{"asset-claimed": {"device-other"}},
	}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-linked": linked, "asset-claimed": claimed}}
	ident := newFakeIdent()
	ident.seed("asset-claimed", "ip", "192.168.1.80")
	merger := &fakeMerger{}
	s := &Service{Repo: devices, Assets: assets, Ident: ident, Merger: merger, Log: quietLog()}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("inventory must apply, got %v", err)
	}
	if devices.linkedAsset != "" {
		t.Fatalf("an asset another device claims must not be adopted (re-linked to %q)", devices.linkedAsset)
	}
	if len(merger.calls) != 0 {
		t.Fatalf("nothing may be merged without an adoption, calls: %+v", merger.calls)
	}
}

// A failed merge never fails the inventory application: the device stays on
// the adopted asset and the duplicate at least loses its endpoint flags.
func TestLinkInventoryMergeFailureKeepsAdoptedLink(t *testing.T) {
	agentID := "device-merge-fail"
	now := time.Now().UTC()
	dup := &domain.Asset{ID: "asset-dup", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-1 * time.Hour)}
	original := &domain.Asset{ID: "asset-original", OrganizationID: "org-1", SiteID: "site-1", FirstSeen: now.Add(-7 * 24 * time.Hour)}
	devices := &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", SiteID: "site-1", AssetID: &dup.ID}}
	assets := &fakeAssetStore{byID: map[string]*domain.Asset{"asset-dup": dup, "asset-original": original}}
	ident := newFakeIdent()
	ident.seed("asset-original", "ip", "192.168.1.80")
	merger := &fakeMerger{err: errors.New("db down")}
	s := &Service{Repo: devices, Assets: assets, Ident: ident, Merger: merger, Log: quietLog()}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{
		Hostname:   "desktop-rufjn45",
		Interfaces: []domain.AgentIface{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"192.168.1.80"}}},
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("a failed merge must not fail the inventory application, got %v", err)
	}
	if devices.linkedAsset != "asset-original" {
		t.Fatalf("device must stay on the adopted asset, got %q", devices.linkedAsset)
	}
	// The fallback clears the endpoint flags on the orphan.
	cleared := false
	for _, u := range assets.updates {
		if hasAgent, ok := u["has_agent"]; ok && hasAgent == false {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("merge failure must clear the duplicate's endpoint flags, updates: %+v", assets.updates)
	}
}

// ---------------------------------------------------------------------------
// pickIfacePrimary: the interface's displayed address is chosen by
// reachability, never by the OS's enumeration order.

func TestPickIfacePrimaryPrefersManagementAddress(t *testing.T) {
	ips := []string{"fe80::1", "2a02:6b8:c0e::1", "192.168.1.80", "10.0.0.9"}
	if got := pickIfacePrimary(ips, "10.0.0.9"); got != "10.0.0.9" {
		t.Fatalf("management address must win when the interface carries it, got %q", got)
	}
}

func TestPickIfacePrimaryPrefersGlobalIPv4OverIPv6(t *testing.T) {
	// Windows enumerates IPv6 (link-local first) before IPv4 on most NICs;
	// the bug report showed a NIC displaying fe80::… instead of its IPv4.
	ips := []string{"fe80::1", "2a02:6b8:c0e::1", "192.168.1.80"}
	if got := pickIfacePrimary(ips, ""); got != "192.168.1.80" {
		t.Fatalf("global IPv4 must be preferred over global/link-local IPv6, got %q", got)
	}
	if got := pickIfacePrimary([]string{"192.168.1.80", "fe80::1"}, ""); got != "192.168.1.80" {
		t.Fatalf("selection must not depend on address order, got %q", got)
	}
}

func TestPickIfacePrimaryFallsBackToGlobalIPv6(t *testing.T) {
	ips := []string{"fe80::1", "2a02:6b8:c0e::1"}
	if got := pickIfacePrimary(ips, ""); got != "2a02:6b8:c0e::1" {
		t.Fatalf("global IPv6 must beat link-local, got %q", got)
	}
}

func TestPickIfacePrimaryLinkLocalOnlyInterface(t *testing.T) {
	// An interface with no global address still shows something — its
	// first link-local entry — instead of an empty cell.
	if got := pickIfacePrimary([]string{"fe80::1", "fe80::2"}, ""); got != "fe80::1" {
		t.Fatalf("link-local-only interface must keep its first address, got %q", got)
	}
}

func TestPickIfacePrimarySkipsLoopbackAndUnspecified(t *testing.T) {
	if got := pickIfacePrimary([]string{"127.0.0.1", "0.0.0.0", "192.168.1.80"}, ""); got != "192.168.1.80" {
		t.Fatalf("loopback/unspecified must never be primary, got %q", got)
	}
}

func TestPickIfacePrimaryManagementAddressNotOnInterface(t *testing.T) {
	// The management address belongs to another NIC: fall through to the
	// reachability rules instead of inventing an address.
	if got := pickIfacePrimary([]string{"fe80::1", "192.168.1.80"}, "172.16.0.1"); got != "192.168.1.80" {
		t.Fatalf("a management address on another NIC must be ignored, got %q", got)
	}
}

func TestPickIfacePrimaryEmpty(t *testing.T) {
	if got := pickIfacePrimary(nil, ""); got != "" {
		t.Fatalf("no addresses must yield an empty primary, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Site defaulting at bind: a connection created without a site assignment
// must land its device on the organization's first site — the e2e live run
// showed the unassigned device binding successfully and then failing every
// inventory submission with an opaque empty-uuid SQL error when the asset
// was created.

type fakeSiteStore struct{ sites []domain.Site }

func (f *fakeSiteStore) List(context.Context, string) ([]domain.Site, error) {
	return f.sites, nil
}

func TestEnsureForConnectorDefaultsSitelessDeviceToFirstSite(t *testing.T) {
	site := domain.Site{ID: "site-first", Name: "Default Site"}
	// ByConnector on an unbound connector reports not-found, like the real repo.
	s := &Service{
		Repo:  &fakeDeviceStore{err: errors.New("no rows")},
		Sites: &fakeSiteStore{sites: []domain.Site{site}},
		Log:   discardLogger(),
	}
	binding, err := s.EnsureForConnector(context.Background(),
		&domain.Connector{ID: "c1", Kind: domain.ConnectorAgent}, DeviceRequest{CSR: "x"},
		func(string, string) (string, error) { return "cert", nil })
	if err != nil {
		t.Fatalf("bind must succeed with the site fallback, got %v", err)
	}
	if binding.SiteID != "site-first" {
		t.Fatalf("device must inherit the org's first site, got %q", binding.SiteID)
	}
}

func TestEnsureForConnectorKeepsAssignedSite(t *testing.T) {
	s := &Service{
		Repo:  &fakeDeviceStore{err: errors.New("no rows")},
		Sites: &fakeSiteStore{sites: []domain.Site{{ID: "site-other"}}},
		Log:   discardLogger(),
	}
	binding, err := s.EnsureForConnector(context.Background(),
		&domain.Connector{ID: "c1", Kind: domain.ConnectorAgent, SiteID: "site-explicit"},
		DeviceRequest{CSR: "x"}, func(string, string) (string, error) { return "cert", nil })
	if err != nil {
		t.Fatalf("bind must succeed, got %v", err)
	}
	if binding.SiteID != "site-explicit" {
		t.Fatalf("an explicitly assigned site must win, got %q", binding.SiteID)
	}
}

func TestLinkInventoryRejectsSitelessDeviceWithClearError(t *testing.T) {
	agentID := "device-siteless"
	s := &Service{
		Repo:   &fakeDeviceStore{device: &domain.Agent{ID: agentID, OrganizationID: "org-1", Platform: "windows"}},
		Assets: &fakeAssetStore{},
		Log:    discardLogger(),
	}
	err := s.LinkInventory(context.Background(), agentID, &domain.SystemInventory{Hostname: "x"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no site") {
		t.Fatalf("siteless device must fail with a readable error, got %v", err)
	}
	if s.Assets.(*fakeAssetStore).inserted != nil {
		t.Fatal("no asset must be created for a siteless device")
	}
}

// discardLogger keeps optional log output invisible in unit tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
