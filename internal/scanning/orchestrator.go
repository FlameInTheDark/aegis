package scanning

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/assets"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// NATS subjects used for scan orchestration (spec §78).
const (
	SubjectScanRequested = "security.scan.requested.v1"
	SubjectScanTask      = "security.scan.task.v1"
	SubjectScanResult    = "security.scan.result.v1"
)

// Orchestrator creates scans, fans out tasks and applies results.
type Orchestrator struct {
	Scans        *pg.ScanRepo
	Tasks        *pg.TaskRepo
	Observations *pg.ObservationRepo
	Scanners     *pg.ScannerRepo
	Schedules    *pg.ScheduleRepo
	Profiles     *pg.ProfileRepo
	Changes      *pg.ChangeRepo
	Assets       *pg.AssetRepo
	Inventory    *assets.Service
	Topology     *pg.TopologyRepo // optional: populated when the scanner reports traceroute hops
	Bus          *platform.Bus
	Log          *slog.Logger
	// AllowPublicScope is inherited from deployment config; it never
	// overrides per-request intent silently.
	AllowPublicScope bool
	// Hub optionally routes scans to remote gRPC scanner agents.
	Hub ScannerHub
}

// ScannerHub routes scans to remote gRPC agents (implemented by hub.Hub).
// When nil or disconnected, scans flow through NATS to embedded scanners.
type ScannerHub interface {
	Dispatch(scan *domain.Scan, cidrs []string)
	Connected(scannerID string) bool
}

// CreateScanInput is the API-level request to start a scan.
type CreateScanInput struct {
	OrgID        string
	SiteID       string
	Name         string
	Profile      domain.ScanProfile
	Targets      []string
	Denylist     []string
	Engine       string
	ScannerID    string
	CreatedBy    string
	ElevatedOK   bool // user confirmed the active_validation warning
	ScheduleCRON string
}

// ValidateProfile checks profile capability vs. request (spec §13).
// Built-in registry profiles resolve statically; custom nmap presets are
// resolved from the scan_profiles table (org-scoped).
func (o *Orchestrator) ValidateProfile(ctx context.Context, orgID string, p domain.ScanProfile, elevatedOK bool) (*domain.ProfileDefinition, error) {
	def, err := o.ResolveProfile(ctx, orgID, p)
	if err != nil {
		return nil, err
	}
	if def.ElevatedReqs && !elevatedOK {
		return nil, fmt.Errorf("profile %s requires explicit confirmation of its warning", p)
	}
	return def, nil
}

// ResolveProfile finds a profile definition by key: the static built-in
// registry first, then custom presets in the scan_profiles table. Custom
// presets are org-scoped at creation; an empty orgID (scanner-side lookup)
// resolves any preset by its globally-unique name.
func (o *Orchestrator) ResolveProfile(ctx context.Context, orgID string, p domain.ScanProfile) (*domain.ProfileDefinition, error) {
	if def, ok := domain.Profiles[p]; ok {
		return &def, nil
	}
	if o.Profiles == nil {
		return nil, fmt.Errorf("unknown profile %q", p)
	}
	def, err := o.Profiles.GetByName(ctx, string(p))
	if err != nil {
		return nil, fmt.Errorf("unknown profile %q", p)
	}
	return def, nil
}

// Create validates scope, persists the scan and enqueues discovery tasks.
func (o *Orchestrator) Create(ctx context.Context, in CreateScanInput) (*domain.Scan, error) {
	def, err := o.ValidateProfile(ctx, in.OrgID, in.Profile, in.ElevatedOK)
	if err != nil {
		return nil, err
	}
	val, err := ValidateScope(in.Targets, nil, nil, in.Denylist, o.AllowPublicScope, def.MaxTargets)
	if err != nil {
		return nil, err
	}
	targets := FilterDenied(val.Targets, in.Denylist)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets remain after denylist filtering")
	}
	if in.Engine == "" {
		in.Engine = "nmap"
	}
	cfg := &domain.ScanConfig{
		Profile:     in.Profile,
		MaxRate:     def.MaxPacketRate,
		Concurrency: 4,
		// 0 = auto: the engine sizes --host-timeout per phase. A fixed
		// 30s here used to starve the OS-fingerprint phase (nmap -O
		// runs its own port scan first) and full-range port sweeps.
		TimeoutSecs: 0,
		Retries:     1,
		Engine:      in.Engine,
		// Custom presets ship their (server-validated) extra nmap arguments
		// with the config so the engine and any re-run reproduce the probes.
		ExtraArgs: def.ExtraArgs,
	}
	// Port-selection semantics travel with the scan config so the engine
	// (and any later re-run) reproduces the exact same port set.
	if def.FullPortScan {
		cfg.FullTCPPorts = true
		cfg.UDPPorts = []int{}
	} else if def.TopTCPPorts > 0 {
		cfg.TopTCPPorts = def.TopTCPPorts
	}
	scan := &domain.Scan{
		ID: ids.New(), OrganizationID: in.OrgID, SiteID: in.SiteID,
		Name: in.Name, Profile: in.Profile, Engine: in.Engine,
		ScannerID: in.ScannerID, CreatedBy: in.CreatedBy,
		State: domain.ScanQueued, Config: cfg,
		ScheduleCRON: in.ScheduleCRON, Scheduled: in.ScheduleCRON != "",
		CreatedAt: time.Now().UTC(),
	}
	scope := &domain.ScanScope{ID: ids.New(), ScanID: scan.ID, CIDRs: targets, Denylist: in.Denylist}
	if err := o.Scans.Create(ctx, scan, scope); err != nil {
		return nil, err
	}
	// Fan out the phase-1 task. Priority: an explicitly chosen hub scanner,
	// then the org's default hub scanner, then the NATS claim path used by
	// embedded scanners. The NATS publish stays as the fallback so nothing
	// regresses when no hub is configured.
	dispatched := false
	if o.Hub != nil {
		if in.ScannerID != "" && o.Hub.Connected(in.ScannerID) {
			o.Hub.Dispatch(scan, targets)
			dispatched = true
		} else if in.ScannerID == "" {
			if def, derr := o.Scanners.DefaultForOrg(ctx, in.OrgID); derr == nil && def != nil && o.Hub.Connected(def.ID) {
				scan.ScannerID = def.ID
				_ = o.Scans.AssignScanner(ctx, scan.ID, def.ID)
				o.Hub.Dispatch(scan, targets)
				dispatched = true
			}
		}
	}
	if !dispatched {
		payload, _ := json.Marshal(map[string]any{"scan_id": scan.ID, "kind": string(domain.TaskDiscoverHosts)})
		if o.Bus != nil {
			if err := o.Bus.Publish(ctx, SubjectScanRequested, payload); err != nil {
				o.Log.Error("publish scan requested failed", "err", err)
			}
		}
	}
	o.Log.Info("scan created", "scan", scan.ID, "profile", in.Profile, "targets", len(targets), "addresses", val.TotalAddresses)
	return scan, nil
}

// RecordObservation persists a normalized scanner observation and applies
// it to the inventory (spec §137).
func (o *Orchestrator) RecordObservation(ctx context.Context, obs *domain.Observation) error {
	obs.ID = ids.New()
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now().UTC()
	}
	if obs.Payload == nil {
		obs.Payload = []byte{}
	}
	if err := o.Observations.Insert(ctx, obs); err != nil {
		return err
	}
	return o.ApplyObservation(ctx, obs)
}

// ApplyObservation updates assets/services/changes from one observation.
func (o *Orchestrator) ApplyObservation(ctx context.Context, obs *domain.Observation) error {
	if o.Inventory == nil && (obs.ObservationType == "host_up" || obs.ObservationType == "port_open" || obs.ObservationType == "service") {
		return fmt.Errorf("scan inventory service is not configured")
	}
	switch obs.ObservationType {
	case "host_up":
		ip, _ := obs.Normalized["ip"].(string)
		host, _ := obs.Normalized["hostname"].(string)
		fqdn, _ := obs.Normalized["fqdn"].(string)
		mac, _ := obs.Normalized["mac"].(string)
		if ip == "" && host == "" && mac == "" {
			return nil
		}
		a, created, err := o.Inventory.ProvisionHost(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, ip, mac, host, fqdn, string(obs.Source), obs.Confidence)
		if err != nil {
			return err
		}
		if !created && o.Assets != nil {
			_ = o.Assets.TouchSeen(ctx, a.ID)
		}
		if dt, _ := obs.Normalized["device_type"].(string); dt != "" {
			o.Inventory.RecordDevice(ctx, obs.ScanID, obs.SiteID, a.ID, domain.DeviceType(dt), obs.Confidence, string(obs.Source))
		}
		// Type-assert BEFORE comparing: a missing key returns nil (any),
		// and `nil != ""` is true — the guard would pass on every
		// host_up and RecordOS would then stamp os_confidence with the
		// presence confidence while leaving os_name empty, blocking
		// every later OS fingerprint of lower numeric confidence.
		fam, _ := obs.Normalized["os_family"].(string)
		osName, _ := obs.Normalized["os_name"].(string)
		if fam != "" || osName != "" {
			ver, _ := obs.Normalized["os_version"].(string)
			o.Inventory.RecordOS(ctx, obs.ScanID, obs.SiteID, a.ID, fam, osName, ver, obs.Confidence, string(obs.Source))
		}
	case "port_open":
		a, err := o.assetForTarget(ctx, obs)
		if err != nil || a == nil {
			return err
		}
		port, _ := obs.Normalized["port"].(float64)
		proto, _ := obs.Normalized["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		name, _ := obs.Normalized["service"].(string)
		svc := &domain.Service{
			Protocol: proto, Port: int(port), ServiceName: name,
			State: "open", Confidence: obs.Confidence,
			Sources: []string{string(obs.Source)}, Exposure: domain.ExposureInternal,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}
		if banner, _ := obs.Normalized["banner"].(string); banner != "" {
			svc.Banner = truncate(banner, 512) // attacker-controlled: bound it
		}
		_, err = o.Inventory.RecordService(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, a.ID, svc)
		if err == nil {
			o.bumpStats(obs.ScanID, func(st *domain.ScanStats) { st.PortsDiscovered++ })
		}
		return err
	case "service":
		a, err := o.assetForTarget(ctx, obs)
		if err != nil || a == nil {
			return err
		}
		port := intOf(obs.Normalized["port"])
		proto, _ := obs.Normalized["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		svc := &domain.Service{
			Protocol: proto, Port: port,
			ServiceName: strOf(obs.Normalized["service"]),
			Product:     strOf(obs.Normalized["product"]),
			Vendor:      strOf(obs.Normalized["vendor"]),
			State:       "open", Confidence: obs.Confidence,
			Sources: []string{string(obs.Source)}, Exposure: domain.ExposureInternal,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}
		if ver := strOf(obs.Normalized["version"]); ver != "" {
			svc.DetectedVersion = ver
			svc.VersionConf = obs.Confidence
		}
		if banner, _ := obs.Normalized["banner"].(string); banner != "" {
			svc.Banner = truncate(banner, 512)
		}
		if cpes := cpeList(obs.Normalized["cpes"]); len(cpes) > 0 {
			svc.CPEs = cpes
		} else if cpe, _ := obs.Normalized["cpe"].(string); cpe != "" {
			svc.CPEs = []string{cpe}
		}
		if tlsRaw, ok := obs.Normalized["tls"].(map[string]any); ok {
			svc.TLS = tlsFromMap(tlsRaw)
		}
		if httpRaw, ok := obs.Normalized["http"].(map[string]any); ok {
			svc.HTTP = httpFromMap(httpRaw)
		}
		_, err = o.Inventory.RecordService(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, a.ID, svc)
		if err == nil {
			o.bumpStats(obs.ScanID, func(st *domain.ScanStats) { st.ServicesFingerprinted++ })
		}
		// Service-level OS hints (nmap service table, HTTP server headers):
		// far weaker than -O fingerprints but available without raw sockets.
		// When the service table has no ostype, the OS CPE nmap appends to
		// service fingerprints ("cpe:/o:linux:linux_kernel") still tells
		// us the family — on hosts whose -O probes are filtered this is
		// the only OS signal a scan can get.
		fam, name := "", ""
		if osHint, _ := obs.Normalized["os"].(string); osHint != "" {
			fam, name = osHintFamily(osHint)
		}
		if fam == "" {
			for _, cpe := range svc.CPEs {
				if f, n, ok := osFamilyFromCPE(cpe); ok {
					fam, name = f, n
					break
				}
			}
		}
		if fam != "" || name != "" {
			o.Inventory.RecordOS(ctx, obs.ScanID, obs.SiteID, a.ID, fam, name, "", 0.5, string(obs.Source))
		}
		// Device-type hints from service fingerprints. Deliberately
		// conservative mappings and a low 0.55 confidence: a JetDirect
		// listener is a printer, an RTSP endpoint on a LAN is very
		// likely a camera, NAS brand names are self-describing — but
		// any -O osclass or stronger later classification must win.
		if dt := deviceHintFromService(strOf(obs.Normalized["service"]), strOf(obs.Normalized["product"]), svc.CPEs); dt != "" {
			o.Inventory.RecordDevice(ctx, obs.ScanID, obs.SiteID, a.ID, domain.DeviceType(dt), 0.55, string(obs.Source))
		}
		// Software bridge: a -sV fingerprint (product/version/CPE) is the
		// network view of "what is installed behind the port". Persist it
		// so the software tab is useful without an endpoint agent; the
		// agent path refines it with OS-level packages later.
		if err == nil {
			if sw := softwareFromService(svc); sw != nil {
				if serr := o.Inventory.RecordSoftware(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, a.ID, sw); serr != nil {
					o.Log.Warn("software record failed", "asset", a.ID, "err", serr)
				}
			}
		}
		return err
	case "host_down":
		o.bumpStats(obs.ScanID, func(st *domain.ScanStats) { st.Unreachable++ })
	case "topology":
		return o.applyTopologyObservation(ctx, obs)
	case "os":
		// handled inside host_up payload in practice; kept for nmap split runs
	default:
		o.Log.Debug("ignoring observation type", "type", obs.ObservationType)
	}
	return nil
}

// applyTopologyObservation turns one scanner traceroute report into
// topology nodes and edges. Payload shape (normalized):
//
//	{"ip": "192.168.1.55", "method": "traceroute",
//	 "path": [{"ip": "192.168.1.1", "ttl": 1}, {"ip": "192.168.1.55", "ttl": 2}]}
//
// The path walks from the scanner outward; the last hop is the target host.
// Every node/edge is an upsert keyed by (site, kind, ref) so repeated scans
// refresh last_seen instead of duplicating rows.
func (o *Orchestrator) applyTopologyObservation(ctx context.Context, obs *domain.Observation) error {
	if o.Topology == nil {
		return nil // topology repo not wired: observations stay persisted for later replay
	}
	targetIP, _ := obs.Normalized["ip"].(string)
	type hopNode struct {
		id  string
		ip  string
		tgt bool
	}
	var hops []hopNode
	// The path arrives in two shapes depending on the code path: as
	// []any{map[string]any...} after a JSON round-trip (replayed
	// observations) or as []map[string]any built in-memory by the scanner.
	appendHop := func(m map[string]any) {
		ip, _ := m["ip"].(string)
		if ip == "" {
			return
		}
		hops = append(hops, hopNode{ip: ip, tgt: ip == targetIP})
	}
	switch path := obs.Normalized["path"].(type) {
	case []any:
		for _, p := range path {
			if m, ok := p.(map[string]any); ok {
				appendHop(m)
			}
		}
	case []map[string]any:
		for _, m := range path {
			appendHop(m)
		}
	}
	if len(hops) == 0 {
		return nil
	}
	// Resolve/create the asset node for the target so the UI can jump from
	// the topology graph straight to the inventory entry.
	var assetNodeID string
	if targetIP != "" && o.Inventory != nil {
		if a, _, err := o.Inventory.ProvisionHost(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, targetIP, "", "", "", string(obs.Source), 0.6); err == nil && a != nil {
			n := &domain.TopologyNode{OrganizationID: obs.OrganizationID, SiteID: obs.SiteID, Kind: domain.NodeAsset, RefID: a.ID, Label: nodeLabel(a, targetIP)}
			if err := o.Topology.UpsertNode(ctx, n); err == nil {
				assetNodeID = n.ID
			}
		}
	}
	for i := range hops {
		if hops[i].tgt && assetNodeID != "" {
			hops[i].id = assetNodeID
			continue
		}
		n := &domain.TopologyNode{OrganizationID: obs.OrganizationID, SiteID: obs.SiteID, Kind: domain.NodeRouter, RefID: hops[i].ip, Label: hops[i].ip}
		if err := o.Topology.UpsertNode(ctx, n); err != nil {
			return err
		}
		hops[i].id = n.ID
	}
	// Chain the path: hop[i] routes_to hop[i+1].
	prev := hops[0].id
	for i := 1; i < len(hops); i++ {
		if hops[i].id == "" || hops[i].id == prev {
			if hops[i].id != "" {
				prev = hops[i].id
			}
			continue
		}
		e := &domain.TopologyEdge{OrganizationID: obs.OrganizationID, SiteID: obs.SiteID, SrcNodeID: prev, DstNodeID: hops[i].id, Kind: domain.EdgeRoutesTo, Confidence: 0.85}
		if err := o.Topology.UpsertEdge(ctx, e); err != nil {
			return err
		}
		prev = hops[i].id
	}
	// When the traced path does not already end on the asset node (filtered
	// final hop), connect the deepest reachable hop to the asset.
	if assetNodeID != "" && prev != assetNodeID {
		e := &domain.TopologyEdge{OrganizationID: obs.OrganizationID, SiteID: obs.SiteID, SrcNodeID: prev, DstNodeID: assetNodeID, Kind: domain.EdgeObservedThru, Confidence: 0.7}
		if err := o.Topology.UpsertEdge(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func nodeLabel(a *domain.Asset, ip string) string {
	if a == nil {
		return ip
	}
	if a.Hostname != "" {
		return a.Hostname
	}
	// No hostname yet: name the node by its address first — operators
	// navigate by IP. "Unknown Device · 192.168.1.5" hid the one fact we
	// are sure of behind a label we are not; the device class (when known)
	// decorates the address instead of replacing it.
	addr := ip
	if addr == "" {
		addr = a.PrimaryIP
	}
	if dt := a.DeviceType.Label(); dt != "" && dt != domain.DeviceUnknown.Label() {
		if addr != "" {
			return dt + " · " + addr
		}
		return dt
	}
	if addr != "" {
		return addr
	}
	return "Host " + a.ID[:8]
}

// deviceHintFromService maps service fingerprints to device classes where
// the mapping is essentially unambiguous. Kept narrow on purpose — a wrong
// device label erodes trust in the whole inventory — and combined with a
// 0.55 confidence at the call site so stronger evidence always overrides it.
// Hardware CPEs (cpe:/h:…) are the strongest service-borne signal: nmap only
// emits them when the service table matched actual device firmware.
func deviceHintFromService(name, product string, cpes []string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	p := strings.ToLower(strings.TrimSpace(product))
	both := n + " " + p
	switch {
	case n == "jetdirect" || strings.Contains(both, "jetdirect"),
		strings.Contains(both, "laserjet"), strings.Contains(both, "inkjet"),
		strings.Contains(both, "deskjet"),
		n == "printer",
		strings.Contains(p, "printer"),
		strings.Contains(p, "lexmark"), strings.Contains(p, "brother"),
		strings.Contains(p, "epson"), strings.Contains(p, "ricoh"),
		strings.Contains(p, "xerox") && strings.Contains(p, "workcentre"):
		return "printer"
	case n == "rtsp", strings.Contains(both, "camera"),
		strings.Contains(both, "hikvision"), strings.Contains(both, "dahua"),
		strings.Contains(both, "network video recorder"), strings.Contains(both, "nvr"):
		return "camera"
	case strings.Contains(both, "synology"), strings.Contains(both, "diskstation"),
		strings.Contains(both, "readynas"), strings.Contains(both, "qnap"),
		strings.Contains(both, "truenas"), strings.Contains(both, "freenas"):
		return "nas"
	}
	for _, cpe := range cpes {
		// Match cpe:/h: and cpe:2.3:h: shapes by checking the part field.
		part := byte(0)
		if strings.HasPrefix(cpe, "cpe:/") && len(cpe) > 5 {
			part = cpe[5]
		} else if strings.HasPrefix(cpe, "cpe:2.3:") && len(cpe) > 8 {
			part = cpe[8]
		}
		if part != 'h' {
			continue
		}
		lc := strings.ToLower(cpe)
		if strings.Contains(lc, "printer") || strings.Contains(lc, "laserjet") ||
			strings.Contains(lc, "jetdirect") {
			return "printer"
		}
		if strings.Contains(lc, "camera") || strings.Contains(lc, "webcam") ||
			strings.Contains(lc, "hikvision") || strings.Contains(lc, "dahua") {
			return "camera"
		}
		if strings.Contains(lc, "nas") || strings.Contains(lc, "diskstation") ||
			strings.Contains(lc, "readynas") {
			return "nas"
		}
	}
	return ""
}

// cpeList normalizes the "cpes" payload key across shapes: []string when the
// observation was built in memory, []any after a JSON round-trip.
func cpeList(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// osFamilyFromCPE extracts an OS family from a CPE of part type "o"
// (cpe:/o:linux:linux_kernel -> linux). Returns ok=false for application
// ("a") and hardware ("h") CPEs. Both CPE 2.2 ("cpe:/o:v:p") and 2.3
// ("cpe:2.3:o:v:p:ver:...") forms share the vendor:product indexing after
// the part-type field.
func osFamilyFromCPE(cpe string) (family, name string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(cpe, "cpe:/"), "cpe:2.3:"), ":")
	if len(parts) < 3 || parts[0] != "o" {
		return "", "", false
	}
	return osFamilyFromVendorProduct(strings.ToLower(parts[1]), strings.ToLower(parts[2]))
}

func osFamilyFromVendorProduct(vendor, product string) (string, string, bool) {
	switch {
	case vendor == "linux" || vendor == "kernel" || strings.Contains(product, "linux"):
		return "linux", "Linux", true
	case vendor == "microsoft" || strings.HasPrefix(product, "windows"):
		return "windows", "Windows", true
	case vendor == "apple" || product == "macos" || product == "mac_os_x" || product == "os_x":
		return "macos", "macOS", true
	case strings.Contains(product, "freebsd"):
		return "bsd", "FreeBSD", true
	case strings.Contains(product, "openbsd"):
		return "bsd", "OpenBSD", true
	case strings.Contains(product, "netbsd"):
		return "bsd", "NetBSD", true
	case vendor == "cisco":
		return "cisco-ios", "Cisco IOS", true
	case vendor == "vmware":
		return "vmware", "VMware ESXi", true
	case product == "solaris":
		return "solaris", "Solaris", true
	case vendor == "juniper":
		return "junos", "Juniper JunOS", true
	case vendor == "qnx":
		return "qnx", "QNX", true
	case vendor == "vxworks" || product == "vxworks":
		return "vxworks", "VxWorks", true
	}
	return "", "", false
}

// softwareFromService converts a network service fingerprint into a software
// inventory row. Only meaningful fingerprints are converted: a bare service
// name without product, version or CPE ("http" alone) carries no software
// information and would pollute the inventory. OS CPEs are excluded — the
// operating system is asset metadata, not installed software.
func softwareFromService(svc *domain.Service) *domain.Software {
	if svc == nil {
		return nil
	}
	name := svc.Product
	if name == "" {
		name = svc.ServiceName
	}
	if name == "" {
		return nil
	}
	appCPEs := make([]string, 0, len(svc.CPEs))
	for _, c := range svc.CPEs {
		if !strings.HasPrefix(c, "cpe:/o:") && !strings.HasPrefix(c, "cpe:2.3:o:") {
			appCPEs = append(appCPEs, c)
		}
	}
	if svc.Product == "" && svc.DetectedVersion == "" && len(appCPEs) == 0 {
		return nil
	}
	return &domain.Software{
		Name:      name,
		Version:   svc.DetectedVersion,
		Vendor:    svc.Vendor,
		Ecosystem: "cpe",
		CPEs:      appCPEs,
		Source:    "nmap",
	}
}

// osHintFamily maps free-form OS hints to the family taxonomy used by -O.
func osHintFamily(hint string) (family, name string) {
	h := strings.ToLower(hint)
	switch {
	case strings.Contains(h, "win"):
		return "windows", "Windows"
	case strings.Contains(h, "linux"), strings.Contains(h, "unix"):
		return "linux", hint
	case strings.Contains(h, "ios"), strings.Contains(h, "cisco"):
		return "cisco-ios", "Cisco IOS"
	case strings.Contains(h, "bsd"):
		return "bsd", hint
	case strings.Contains(h, "mac"), strings.Contains(h, "darwin"):
		return "macos", "macOS"
	default:
		return "", hint
	}
}

func (o *Orchestrator) assetForTarget(ctx context.Context, obs *domain.Observation) (*domain.Asset, error) {
	ip, _ := obs.Normalized["ip"].(string)
	if ip == "" {
		ip = obs.Target
	}
	host, _ := obs.Normalized["hostname"].(string)
	mac, _ := obs.Normalized["mac"].(string)
	a, _, err := o.Inventory.ProvisionHost(ctx, obs.OrganizationID, obs.SiteID, obs.ScanID, ip, mac, host, "", string(obs.Source), obs.Confidence)
	return a, err
}

// CompleteTask marks a task done and advances scan progress (§116).
func (o *Orchestrator) CompleteTask(ctx context.Context, scanID, taskID string, errMsg string) {
	state := domain.TaskSucceeded
	if errMsg != "" {
		state = domain.TaskFailed
	}
	_ = o.Tasks.UpdateState(ctx, taskID, state, errMsg)
	o.RefreshProgress(ctx, scanID)
}

// RefreshProgress recomputes counters for a scan.
func (o *Orchestrator) RefreshProgress(ctx context.Context, scanID string) {
	done, failed, total, err := o.Tasks.CountByState(ctx, scanID)
	if err != nil {
		return
	}
	progress := 0.0
	phase := "discovery"
	if total > 0 {
		progress = float64(done+failed) / float64(total) * 100
	}
	if progress >= 100 {
		phase = "completed"
		_ = o.Scans.UpdateState(ctx, scanID, domain.ScanCompleted, phase, 100)
	} else {
		_ = o.Scans.UpdateState(ctx, scanID, domain.ScanRunning, phase, progress)
	}
	_ = o.Scans.UpdateStats(ctx, scanID, domain.ScanStats{TasksTotal: int(total), TasksDone: int(done), TasksFailed: int(failed)})
}

// Cancel sets the kill switch; scanners poll it between probes (§11/§13).
func (o *Orchestrator) Cancel(ctx context.Context, orgID, scanID string) error {
	scan, err := o.Scans.ByID(ctx, orgID, scanID)
	if err != nil {
		return err
	}
	if scan.State != domain.ScanRunning && scan.State != domain.ScanQueued && scan.State != domain.ScanPaused {
		return fmt.Errorf("scan %s is %s and cannot be cancelled", scanID, scan.State)
	}
	_ = o.Scans.UpdateState(ctx, scanID, domain.ScanCancelling, "cancelling", scan.Progress)
	return o.Scans.SetKillSwitch(ctx, scanID)
}

// RunDueSchedules materializes scheduled scans whose next run passed.
func (o *Orchestrator) RunDueSchedules(ctx context.Context, now time.Time) int {
	due, err := o.Schedules.Due(ctx, now)
	if err != nil {
		return 0
	}
	n := 0
	for _, s := range due {
		_, err := o.Create(ctx, CreateScanInput{
			OrgID: s.OrganizationID, SiteID: s.SiteID, Name: s.Name,
			Profile: s.Profile, Targets: s.Scope, Engine: s.Engine,
			CreatedBy: s.CreatedBy, ScheduleCRON: s.CRON,
		})
		if err != nil {
			o.Log.Error("scheduled scan failed", "schedule", s.ID, "err", err)
			continue
		}
		next := NextRunAfter(now, s.CRON)
		_ = o.Schedules.MarkRun(ctx, s.ID, now, next)
		n++
	}
	return n
}

// NextRunAfter computes the next cron run (simple CRON subset:
// "M H * * *" daily/time-of-day or "@every 1h" style; documented assumption §191).
func NextRunAfter(now time.Time, cron string) time.Time {
	if after, ok := parseEvery(now, cron); ok {
		return after
	}
	fields := splitFields(cron)
	if len(fields) == 5 {
		if m, h, ok := parseCronDaily(fields); ok {
			next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
			if !next.After(now) {
				next = next.Add(24 * time.Hour)
			}
			return next
		}
	}
	return now.Add(24 * time.Hour) // conservative default: daily
}

func parseEvery(now time.Time, cron string) (time.Time, bool) {
	if len(cron) > 7 && cron[:7] == "@every " {
		if d, err := time.ParseDuration(cron[7:]); err == nil && d >= time.Minute {
			return now.Add(d), true
		}
	}
	return time.Time{}, false
}

func splitFields(cron string) []string {
	var out []string
	cur := ""
	for _, r := range cron {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func parseCronDaily(f []string) (int, int, bool) {
	m, err1 := strconv.Atoi(f[0])
	h, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || m < 0 || m > 59 || h < 0 || h > 23 {
		return 0, 0, false
	}
	return m, h, true
}

func (o *Orchestrator) bumpStats(scanID string, fn func(*domain.ScanStats)) {
	// Per-observation counters are folded into scan stats by the scanner
	// process at task completion via RefreshProgress/UpdateStats.
	_ = scanID
	_ = fn
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func intOf(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	}
	return 0
}

func tlsFromMap(m map[string]any) *domain.TLSInfo {
	t := &domain.TLSInfo{}
	t.Version = strOf(m["version"])
	t.Cipher = strOf(m["cipher"])
	t.SubjectCN = strOf(m["subject_cn"])
	t.Issuer = strOf(m["issuer"])
	t.SHA256 = strOf(m["sha256"])
	t.SelfSigned = strOf(m["self_signed"]) == "true"
	t.Expired = strOf(m["expired"]) == "true"
	if alpn, ok := m["alpn"].([]any); ok {
		for _, a := range alpn {
			t.ALPN = append(t.ALPN, fmt.Sprint(a))
		}
	}
	return t
}

func httpFromMap(m map[string]any) *domain.HTTPInfo {
	h := &domain.HTTPInfo{}
	h.Title = strOf(m["title"])
	h.ServerHeader = strOf(m["server_header"])
	h.PoweredBy = strOf(m["x_powered_by"])
	h.StatusLine = strOf(m["status_line"])
	return h
}
