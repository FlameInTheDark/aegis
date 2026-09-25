// Package assets implements asset provisioning and correlation :
// different scanners report the same device differently; an identity
// resolver merges observations into logical assets without ever merging
// two devices solely because they shared an IP at different times.
package assets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// IPStaleFromEnv reads AEGIS_ASSET_IP_STALE_DAYS (days). Every process that
// builds an inventory Service (server hub ingestion, embedded scanner) uses
// it so identity resolution behaves identically regardless of which path
// applied the observation.
func IPStaleFromEnv() time.Duration {
	d := strings.TrimSpace(os.Getenv("AEGIS_ASSET_IP_STALE_DAYS"))
	if d == "" {
		return 0
	}
	n, err := strconv.Atoi(d)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * 24 * time.Hour
}

// Service provisions assets from observations.
type Service struct {
	Assets   *pg.AssetRepo
	Ident    *pg.IdentifierRepo
	Ifaces   *pg.InterfaceRepo
	Services *pg.ServiceRepo
	Software *pg.SoftwareRepo
	Changes  *pg.ChangeRepo
	// DB enables domain-event emission into the alert outbox (asset
	// discovered, service discovered/changed, software installed); nil
	// disables emission (tests, or consumers that must stay silent).
	DB  *pg.DB
	Log *slog.Logger
	// IPStale bounds how long an IP observation keeps resolving to the same
	// asset. 0 (the default) means: within a site, an address always maps to
	// the asset that last held it — rescans update the asset instead of
	// creating a copy. Strong identifiers (agent/mac/hostname) still win
	// first, so a genuinely new device appearing at a reused address is
	// recognized by its MAC/hostname and the IP moves to it.
	IPStale time.Duration
}

// ProvisionHost upserts a host observed at a site. Identity resolution:
//  1. strong identifiers (agent/cert/mac/serial/machine_id) win,
//  2. the address resolves to the asset that last held this IP in the site
//     (address-aware: rescans refresh the same asset instead of copying it;
//     see Service.IPStale for the optional staleness bound),
//  3. otherwise a NEW asset is created.
func (s *Service) ProvisionHost(ctx context.Context, orgID, siteID, scanID, ip, mac, macVendor, hostname, fqdn, source string, conf domain.Confidence) (*domain.Asset, bool, error) {
	created := false
	asset := s.findByStrongID(ctx, orgID, mac, hostname, fqdn)
	if asset == nil {
		asset = s.findByAddress(ctx, orgID, siteID, ip)
	}
	if asset == nil {
		asset = &domain.Asset{
			ID: ids.New(), OrganizationID: orgID, SiteID: siteID,
			DeviceType: domain.DeviceUnknown, Exposure: domain.ExposureInternal,
			Criticality: domain.CriticalityMedium,
			// The observation confidence describes PRESENCE, not the
			// OS/device classification. Seeding os_confidence with it
			// (0.85 from discovery) used to block every later OS
			// fingerprint of lower numeric confidence — OS data starts
			// at 0 and is filled in by RecordOS/RecordDevice.
			DeviceTypeConf: 0.2, DeviceTypeSrcs: []string{source},
		}
		if err := s.Assets.Insert(ctx, asset); err != nil {
			return nil, false, err
		}
		created = true
		if s.Changes != nil && scanID != "" {
			s.recordChange(ctx, scanID, siteID, domain.ChangeNewAsset, asset.ID, "", "", ip)
		}
		if s.DB != nil {
			// Reliable transition: a NEW device entered the inventory.
			_ = alerting.EmitAssetDiscovered(ctx, s.DB, orgID, siteID, asset.ID, hostname, source, string(asset.DeviceType))
		}
	}

	// Merge identity data.
	if mac != "" {
		_ = s.Ident.Upsert(ctx, asset.ID, "mac", strings.ToLower(mac), domain.IdentifierWeights["mac"])
	}
	if ip != "" {
		_ = s.Ident.Upsert(ctx, asset.ID, "ip", ip, domain.IdentifierWeights["ip"])
	}
	if hostname != "" {
		_ = s.Ident.Upsert(ctx, asset.ID, "hostname", strings.ToLower(hostname), domain.IdentifierWeights["hostname"])
	}
	if fqdn != "" {
		_ = s.Ident.Upsert(ctx, asset.ID, "fqdn", strings.ToLower(fqdn), domain.IdentifierWeights["fqdn"])
	}

	// Enrich fields when we have better evidence than stored.
	fields := map[string]any{"last_seen": time.Now().UTC()}
	if hostname != "" && asset.Hostname == "" {
		fields["hostname"] = hostname
	}
	if fqdn != "" && asset.FQDN == "" {
		fields["fqdn"] = fqdn
	}
	// Hardware vendor: nmap's resolved OUI organization is real evidence
	// and upgrades the tiny built-in OUI guess; both only fill an empty
	// vendor so agent-reported data stays authoritative.
	if mac != "" && asset.Vendor == "" {
		if v := macVendor; v == "" {
			v = OUIVendor(mac)
			if v != "" {
				fields["vendor"] = v
			}
		} else {
			fields["vendor"] = v
		}
	}
	if macVendor != "" && asset.Vendor != "" && asset.Vendor == OUIVendor(mac) {
		fields["vendor"] = macVendor // upgrade the OUI guess to the real string
	}
	if err := s.Assets.Update(ctx, asset.ID, fields); err != nil {
		s.Log.Warn("asset enrich failed", "asset", asset.ID, "err", err)
	}
	if ip != "" {
		s.ensureInterface(ctx, asset.ID, mac, macVendor, ip)
	}
	return asset, created, nil
}

// RecordOS applies an OS observation with confidence and source.
// Override semantics: the LATEST observation of equal or higher confidence
// replaces the stored fingerprint (equal-confidence observations refresh the
// values instead of bouncing off them), so a fresh scan always updates the
// asset. Endpoint agents remain authoritative over network guesses.
func (s *Service) RecordOS(ctx context.Context, orgID, scanID, siteID, assetID, family, name, version string, conf domain.Confidence, source string) {
	if assetID == "" {
		return
	}
	// An observation with no OS content must not move the confidence dial:
	// stamping os_confidence without family/name/version would block every
	// later real fingerprint of lower numeric confidence.
	if family == "" && name == "" && version == "" {
		return
	}
	cur, err := s.Assets.ByID(ctx, "", assetID)
	if err != nil || cur == nil {
		return
	}
	// Endpoint agent is authoritative over network guesses; otherwise the
	// latest evidence at equal or better confidence wins.
	if conf >= cur.OSConfidence || source == string(domain.SourceAgent) {
		fields := map[string]any{
			"os_confidence": conf, "last_seen": time.Now().UTC(),
		}
		if family != "" {
			fields["os_family"] = family
		}
		if name != "" {
			fields["os_name"] = name
		}
		if version != "" {
			fields["os_version"] = version
		}
		srcs := cur.OSSources
		if !contains(srcs, source) {
			srcs = append(srcs, source)
			fields["os_sources"] = srcs
		}
		if cur.OSName != "" && name != "" && cur.OSName != name {
			if s.Changes != nil && scanID != "" {
				s.recordChange(ctx, scanID, siteID, domain.ChangeOSChanged, assetID, "os", cur.OSName, name)
			}
		}
		_ = s.Assets.Update(ctx, assetID, fields)
	}
}

// RecordDevice applies device-type classification with confidence.
// Override semantics mirror RecordOS: evidence at equal or higher confidence
// wins (floor 0.5), so a dedicated fingerprint scan refreshes the
// classification while a weak service-table hint (0.55) can fill an
// unclassified asset but never tramples a MAC-vendor or osclass verdict.
func (s *Service) RecordDevice(ctx context.Context, orgID, scanID, siteID, assetID string, dt domain.DeviceType, conf domain.Confidence, source string) {
	if assetID == "" || dt == "" || dt == domain.DeviceUnknown {
		return
	}
	if conf < domain.Confidence(0.5) {
		return
	}
	cur, err := s.Assets.ByID(ctx, "", assetID)
	if err != nil || cur == nil {
		return
	}
	if conf < cur.DeviceTypeConf {
		return
	}
	fields := map[string]any{"device_type": dt, "device_type_confidence": conf, "last_seen": time.Now().UTC()}
	if s := source; s != "" {
		fields["device_type_sources"] = []string{s}
	}
	_ = s.Assets.Update(ctx, assetID, fields)
}

// RecordService upserts an observed service and records change deltas.
func (s *Service) RecordService(ctx context.Context, orgID, siteID, scanID, assetID string, svc *domain.Service) (*domain.Service, error) {
	existing, _ := s.findService(ctx, assetID, svc.Port, svc.Protocol)
	if existing != nil {
		svc.ID = existing.ID
		svc.FirstSeen = existing.FirstSeen
	} else {
		if svc.ID == "" {
			svc.ID = ids.New()
		}
		if s.Changes != nil && scanID != "" {
			s.recordChange(ctx, scanID, siteID, domain.ChangeServiceOpened, assetID, fmt.Sprintf("%s/%d", svc.Protocol, svc.Port), "", svc.ServiceName)
		}
	}
	svc.OrganizationID = orgID
	svc.AssetID = assetID
	svc.LastSeen = time.Now().UTC()
	productChanged := existing != nil && existing.Product != "" && svc.Product != existing.Product
	if productChanged {
		if s.Changes != nil && scanID != "" {
			s.recordChange(ctx, scanID, siteID, domain.ChangeServiceChanged, assetID, fmt.Sprintf("%s/%d", svc.Protocol, svc.Port), existing.Product, svc.Product)
		}
	}
	if err := s.Services.Upsert(ctx, svc); err != nil {
		return nil, err
	}
	if s.DB != nil {
		_ = alerting.EmitService(ctx, s.DB, orgID, siteID, assetID, svc.ID,
			fmt.Sprintf("%s/%d", svc.Protocol, svc.Port), svc.Product, productChanged)
	}
	return svc, nil
}

// RecordSoftware upserts an agent-reported package.
func (s *Service) RecordSoftware(ctx context.Context, orgID, siteID, scanID, assetID string, sw *domain.Software) error {
	exists, _, err := s.Software.ExistsForAsset(ctx, assetID, sw.Name, sw.Version, sw.Ecosystem)
	if err != nil {
		s.Log.Warn("software existence check failed", "asset", assetID, "err", err)
	}
	sw.AssetID = assetID
	sw.LastSeen = time.Now().UTC()
	if sw.ID == "" {
		sw.ID = ids.New()
	}
	if err := s.Software.Upsert(ctx, sw); err != nil {
		return err
	}
	if !exists && s.DB != nil {
		_ = alerting.EmitSoftwareInstalled(ctx, s.DB, orgID, siteID, assetID, sw.ID, sw.Name, sw.Version, sw.Ecosystem)
	}
	return nil
}

// MarkMissingAgent records an agent-absent posture change for a site.
func (s *Service) MarkMissingAgent(ctx context.Context, siteID, assetID string) {
	// placeholder used by the worker's coverage job
	_ = ctx
	_ = siteID
	_ = assetID
}

func (s *Service) findByStrongID(ctx context.Context, orgID, mac, hostname, fqdn string) *domain.Asset {
	type idpair struct{ typ, val string }
	var pairs []idpair
	if mac != "" {
		pairs = append(pairs, idpair{"mac", strings.ToLower(mac)})
	}
	if hostname != "" {
		pairs = append(pairs, idpair{"hostname", strings.ToLower(hostname)})
	}
	if fqdn != "" {
		pairs = append(pairs, idpair{"fqdn", strings.ToLower(fqdn)})
	}
	for _, p := range pairs {
		idsList, err := s.Ident.FindByIdentifier(ctx, orgID, p.typ, p.val)
		if err != nil || len(idsList) == 0 {
			continue
		}
		// Multiple candidates: ambiguous (same hostname reused). Merge only
		// when unambiguous — otherwise prefer none and let evidence grow.
		if len(idsList) > 1 {
			continue
		}
		a, err := s.Assets.ByID(ctx, orgID, idsList[0])
		if err == nil && a != nil {
			return a
		}
	}
	return nil
}

// findByAddress resolves an IP to the asset that last held it within the
// site, using the persisted "ip" identifier (indexed by (type, value)) —
// never a fuzzy text search. The result must belong to the requesting org
// and site: the same subnet can legitimately exist in two sites.
func (s *Service) findByAddress(ctx context.Context, orgID, siteID, ip string) *domain.Asset {
	if ip == "" {
		return nil
	}
	candidates, err := s.Ident.FindByIdentifier(ctx, orgID, "ip", ip)
	if err != nil || len(candidates) == 0 {
		return nil
	}
	var best *domain.Asset
	for _, id := range candidates {
		a, err := s.Assets.ByID(ctx, orgID, id)
		if err != nil || a == nil || a.OrganizationID != orgID || a.SiteID != siteID {
			continue
		}
		if s.IPStale > 0 && !a.LastSeen.After(time.Now().UTC().Add(-s.IPStale)) {
			continue // explicitly configured staleness bound exceeded
		}
		if best == nil || a.LastSeen.After(best.LastSeen) {
			best = a
		}
	}
	return best
}

func (s *Service) findService(ctx context.Context, assetID string, port int, proto string) (*domain.Service, error) {
	list, err := s.Services.ListForAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Port == port && strings.EqualFold(list[i].Protocol, proto) {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (s *Service) ensureInterface(ctx context.Context, assetID, mac, macVendor, ip string) {
	if mac == "" {
		return // no MAC: cannot key an interface row (IP-only observation)
	}
	var nic *domain.Interface
	ifaces, err := s.Ifaces.ListForAsset(ctx, assetID)
	if err == nil {
		for i := range ifaces {
			if strings.EqualFold(ifaces[i].MAC, mac) {
				nic = &ifaces[i]
				break
			}
		}
	}
	if nic == nil {
		now := time.Now().UTC()
		nic = &domain.Interface{ID: ids.New(), AssetID: assetID, MAC: strings.ToLower(mac), Vendor: macVendor, Status: "unknown", FirstSeen: now, LastSeen: now}
	} else if nic.Vendor == "" && macVendor != "" {
		nic.Vendor = macVendor
	}
	if err := s.Ifaces.Upsert(ctx, nic); err != nil {
		// Surface the failure instead of vanishing: this upsert once failed
		// for the whole product lifetime (42P10 - migration 0003 had no
		// unique index on (asset_id, mac) for the ON CONFLICT target) and
		// MAC/vendor/address data silently never appeared in the inventory.
		s.Log.Warn("interface upsert failed", "asset", assetID, "mac", mac, "err", err)
		return
	}
	// Attach the observed address to the interface (idempotent): AddIP
	// previously had zero callers, so ip_addresses stayed empty and the
	// interfaces section of the asset page showed no addresses. The scanned
	// address becomes the interface's single primary — exactly one per
	// interface, mirroring the agent path's SetPrimaryIP convergence.
	if ip != "" {
		_ = s.Ifaces.AddIP(ctx, nic.ID, ip, false)
		_ = s.Ifaces.SetPrimaryIP(ctx, nic.ID, ip)
	}
}

func (s *Service) recordChange(ctx context.Context, scanID, siteID string, t domain.ChangeType, assetID, entity, before, after string) {
	_ = s.Changes.Insert(ctx, &domain.Change{ID: ids.New(), ScanID: scanID, SiteID: siteID, Type: t, AssetID: assetID, Entity: entity, Before: before, After: after, CreatedAt: time.Now().UTC()})
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ouiVendorMap is a deliberately small vendor prefix table for evidence
// enrichment (not authoritative device classification).
var ouiVendorMap = map[string]string{
	"00:1a:2b": "Ayecom", "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
	"08:00:27": "Oracle VirtualBox", "52:54:00": "QEMU/KVM", "b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "00:1b:63": "Apple",
	"f0:18:98": "Apple", "3c:06:30": "Apple", "00:26:bb": "Apple",
	"00:15:5d": "Microsoft Hyper-V", "00:1d:7e": "Cisco", "00:23:04": "Cisco",
	"f8:bc:12": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
	"00:17:88": "Philips Hue", "ec:fa:bc": "Amazon", "44:65:0d": "Amazon",
	"00:e0:4c": "Realtek", "d8:bb:c1": "Wistron", "00:25:90": "Supermicro",
	"0c:c4:7a": "Intel", "3c:97:0e": "Wistron", "a4:bb:6d": "HP",
	"00:1e:4f": "Fortinet", "00:09:0f": "Fortinet", "00:0d:b9": "PC Engines",
}

// OUIVendor resolves a MAC prefix to a vendor hint.
func OUIVendor(mac string) string {
	mac = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	return ouiVendorMap[strings.Join(parts[:3], ":")]
}
