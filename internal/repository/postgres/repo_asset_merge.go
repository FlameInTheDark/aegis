package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// MergeAssets folds a duplicate asset into the canonical one and deletes the
// duplicate, in a single transaction. It is the cleanup half of identity
// convergence: when a device adopts its machine's original asset (created by
// a scan) the abandoned duplicate must not stay behind presenting itself as
// a second device.
//
// Every inventory-bearing table moves with conflict-aware upserts — the
// duplicate's observations merge into whatever the target already holds
// instead of colliding:
//   - asset_identifiers, mac_addresses, software: upsert, last_seen keeps
//     the fresher value, identifiers keep the heavier weight,
//   - network_interfaces: an interface whose MAC already exists on the
//     target donates its addresses to the target's interface; distinct
//     interfaces are re-keyed,
//   - services: re-keyed unless the target already lists the same
//     protocol/port (the target's row stays; the duplicate's dies),
//   - findings: re-pointed to the target's equivalent service/software row
//     first, then re-keyed; exact duplicates of the dedup triple
//     (asset, cve, service) are dropped in favor of the target's row,
//   - group memberships: joined, never duplicated,
//   - devices still bound to the duplicate are re-bound to the target.
//
// Scan history (scan_changes) references assets without a foreign key, so
// the final DELETE leaves the change log intact; asset topology overrides
// fall back to NULL by their own ON DELETE SET NULL rule. Tags, risk and
// classification columns belong to the target — the duplicate's copies are
// discarded, and the endpoint's authoritative data re-lands on the target
// through the normal inventory application right after the merge.
func (r *AssetRepo) MergeAssets(ctx context.Context, orphanID, targetID string) error {
	if orphanID == "" || targetID == "" {
		return fmt.Errorf("postgres: asset merge needs both a duplicate and a target id")
	}
	if orphanID == targetID {
		return fmt.Errorf("postgres: asset merge target must differ from the duplicate")
	}
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		const (
			orphan = "$1"
			target = "$2"
		)
		stmts := []string{
			// Identity identifiers: the duplicate's hostname, addresses and
			// hardware ids keep resolving — to the canonical asset now.
			`INSERT INTO asset_identifiers (id, asset_id, type, value, weight, created_at)
			 SELECT gen_random_uuid(), ` + target + `, type, value, weight, created_at
			 FROM asset_identifiers WHERE asset_id = ` + orphan + `
			 ON CONFLICT (asset_id, type, value) DO UPDATE
			 SET weight = GREATEST(asset_identifiers.weight, EXCLUDED.weight)`,

			// Interface addresses whose owning MAC already exists on the
			// target: donate the address rows to the target's interface.
			// The empty MAC ("") counts as a match only between two macless
			// interfaces — the endpoint path converges those on a single
			// anonymous row per asset.
			`INSERT INTO ip_addresses (id, interface_id, ip, is_primary, first_seen, last_seen)
			 SELECT gen_random_uuid(), t.id, s.ip, s.is_primary, s.first_seen, s.last_seen
			 FROM ip_addresses s
			 JOIN network_interfaces o ON o.id = s.interface_id AND o.asset_id = ` + orphan + `
			 JOIN network_interfaces t ON t.asset_id = ` + target + ` AND t.mac = o.mac
			 ON CONFLICT (interface_id, ip) DO UPDATE
			 SET last_seen = GREATEST(ip_addresses.last_seen, EXCLUDED.last_seen),
			     is_primary = ip_addresses.is_primary OR EXCLUDED.is_primary`,

			// Re-key interfaces whose MAC the target does not have yet.
			`UPDATE network_interfaces o SET asset_id = ` + target + `
			 WHERE o.asset_id = ` + orphan + ` AND o.mac <> ''
			   AND NOT EXISTS (SELECT 1 FROM network_interfaces t
			                   WHERE t.asset_id = ` + target + ` AND t.mac = o.mac)`,

			// The macless anonymous interface re-keys only when the target
			// has none; otherwise its addresses already moved above and the
			// row dies with the asset.
			`UPDATE network_interfaces o SET asset_id = ` + target + `
			 WHERE o.asset_id = ` + orphan + ` AND o.mac = ''
			   AND NOT EXISTS (SELECT 1 FROM network_interfaces t
			                   WHERE t.asset_id = ` + target + ` AND t.mac = '')`,

			// Hardware MAC observations.
			`INSERT INTO mac_addresses (id, asset_id, mac, vendor, first_seen, last_seen)
			 SELECT gen_random_uuid(), ` + target + `, mac, vendor, first_seen, last_seen
			 FROM mac_addresses WHERE asset_id = ` + orphan + `
			 ON CONFLICT (asset_id, mac) DO UPDATE
			 SET last_seen = GREATEST(mac_addresses.last_seen, EXCLUDED.last_seen),
			     vendor = COALESCE(NULLIF(mac_addresses.vendor, ''), EXCLUDED.vendor)`,

			// Services: re-key unless the target already lists the port.
			`UPDATE services o SET asset_id = ` + target + `
			 WHERE o.asset_id = ` + orphan + `
			   AND NOT EXISTS (SELECT 1 FROM services t
			                   WHERE t.asset_id = ` + target + `
			                     AND t.protocol = o.protocol AND t.port = o.port)`,

			// Findings tied to a service the target duplicates: re-point
			// them to the target's twin so the twin delete below cannot
			// cascade them away.
			`UPDATE findings f SET service_id = t.id
			 FROM services o, services t
			 WHERE f.service_id = o.id AND o.asset_id = ` + orphan + `
			   AND t.asset_id = ` + target + `
			   AND t.protocol = o.protocol AND t.port = o.port`,

			// Findings bound to the duplicate's software: re-point to the
			// target's equivalent package when one exists (after the
			// software merge below has produced every twin).
			`UPDATE findings f SET software_id = t.id
			 FROM software o, software t
			 WHERE f.software_id = o.id AND o.asset_id = ` + orphan + `
			   AND t.asset_id = ` + target + `
			   AND t.name = o.name AND t.version = o.version
			   AND t.ecosystem = o.ecosystem`,

			// Software: upsert onto the target.
			`INSERT INTO software (id, asset_id, name, version, vendor, ecosystem, purl, cpes, source, first_seen, last_seen)
			 SELECT gen_random_uuid(), ` + target + `, name, version, vendor, ecosystem, purl, cpes, source, first_seen, last_seen
			 FROM software WHERE asset_id = ` + orphan + `
			 ON CONFLICT (asset_id, name, version, ecosystem) DO UPDATE
			 SET last_seen = GREATEST(software.last_seen, EXCLUDED.last_seen)`,

			// Findings: re-key the ones whose dedup triple
			// (asset, cve, service) the target does not have yet — the same
			// NULL-safe key the idx_findings_dedup index enforces.
			`UPDATE findings f SET asset_id = ` + target + `
			 WHERE f.asset_id = ` + orphan + `
			   AND NOT EXISTS (SELECT 1 FROM findings t
			                   WHERE t.asset_id = ` + target + `
			                     AND COALESCE(t.cve_id, '') = COALESCE(f.cve_id, '')
			                     AND COALESCE(t.service_id::text, '') = COALESCE(f.service_id::text, ''))`,

			// Exact finding duplicates (same cve on the same service) stay
			// on the target's row; the duplicate's copy dies here so the
			// dedup index cannot reject the move above. Runs after the
			// re-key: whatever is left on the duplicate is redundant.
			`DELETE FROM findings WHERE asset_id = ` + orphan,

			// Group memberships: join, never duplicate.
			`INSERT INTO asset_group_members (group_id, asset_id, added_at)
			 SELECT group_id, ` + target + `, added_at
			 FROM asset_group_members WHERE asset_id = ` + orphan + `
			 ON CONFLICT (group_id, asset_id) DO NOTHING`,

			// Devices still bound to the duplicate follow the merge.
			`UPDATE agents SET asset_id = ` + target + ` WHERE asset_id = ` + orphan,

			// The duplicate itself. Cascades take the leftover rows
			// (duplicate-side interfaces, software, identifiers, findings);
			// scan_changes keeps its history — no foreign key.
			`DELETE FROM assets WHERE id = ` + orphan,
		}
		for _, stmt := range stmts {
			if _, err := tx.Exec(ctx, stmt, orphanID, targetID); err != nil {
				return fmt.Errorf("postgres: asset merge: %w", err)
			}
		}
		return nil
	})
}
