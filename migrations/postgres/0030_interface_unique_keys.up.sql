-- 0030: unique keys the interface/IP upserts always assumed.
--
-- InterfaceRepo.Upsert writes with ON CONFLICT (asset_id, mac) and AddIP
-- with ON CONFLICT (interface_id, ip), but 0003 created only plain indexes
-- on those column pairs. PostgreSQL rejects every such write with 42P10
-- ("there is no unique or exclusion constraint matching the ON CONFLICT
-- specification"), so network_interfaces and ip_addresses stayed empty for
-- the whole system: no MAC address, no NIC vendor and no observed address
-- ever reached the inventory UI, silently.
-- Backfill the missing unique indexes. The broken upserts mean few or no
-- rows are expected, but existing deployments may hold duplicates from
-- other writers — dedupe defensively (keep the oldest row, i.e. the
-- earliest first_seen) before the indexes go up.

DELETE FROM network_interfaces a
  USING network_interfaces b
  WHERE a.asset_id = b.asset_id
    AND a.mac = b.mac
    AND a.id > b.id;

DELETE FROM ip_addresses a
  USING ip_addresses b
  WHERE a.interface_id = b.interface_id
    AND a.ip = b.ip
    AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ifaces_asset_mac
    ON network_interfaces(asset_id, mac);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ips_iface_ip
    ON ip_addresses(interface_id, ip);
