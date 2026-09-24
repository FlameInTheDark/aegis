-- 0030 down: drop the interface/IP unique indexes.

DROP INDEX IF EXISTS uq_ips_iface_ip;
DROP INDEX IF EXISTS uq_ifaces_asset_mac;
