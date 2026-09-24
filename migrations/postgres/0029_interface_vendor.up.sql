-- 0029: MAC hardware vendor on network interfaces.
--
-- nmap resolves the OUI vendor of on-link MAC addresses (address@vendor in
-- the XML) but the pipeline dropped it: interfaces stored only the MAC, so
-- the inventory could never show which hardware a host's NIC came from.
-- The vendor rides the host_up observation now and lands here, next to the
-- MAC it describes. Empty for interfaces discovered without vendor evidence
-- (agent-reported, IP-only observations).
ALTER TABLE network_interfaces ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT '';
