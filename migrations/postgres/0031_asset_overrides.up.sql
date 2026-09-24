-- 0031: analyst field overrides for assets.
--
-- Detection is occasionally wrong (a router fingerprinted as a
-- workstation). These columns hold the analyst's correction; they are
-- NEVER written by scan ingestion, so the scanned value stays intact in
-- its original column and clearing the override brings it back. NULL =
-- no override (the scanned value is authoritative and displayed).
--
-- The read path (repo scanAsset) applies the override onto the effective
-- Hostname/DeviceType fields, so every consumer — inventory, topology,
-- search — sees the override transparently, and the *_override fields
-- ride along in the JSON so the UI can badge the row and offer a reset.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS name_override TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_type_override TEXT;
