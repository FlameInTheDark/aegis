-- 0011: asset identity repair.
--
-- asset_identifiers was designed to upsert on (asset_id, type, value)
-- (see IdentifierRepo.Upsert), but migration 0003 only created non-unique
-- indexes. Postgres rejects every ON CONFLICT insert without a matching
-- unique constraint, the scanner swallows the error, identifiers never
-- persisted and every scan forked the same devices into new asset rows.
--
-- Backfill: drop duplicate identifier rows (if any predate this fix), then
-- add the constraint the upsert always assumed.

DELETE FROM asset_identifiers a
USING asset_identifiers b
WHERE a.id > b.id
  AND a.asset_id = b.asset_id
  AND a.type = b.type
  AND a.value = b.value;

CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_ident_asset_type_value
    ON asset_identifiers(asset_id, type, value);

-- Substring search on identifier values (used by the global search and the
-- address-aware asset resolver's diagnostics).
CREATE INDEX IF NOT EXISTS idx_asset_ident_value_trgm
    ON asset_identifiers USING gin (value gin_trgm_ops);
