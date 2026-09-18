-- 0011 down: drop the identifier unique constraint and trigram index.

DROP INDEX IF EXISTS idx_asset_ident_value_trgm;
DROP INDEX IF EXISTS uq_asset_ident_asset_type_value;
