ALTER TABLE connectors DROP COLUMN IF EXISTS shutdown_at;
-- Backfilled scanner rows (transport=connector) cannot be told apart from
-- enrollment-materialized ones; dropping the column is the reversible part.
