DROP INDEX IF EXISTS uq_scanners_connector;
ALTER TABLE scanners DROP COLUMN IF EXISTS connector_id;
