DROP TABLE IF EXISTS org_integrations;
ALTER TABLE findings DROP COLUMN IF EXISTS external_synced_at;
ALTER TABLE findings DROP COLUMN IF EXISTS external_url;
ALTER TABLE findings DROP COLUMN IF EXISTS external_key;
ALTER TABLE findings DROP COLUMN IF EXISTS external_tracker;
