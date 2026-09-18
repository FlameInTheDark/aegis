ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS affected;
ALTER TABLE vulnerability_cpe_matches DROP COLUMN IF EXISTS version_type;
DROP TABLE IF EXISTS feed_meta;
