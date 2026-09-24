DROP INDEX IF EXISTS idx_matches_status;
ALTER TABLE detection_matches DROP COLUMN IF EXISTS status;
