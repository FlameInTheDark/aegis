DROP INDEX IF EXISTS idx_software_osv_pending;
ALTER TABLE software DROP COLUMN IF EXISTS osv_queried_at;
ALTER TABLE software DROP COLUMN IF EXISTS osv_status;
