-- F14: per-row advisory query status so "queried, clean" is evidence
-- (absence of a finding after a real query), not ignorance.
ALTER TABLE software ADD COLUMN IF NOT EXISTS osv_status TEXT NOT NULL DEFAULT 'not_queried';
ALTER TABLE software ADD COLUMN IF NOT EXISTS osv_queried_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_software_osv_pending ON software (ecosystem, name) WHERE osv_status = 'not_queried' AND purl <> '';
