-- Restore the original three-column dedup identity. Note: rows collapsed by
-- the up migration cannot be resurrected; down is for environment teardown
-- parity, not data recovery.
DROP INDEX IF EXISTS idx_findings_dedup;

CREATE UNIQUE INDEX idx_findings_dedup ON findings
    (asset_id, COALESCE(cve_id, ''), COALESCE(service_id::text, ''));
