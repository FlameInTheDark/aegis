-- Findings dedup identity must include the advisory (osv_id) and software
-- package (software_id) dimensions. The previous key (asset, cve, service)
-- collided whenever several packages on one asset were affected by the same
-- CVE (service_id NULL -> identical key) and whenever two distinct non-CVE
-- OSV advisories hit the same asset (cve_id NULL -> identical key): the
-- upsert silently overwrote the earlier finding, losing remediation detail
-- and skewing counts. The ON CONFLICT clause in FindingRepo.Upsert already
-- targets the new identity, so without this index every upsert would fail
-- with "no unique or exclusion constraint matching".
--
-- Collapse existing duplicates first, keeping one row per identity: the
-- most recently seen (last_seen, id) wins, mirroring what re-observation
-- would have refreshed anyway. Status/evidence history of dropped rows is
-- intentionally discarded; finding_status_history rows of deleted findings
-- are removed with them.

DELETE FROM findings a
USING findings b
WHERE a.asset_id = b.asset_id
  AND COALESCE(a.cve_id, '') = COALESCE(b.cve_id, '')
  AND COALESCE(a.osv_id, '') = COALESCE(b.osv_id, '')
  AND COALESCE(a.service_id::text, '') = COALESCE(b.service_id::text, '')
  AND COALESCE(a.software_id::text, '') = COALESCE(b.software_id::text, '')
  AND (a.last_seen, a.id) < (b.last_seen, b.id);

DROP INDEX IF EXISTS idx_findings_dedup;

CREATE UNIQUE INDEX idx_findings_dedup ON findings
    (asset_id, COALESCE(cve_id, ''), COALESCE(osv_id, ''),
     COALESCE(service_id::text, ''), COALESCE(software_id::text, ''));
