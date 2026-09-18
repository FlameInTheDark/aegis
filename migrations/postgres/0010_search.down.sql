-- 0010 down: remove trigram search indexes and the extension.

DROP INDEX IF EXISTS idx_vuln_refs_url_trgm;
DROP INDEX IF EXISTS idx_vulns_description_trgm;
DROP INDEX IF EXISTS idx_vulns_cve_id_trgm;
DROP EXTENSION IF EXISTS pg_trgm;
