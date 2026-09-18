-- 0010: substring + content search for the CVE index (spec §67).
-- Users search by partial CVE ids ("CVE-2005-24"), description text and
-- reference URLs. pg_trgm GIN indexes make ILIKE '%substring%' fast over
-- hundreds of thousands of CVE rows without an external search engine.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_vulns_cve_id_trgm
    ON vulnerabilities USING gin (cve_id gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_vulns_description_trgm
    ON vulnerabilities USING gin (description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_vuln_refs_url_trgm
    ON vulnerability_references USING gin (url gin_trgm_ops);
