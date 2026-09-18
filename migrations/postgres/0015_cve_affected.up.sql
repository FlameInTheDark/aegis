-- 0015: CVE affected products — parse and store the CVE List v5
-- containers.cna.affected statement (vendor/product/defaultStatus/versions
-- with ranges, statuses and versionType) and make CPE matches version-type
-- aware so range matching uses the right ordering rules.
--
-- Also adds a tiny feed_meta KV store; the cvelistv5 job records its ingest
-- schema version there and force-rebootstraps the corpus once after parser
-- upgrades (old rows were ingested with collapsed/missing range bounds).

ALTER TABLE vulnerabilities
    ADD COLUMN affected JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE vulnerability_cpe_matches
    ADD COLUMN version_type TEXT NOT NULL DEFAULT '';

CREATE TABLE feed_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
