-- Feeds: carry a visible 'running' state so a multi-hour bootstrap (NVD full
-- pull, cvelistV5 archive ingest) is observable in GET /api/v1/feeds instead
-- of reading as an indefinite 'never_synced' with zero records.
ALTER TABLE feed_sources DROP CONSTRAINT feed_sources_last_status_check;
ALTER TABLE feed_sources ADD CONSTRAINT feed_sources_last_status_check
    CHECK (last_status IN ('healthy','stale','failed','never_synced','running'));
