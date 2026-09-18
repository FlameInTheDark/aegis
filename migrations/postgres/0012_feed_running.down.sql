ALTER TABLE feed_sources DROP CONSTRAINT feed_sources_last_status_check;
ALTER TABLE feed_sources ADD CONSTRAINT feed_sources_last_status_check
    CHECK (last_status IN ('healthy','stale','failed','never_synced'));
