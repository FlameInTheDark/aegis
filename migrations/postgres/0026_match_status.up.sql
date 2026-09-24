-- Detection match triage (v1.13.0): analysts work the match queue — new,
-- investigating, contained, closed. The status rides on the match row with
-- per-row audit through the platform audit log at the handler layer.
ALTER TABLE detection_matches ADD COLUMN status TEXT NOT NULL DEFAULT 'new';
CREATE INDEX idx_matches_status ON detection_matches(organization_id, status);
