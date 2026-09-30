-- Investigation queue (F2 first slice): analysts get a personal, dated work
-- queue instead of browsing undifferentiated tables.
--
-- findings.due_date: a triage deadline on the finding. Stored NULL until an
-- operator sets one; "overdue" is derived (due_date < now() AND status still
-- active) and never guessed by the correlation plane.
ALTER TABLE findings ADD COLUMN due_date TIMESTAMPTZ;
CREATE INDEX idx_findings_due_date ON findings(organization_id, due_date)
    WHERE due_date IS NOT NULL;

-- detection_matches.assignee: matches had a triage status but no owner, so
-- the same "my queue" filter could not exist on the Detections screen. Empty
-- string keeps the unassigned default (matching findings.owner).
ALTER TABLE detection_matches ADD COLUMN assignee TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_matches_assignee ON detection_matches(organization_id, assignee);
