DROP INDEX IF EXISTS idx_matches_assignee;
ALTER TABLE detection_matches DROP COLUMN IF EXISTS assignee;
DROP INDEX IF EXISTS idx_findings_due_date;
ALTER TABLE findings DROP COLUMN IF EXISTS due_date;
