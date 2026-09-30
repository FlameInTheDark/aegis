-- F5 (destinations beyond webhooks): email destinations need per-kind
-- non-secret settings (SMTP host/port, from, recipients). The SMTP password
-- rides the existing secret column, so masking and rotation are inherited.
ALTER TABLE alert_destinations ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb;
