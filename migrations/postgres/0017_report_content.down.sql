ALTER TABLE reports DROP COLUMN IF EXISTS asset_id;
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_type_check;
ALTER TABLE reports ADD CONSTRAINT reports_type_check CHECK (type IN
    ('executive_security','technical_vulnerability','network_inventory','topology',
     'security_event','asset_risk','scan_comparison'));
