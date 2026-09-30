-- F13: control_posture report type. The reports.type CHECK is replaced by
-- every new type (pattern from 0017_report_content).
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_type_check;
ALTER TABLE reports ADD CONSTRAINT reports_type_check CHECK (
    type IN ('executive_security', 'technical_vulnerability', 'network_inventory',
             'topology', 'security_event', 'asset_risk', 'scan_comparison',
             'site_detail', 'device_detail', 'control_posture')
);
