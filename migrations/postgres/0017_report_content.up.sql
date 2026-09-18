-- 0017: report content extensions — per-asset reports, site-detail reports,
-- inventory statistics (spec §50, §138).

-- New report types: full site detail and per-device detail.
ALTER TABLE reports DROP CONSTRAINT reports_type_check;
ALTER TABLE reports ADD CONSTRAINT reports_type_check CHECK (type IN
    ('executive_security','technical_vulnerability','network_inventory','topology',
     'security_event','asset_risk','scan_comparison','site_detail','device_detail'));

-- Per-device report target.
ALTER TABLE reports ADD COLUMN asset_id UUID;


