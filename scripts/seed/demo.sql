-- Aegis demo dataset (spec §139). Idempotent; tags demo rows with demo_source.
-- Apply: psql "$AEGIS_DATABASE_URL" -f scripts/seed/demo.sql
-- Requires: migrations applied (server does this on first boot).

-- Fixed demo ids (uuid-shaped, satisfy uuid columns; swap to gen_random_uuid() if your schema differs).
\set ORG '00000000-0000-4000-8000-000000000001'
\set USER '00000000-0000-4000-8000-000000000002'
\set SITE_HQ '00000000-0000-4000-8000-000000000010'
\set SITE_DC '00000000-0000-4000-8000-000000000011'
\set SITE_BR '00000000-0000-4000-8000-000000000012'

INSERT INTO organizations (id, name, slug, created_at, updated_at)
VALUES (:'ORG', 'Demo Organization', 'demo', now(), now())
ON CONFLICT (id) DO NOTHING;

-- argon2id hash of 'aegis-demo-admin-2026'
INSERT INTO users (id, email, name, password_hash, created_at, updated_at)
VALUES (:'USER', 'admin@aegis.local', 'Demo Administrator',
        '$argon2id$v=19$m=65536,t=3,p=2$oftbOjf371hRcZli5bWphQ$M+HmPBqG/lp6wGu/0gOG7fnQR0EgwIwsjaO8tlAEot8',
        now(), now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO memberships (id, user_id, organization_id, role, created_at)
VALUES (gen_random_uuid(), :'USER', :'ORG', 'owner', now())
ON CONFLICT DO NOTHING;

INSERT INTO sites (id, organization_id, name, site_type, description, created_at, updated_at) VALUES
 (:'SITE_HQ', :'ORG', 'HQ', 'hq', 'Headquarters office LAN', now(), now()),
 (:'SITE_DC', :'ORG', 'Datacenter', 'datacenter', 'Primary datacenter', now(), now()),
 (:'SITE_BR', :'ORG', 'Branch Office', 'branch', 'Remote branch', now(), now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO networks (id, site_id, organization_id, cidr, name, vlan_id, exposure, created_at, updated_at) VALUES
 (gen_random_uuid(), :'SITE_HQ', :'ORG', '192.168.10.0/24', 'corp', 10, 'internal_only', now(), now()),
 (gen_random_uuid(), :'SITE_HQ', :'ORG', '192.168.20.0/24', 'guest', 20, 'internal_only', now(), now()),
 (gen_random_uuid(), :'SITE_DC', :'ORG', '10.20.0.0/24', 'server-farm', 30, 'internal_only', now(), now()),
 (gen_random_uuid(), :'SITE_BR', :'ORG', '192.168.50.0/24', 'branch-lan', 50, 'internal_only', now(), now())
ON CONFLICT DO NOTHING;

-- Assets: router, switch, firewall, servers, workstations, laptop, printer, camera, NAS, IoT, hypervisor.
INSERT INTO assets (id, organization_id, site_id, hostname, device_type, os_family, os_name, os_version, os_confidence, os_sources, device_type_confidence, exposure, criticality, risk_score, has_agent, demo_source, first_seen, last_seen, updated_at) VALUES
 ('10000000-0000-4000-8000-000000000101', :'ORG', :'SITE_DC', 'edge-fw', 'firewall', 'linux', 'pfSense', '2.7', 0.9, ARRAY['nmap','mac_vendor'], 0.9, 'publicly_reachable', 'critical', 78, false, true, now()-interval '30 days', now()-interval '1 hours', now()),
 ('10000000-0000-4000-8000-000000000102', :'ORG', :'SITE_HQ', 'gw-hq', 'router', 'linux', 'MikroTik RouterOS', '7.14', 0.85, ARRAY['nmap'], 0.85, 'internal_only', 'critical', 42, false, true, now()-interval '30 days', now()-interval '2 hours', now()),
 ('10000000-0000-4000-8000-000000000103', :'ORG', :'SITE_HQ', 'sw-hq-1', 'switch', 'other', 'Cisco IOS', '15.2', 0.7, ARRAY['snmp','mac_vendor'], 0.9, 'internal_only', 'high', 25, false, true, now()-interval '28 days', now()-interval '3 hours', now()),
 ('10000000-0000-4000-8000-000000000104', :'ORG', :'SITE_DC', 'web-01', 'server', 'linux', 'Ubuntu Server', '24.04', 0.96, ARRAY['endpoint_agent','nmap'], 0.98, 'publicly_reachable', 'critical', 88, true, true, now()-interval '25 days', now()-interval '20 minutes', now()),
 ('10000000-0000-4000-8000-000000000105', :'ORG', :'SITE_DC', 'db-01', 'server', 'linux', 'Debian', '12', 0.95, ARRAY['endpoint_agent'], 0.95, 'internal_only', 'critical', 61, true, true, now()-interval '25 days', now()-interval '20 minutes', now()),
 ('10000000-0000-4000-8000-000000000106', :'ORG', :'SITE_DC', 'esx-01', 'hypervisor', 'linux', 'VMware ESXi', '8.0', 0.8, ARRAY['nmap'], 0.9, 'internal_only', 'critical', 70, false, true, now()-interval '20 days', now()-interval '4 hours', now()),
 ('10000000-0000-4000-8000-000000000107', :'ORG', :'SITE_HQ', 'ws-fin-01', 'workstation', 'windows', 'Windows 11 Pro', '23H2', 0.97, ARRAY['endpoint_agent'], 0.97, 'internal_only', 'medium', 35, true, true, now()-interval '18 days', now()-interval '15 minutes', now()),
 ('10000000-0000-4000-8000-000000000108', :'ORG', :'SITE_HQ', 'ws-hr-02', 'workstation', 'windows', 'Windows 10 Pro', '22H2', 0.97, ARRAY['endpoint_agent'], 0.97, 'internal_only', 'medium', 30, true, true, now()-interval '18 days', now()-interval '40 minutes', now()),
 ('10000000-0000-4000-8000-000000000109', :'ORG', :'SITE_HQ', 'lap-srv-01', 'laptop', 'darwin', 'macOS Sonoma', '14.6', 0.95, ARRAY['endpoint_agent'], 0.95, 'vpn_only', 'medium', 28, true, true, now()-interval '10 days', now()-interval '2 hours', now()),
 ('10000000-0000-4000-8000-000000000110', :'ORG', :'SITE_HQ', 'prn-recep', 'printer', 'other', 'HP LaserJet', '', 0.6, ARRAY['banner'], 0.8, 'internal_only', 'low', 15, false, true, now()-interval '15 days', now()-interval '6 hours', now()),
 ('10000000-0000-4000-8000-000000000111', :'ORG', :'SITE_HQ', 'cam-park-1', 'camera', 'linux', 'Dahua firmware', '', 0.55, ARRAY['banner','mac_vendor'], 0.75, 'internal_only', 'medium', 44, false, true, now()-interval '12 days', now()-interval '1 hours', now()),
 ('10000000-0000-4000-8000-000000000112', :'ORG', :'SITE_DC', 'nas-01', 'nas', 'linux', 'Synology DSM', '7.2', 0.85, ARRAY['banner'], 0.9, 'internal_only', 'high', 52, false, true, now()-interval '22 days', now()-interval '2 hours', now()),
 ('10000000-0000-4000-8000-000000000113', :'ORG', :'SITE_BR', 'iot-thermo', 'iot', 'linux', 'Embedded', '', 0.4, ARRAY['banner'], 0.6, 'internal_only', 'low', 20, false, true, now()-interval '9 days', now()-interval '8 hours', now())
ON CONFLICT (id) DO NOTHING;

-- Services (observed endpoints). CPEs align with the demo vulnerabilities.
INSERT INTO services (id, asset_id, organization_id, protocol, port, service_name, product, vendor, detected_version, version_confidence, cpes, banner, sources, confidence, exposure, state, first_seen, last_seen) VALUES
 ('20000000-0000-4000-8000-000000000201', '10000000-0000-4000-8000-000000000104', :'ORG', 'tcp', 443, 'https', 'nginx', 'nginx', '1.24.0', 0.93, ARRAY['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'], 'Server: nginx/1.24.0', ARRAY['nmap','http'], 0.93, 'publicly_reachable', 'open', now()-interval '25 days', now()-interval '20 minutes'),
 ('20000000-0000-4000-8000-000000000202', '10000000-0000-4000-8000-000000000104', :'ORG', 'tcp', 22, 'ssh', 'OpenSSH', 'OpenBSD', '9.6p1', 0.95, ARRAY['cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'], 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', ARRAY['nmap'], 0.95, 'internal_only', 'open', now()-interval '25 days', now()-interval '20 minutes'),
 ('20000000-0000-4000-8000-000000000203', '10000000-0000-4000-8000-000000000105', :'ORG', 'tcp', 5432, 'postgresql', 'PostgreSQL', 'PostgreSQL', '15.7', 0.9, ARRAY['cpe:2.3:a:postgresql:postgresql:15.7:*:*:*:*:*:*:*'], '', ARRAY['nmap','endpoint_agent'], 0.9, 'internal_only', 'open', now()-interval '25 days', now()-interval '20 minutes'),
 ('20000000-0000-4000-8000-000000000204', '10000000-0000-4000-8000-000000000107', :'ORG', 'tcp', 3389, 'rdp', 'Microsoft Terminal Services', 'microsoft', '', 0, ARRAY[]::text[], '', ARRAY['nmap'], 0.8, 'internal_only', 'open', now()-interval '18 days', now()-interval '15 minutes'),
 ('20000000-0000-4000-8000-000000000205', '10000000-0000-4000-8000-000000000107', :'ORG', 'tcp', 445, 'smb', '', '', '', 0, ARRAY[]::text[], '', ARRAY['nmap'], 0.7, 'internal_only', 'open', now()-interval '18 days', now()-interval '15 minutes'),
 ('20000000-0000-4000-8000-000000000206', '10000000-0000-4000-8000-000000000110', :'ORG', 'tcp', 23, 'telnet', '', '', '', 0, ARRAY[]::text[], 'HP JetDirect', ARRAY['nmap'], 0.9, 'internal_only', 'open', now()-interval '15 days', now()-interval '6 hours'),
 ('20000000-0000-4000-8000-000000000207', '10000000-0000-4000-8000-000000000112', :'ORG', 'udp', 161, 'snmp', 'Synology', 'synology', '', 0, ARRAY[]::text[], 'public', ARRAY['nmap'], 0.7, 'internal_only', 'open', now()-interval '22 days', now()-interval '2 hours'),
 ('20000000-0000-4000-8000-000000000208', '10000000-0000-4000-8000-000000000106', :'ORG', 'tcp', 443, 'https', 'VMware HTTP', 'vmware', '', 0, ARRAY[]::text[], '', ARRAY['nmap'], 0.7, 'internal_only', 'open', now()-interval '20 days', now()-interval '4 hours')
ON CONFLICT (id) DO NOTHING;

-- Software (agent inventory) aligned to ecosystems for OSV matching demos.
INSERT INTO software (id, asset_id, name, version, vendor, ecosystem, purl, source, first_seen, last_seen) VALUES
 ('30000000-0000-4000-8000-000000000301', '10000000-0000-4000-8000-000000000104', 'nginx', '1.24.0', 'nginx', 'os_debian', 'pkg:os_debian/nginx@1.24.0', 'dpkg', now()-interval '25 days', now()-interval '20 minutes'),
 ('30000000-0000-4000-8000-000000000302', '10000000-0000-4000-8000-000000000104', 'openssl', '3.0.13', 'openssl', 'os_debian', 'pkg:os_debian/openssl@3.0.13', 'dpkg', now()-interval '25 days', now()-interval '20 minutes'),
 ('30000000-0000-4000-8000-000000000303', '10000000-0000-4000-8000-000000000105', 'postgresql-15', '15.7-1', 'postgresql', 'os_debian', 'pkg:os_debian/postgresql-15@15.7-1', 'dpkg', now()-interval '25 days', now()-interval '20 minutes'),
 ('30000000-0000-4000-8000-000000000304', '10000000-0000-4000-8000-000000000107', 'google-chrome', '126.0.6478.126', 'google', 'winget', 'pkg:winget/google-chrome@126.0.6478.126', 'registry', now()-interval '18 days', now()-interval '15 minutes')
ON CONFLICT (id) DO NOTHING;

-- Vulnerability index (synthetic demo records with provenance; real feeds
-- overwrite/extend via the feed-worker).
INSERT INTO vulnerabilities (cve_id, state, published_at, updated_at, description, cvss_v3, cwe, source, source_record, ingested_at) VALUES
 ('CVE-2021-44228', 'PUBLISHED', '2021-12-10T10:15:00Z', now(), 'Apache Log4j2 JNDI remote code execution (Log4Shell).',
   '{"version":"3.1","score":10.0,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}'::jsonb, ARRAY['CWE-502','CWE-917'], 'demo', 'CVE-2021-44228', now()),
 ('CVE-2023-48795', 'PUBLISHED', '2023-12-18T10:15:00Z', now(), 'Terrapin: SSH channel integrity breach by sequence number manipulation.',
   '{"version":"3.1","score":5.9,"vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}'::jsonb, ARRAY['CWE-354'], 'demo', 'CVE-2023-48795', now()),
 ('CVE-2024-21762', 'PUBLISHED', '2024-02-08T10:15:00Z', now(), 'FortiOS out-of-bounds write allowing remote code execution.',
   '{"version":"3.1","score":9.8,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'::jsonb, ARRAY['CWE-787'], 'demo', 'CVE-2024-21762', now()),
 ('CVE-2023-4966', 'PUBLISHED', '2023-10-11T10:15:00Z', now(), 'Citrix NetScaler sensitive information disclosure (Citrix Bleed).',
   '{"version":"3.1","score":9.4,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}'::jsonb, ARRAY['CWE-200'], 'demo', 'CVE-2023-4966', now()),
 ('CVE-2021-34527', 'PUBLISHED', '2021-07-01T10:15:00Z', now(), 'Windows Print Spooler remote code execution (PrintNightmare).',
   '{"version":"3.1","score":8.8,"vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}'::jsonb, ARRAY['CWE-269'], 'demo', 'CVE-2021-34527', now()),
 ('CVE-2023-44487', 'PUBLISHED', '2023-10-10T10:15:00Z', now(), 'HTTP/2 Rapid Reset denial of service.',
   '{"version":"3.1","score":7.5,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}'::jsonb, ARRAY['CWE-400'], 'demo', 'CVE-2023-44487', now())
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO vulnerability_kev (cve_id, known_exploited, date_added, source, ingested_at)
VALUES ('CVE-2021-44228', true, '2021-12-11', 'demo', now()),
       ('CVE-2021-34527', true, '2021-07-02', 'demo', now()),
       ('CVE-2023-4966', true, '2023-10-18', 'demo', now()),
       ('CVE-2024-21762', true, '2024-02-09', 'demo', now())
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO vulnerability_epss (cve_id, date, epss, percentile, source, ingested_at)
VALUES ('CVE-2021-44228', to_char(now(),'YYYY-MM-DD')::date, 0.975, 0.999, 'demo', now()),
       ('CVE-2023-44487', to_char(now(),'YYYY-MM-DD')::date, 0.81, 0.97, 'demo', now())
ON CONFLICT (cve_id, date) DO NOTHING;

INSERT INTO vulnerability_cpe_matches (id, cve_id, cpe, vendor, product, version) VALUES
 (gen_random_uuid(), 'CVE-2021-44228', 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', 'apache', 'log4j', '2.14.1'),
 (gen_random_uuid(), 'CVE-2023-48795', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', 'openbsd', 'openssh', '')
ON CONFLICT (id) DO NOTHING;

INSERT INTO vulnerability_references (id, cve_id, url) VALUES
 (gen_random_uuid(), 'CVE-2021-44228', 'https://logging.apache.org/log4j/2.x/security.html'),
 (gen_random_uuid(), 'CVE-2023-48795', 'https://terrapin-attack.com/'),
 (gen_random_uuid(), 'CVE-2024-21762', 'https://www.fortiguard.com/psirt')
ON CONFLICT (id) DO NOTHING;

-- Findings: potential/confirmed matches with risk + evidence.
INSERT INTO findings (id, organization_id, asset_id, service_id, cve_id, title, match_type, confidence, risk_score, severity, status, remediation, first_seen, last_seen, created_at, updated_at) VALUES
 ('40000000-0000-4000-8000-000000000401', :'ORG', '10000000-0000-4000-8000-000000000104', '20000000-0000-4000-8000-000000000202', 'CVE-2023-48795', 'Terrapin: SSH channel integrity breach by sequence number manipulation.', 'EXACT_CPE', 0.85, 58, 'high', 'open', 'Upgrade OpenSSH to a patched release (9.9+).', now()-interval '5 days', now()-interval '1 hours', now()-interval '5 days', now()-interval '1 hours'),
 ('40000000-0000-4000-8000-000000000402', :'ORG', '10000000-0000-4000-8000-000000000107', '20000000-0000-4000-8000-000000000205', 'CVE-2021-34527', 'Windows Print Spooler remote code execution (PrintNightmare).', 'HEURISTIC', 0.4, 66, 'high', 'acknowledged', 'Verify Print Spooler exposure; apply Microsoft patches.', now()-interval '12 days', now()-interval '2 hours', now()-interval '12 days', now()-interval '2 hours'),
 ('40000000-0000-4000-8000-000000000403', :'ORG', '10000000-0000-4000-8000-000000000106', '20000000-0000-4000-8000-000000000208', 'CVE-2023-44487', 'HTTP/2 Rapid Reset denial of service.', 'SERVICE_VERSION', 0.6, 47, 'medium', 'in_progress', 'Update ESXi to a release with HTTP/2 mitigations.', now()-interval '3 days', now()-interval '4 hours', now()-interval '3 days', now()-interval '4 hours')
ON CONFLICT (id) DO NOTHING;

INSERT INTO finding_evidence (id, finding_id, kind, statement, detail, source, created_at) VALUES
 ('50000000-0000-4000-8000-000000000501', '40000000-0000-4000-8000-000000000401', 'banner', 'SSH banner observed: OpenSSH_9.6p1 (version inside Terrapin-affected range)', '{"banner":"SSH-2.0-OpenSSH_9.6p1"}'::jsonb, 'banner', now()-interval '5 days'),
 ('50000000-0000-4000-8000-000000000502', '40000000-0000-4000-8000-000000000402', 'heuristic', 'SMB service on Windows workstation; PrintNightmare class applies to exposed spooler (potential, not confirmed)', '{}'::jsonb, 'heuristic', now()-interval '12 days')
ON CONFLICT (id) DO NOTHING;

-- Detection rules + a couple of matches.
INSERT INTO detection_rules (id, organization_id, title, identifier, status, description, author, level, type, event_type, threshold, window_spec, group_by, enabled, created_at, updated_at) VALUES
 ('60000000-0000-4000-8000-000000000601', :'ORG', 'Port scan pattern', 'aegis-portscan-01', 'stable', 'One source contacting many distinct destination ports in a short window.', 'aegis', 'medium', 'threshold', 'flow', '{"count":40,"distinct":"dst_port"}'::jsonb, '60s', ARRAY['src_ip'], true, now(), now()),
 ('60000000-0000-4000-8000-000000000602', :'ORG', 'SMB lateral movement pattern', 'aegis-smb-lateral-01', 'stable', 'Asset contacting many distinct internal hosts on SMB-like traffic.', 'aegis', 'high', 'entity_agg', 'flow', '{"count":30,"distinct":"dst_ip"}'::jsonb, '5m', ARRAY['src_ip'], true, now(), now()),
 ('60000000-0000-4000-8000-000000000603', :'ORG', 'Abnormal DNS volume', 'aegis-dns-volume-01', 'experimental', 'Unusually high DNS query volume from one source.', 'aegis', 'medium', 'threshold', 'dns', '{"count":120}'::jsonb, '1m', ARRAY['src_ip'], true, now(), now()),
 ('60000000-0000-4000-8000-000000000604', :'ORG', 'Critical IDS alert', 'aegis-ids-critical-01', 'stable', 'High or critical severity IDS alert from Suricata/Snort.', 'aegis', 'high', 'single_event', 'alert', NULL, '', ARRAY[]::text[], true, now(), now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO detection_matches (id, organization_id, rule_id, rule_title, level, site_id, asset_id, src_ip, entity, summary, event_ids, count, timestamp) VALUES
 ('70000000-0000-4000-8000-000000000701', :'ORG', '60000000-0000-4000-8000-000000000601', 'Port scan pattern', 'medium', :'SITE_HQ', NULL, '203.0.113.77', '203.0.113.77', 'Port scan pattern — 42 events across distinct ports (demo)', ARRAY[]::text[], 42, now()-interval '2 hours'),
 ('70000000-0000-4000-8000-000000000702', :'ORG', '60000000-0000-4000-8000-000000000603', 'Abnormal DNS volume', 'medium', :'SITE_HQ', NULL, '192.168.10.140', '192.168.10.140', 'Abnormal DNS volume — 148 queries in 1m (demo)', ARRAY[]::text[], 148, now()-interval '90 minutes')
ON CONFLICT (id) DO NOTHING;

-- Audit trail + feed sources + a report definition.
INSERT INTO audit_logs (id, organization_id, actor_id, action, target, result, detail, created_at) VALUES
 (gen_random_uuid(), :'ORG', :'USER', 'scan.created', 'demo-nightly-scan', 'success', '{"profile":"inventory","targets":["192.168.10.0/24"]}'::jsonb, now()-interval '1 days'),
 (gen_random_uuid(), :'ORG', :'USER', 'finding.status_changed', '40000000-0000-4000-8000-000000000402', 'success', '{"to":"acknowledged","reason":"verified on isolated VLAN"}'::jsonb, now()-interval '2 hours')
ON CONFLICT DO NOTHING;

INSERT INTO feed_sources (name, enabled, last_sync_at, last_status, records_ingested, license) VALUES
 ('nvd', true, now()-interval '3 hours', 'healthy', 287431, 'NVD public domain (NIST); CVE data under CVE TOU'),
 ('kev', true, now()-interval '3 hours', 'healthy', 1290, 'U.S. Government public domain (CISA)'),
 ('epss', true, now()-interval '3 hours', 'healthy', 243117, 'FIRST EPSS, CC-BY (attribution required)'),
 ('osv', true, NULL, 'never_synced', 0, 'Apache-2.0 / ODC-By')
ON CONFLICT (name) DO NOTHING;

-- Demo note: events live in ClickHouse — apply scripts/seed/demo_clickhouse.sql
-- with clickhouse-client. This file is demo data only; demo_source=true marks
-- simulated records so they are never confused with production observations.
