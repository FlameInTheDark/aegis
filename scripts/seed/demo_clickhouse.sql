-- Aegis ClickHouse demo events (spec §139).
-- Apply: clickhouse-client --queries-file scripts/seed/demo_clickhouse.sql
-- Matches migrations/clickhouse/001_schema.sql (aegis.security_events).

SET insert_deduplicate = 0;

-- 40 synthetic events over the last 48 hours spanning alerts/flows/dns/http/tls
-- for the demo org tenant. IPv6 type accepts IPv4-mapped values.
INSERT INTO aegis.security_events
(event_id, tenant_id, site_id, sensor_id, timestamp, event_type, source, schema_version, src_ip, src_port, dst_ip, dst_port, protocol, direction, severity, action, rule_id, rule_name, application, hostname, payload_meta, tags)
SELECT
  toUUID(hexToUUID('e' || lpad(right(number::String, 3), 3, '0') || '0000-0000-4000-8000-000000000000')),
  toUUID('00000000-0000-4000-8000-000000000001'),
  toUUID('00000000-0000-4000-8000-000000000010'),
  'suricata-hq',
  now() - INTERVAL number HOUR,
  multiIf(number % 5 = 0, 'alert', number % 5 = 1, 'flow', number % 5 = 2, 'dns', number % 5 = 3, 'http', 'tls'),
  'suricata',
  '1',
  toIPv6('192.168.10.' || toString(20 + (number % 40))),
  45000 + number % 1000,
  if(number % 5 = 0, toIPv6('203.0.113.9'), toIPv6('10.20.0.' || toString(1 + number % 20))),
  if(number % 5 = 0, 80, multiIf(number % 5 = 2, 53, number % 5 = 3, 80, number % 5 = 4, 443, 445)),
  'tcp',
  if(number % 5 = 0, 'inbound', 'outbound'),
  multiIf(number % 5 = 0, 'high', 'info'),
  if(number % 5 = 0, 'alert', 'allowed'),
  if(number % 5 = 0, '2027865', ''),
  if(number % 5 = 0, 'ET SCAN Suspicious inbound to port 445', ''),
  multiIf(number % 5 = 2, 'dns', number % 5 = 3, 'http', number % 5 = 4, 'tls', ''),
  if(number % 5 = 2, 'cdn.example.internal', if(number % 5 = 3, 'portal.demo.internal', '')),
  '{}',
  ['demo']
FROM numbers(40);

-- Note: generated UUIDs via hexToUUID may collide in exotic cases; for a demo
-- dataset re-running is safe due to the events' distinct timestamps.
