-- 0028: normalize scan_profiles.spec keys to snake_case.
--
-- ProfileDefinition previously serialized without json tags, so spec
-- snapshots stored PascalCase keys ("TopTCPPorts", "ServiceDetect", ...).
-- The struct now emits snake_case; old custom presets would unmarshal to
-- zero-values (blank names / lost knobs) without this one-time rewrite.
-- Built-in rows are re-seeded from the static registry at every boot, so
-- this migration primarily protects org-created presets.

UPDATE scan_profiles
SET spec = (
    SELECT jsonb_object_agg(
        CASE key
            WHEN 'Name'          THEN 'name'
            WHEN 'Description'   THEN 'description'
            WHEN 'HostDiscovery' THEN 'host_discovery'
            WHEN 'TopTCPPorts'   THEN 'top_tcp_ports'
            WHEN 'TopUDPPorts'   THEN 'top_udp_ports'
            WHEN 'FullPortScan'  THEN 'full_port_scan'
            WHEN 'ServiceDetect' THEN 'service_detect'
            WHEN 'ServiceLite'   THEN 'service_lite'
            WHEN 'OSDetect'      THEN 'os_detect'
            WHEN 'Traceroute'    THEN 'traceroute'
            WHEN 'SafeNSE'       THEN 'safe_nse'
            WHEN 'ZgrabEnrich'   THEN 'zgrab_enrich'
            WHEN 'SafeValidation' THEN 'safe_validation'
            WHEN 'ElevatedReqs'  THEN 'elevated_reqs'
            WHEN 'SSHCollect'    THEN 'ssh_collect'
            WHEN 'MaxTargets'    THEN 'max_targets'
            WHEN 'MaxPacketRate' THEN 'max_packet_rate'
            WHEN 'Warning'       THEN 'warning'
            ELSE key
        END,
        value
    )
    FROM jsonb_each(spec)
)
WHERE spec ?| array['Name','Description','HostDiscovery','TopTCPPorts','TopUDPPorts',
                    'FullPortScan','ServiceDetect','ServiceLite','OSDetect','Traceroute',
                    'SafeNSE','ZgrabEnrich','SafeValidation','ElevatedReqs','SSHCollect',
                    'MaxTargets','MaxPacketRate','Warning'];
