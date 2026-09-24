-- 0028 (down): restore the PascalCase key spelling ProfileDefinition
-- serialized before the struct gained json tags. Data-preserving; only the
-- JSON key casing changes back.

UPDATE scan_profiles
SET spec = (
    SELECT jsonb_object_agg(
        CASE key
            WHEN 'name'            THEN 'Name'
            WHEN 'description'     THEN 'Description'
            WHEN 'host_discovery'  THEN 'HostDiscovery'
            WHEN 'top_tcp_ports'   THEN 'TopTCPPorts'
            WHEN 'top_udp_ports'   THEN 'TopUDPPorts'
            WHEN 'full_port_scan'  THEN 'FullPortScan'
            WHEN 'service_detect'  THEN 'ServiceDetect'
            WHEN 'service_lite'    THEN 'ServiceLite'
            WHEN 'os_detect'       THEN 'OSDetect'
            WHEN 'traceroute'      THEN 'Traceroute'
            WHEN 'safe_nse'        THEN 'SafeNSE'
            WHEN 'zgrab_enrich'    THEN 'ZgrabEnrich'
            WHEN 'safe_validation' THEN 'SafeValidation'
            WHEN 'elevated_reqs'   THEN 'ElevatedReqs'
            WHEN 'ssh_collect'     THEN 'SSHCollect'
            WHEN 'max_targets'     THEN 'MaxTargets'
            WHEN 'max_packet_rate' THEN 'MaxPacketRate'
            WHEN 'warning'         THEN 'Warning'
            ELSE key
        END,
        value
    )
    FROM jsonb_each(spec)
)
WHERE spec ?| array['name','description','host_discovery','top_tcp_ports','top_udp_ports',
                    'full_port_scan','service_detect','service_lite','os_detect','traceroute',
                    'safe_nse','zgrab_enrich','safe_validation','elevated_reqs','ssh_collect',
                    'max_targets','max_packet_rate','warning'];
