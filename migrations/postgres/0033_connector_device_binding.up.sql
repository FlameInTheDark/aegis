-- 0033 (v1.24.0): connector-only enrollment. The standalone agent
-- enrollment protocol (aeg_enroll_* tokens + AgentService.Enroll) is
-- removed; endpoint devices are now agent-kind CONNECTORS that call
-- ConnectorService.BindDevice with the connector secret. The agents table
-- remains the device record (tasks, events, asset link, certificate
-- metadata) but gains a 1:1 binding to the connector that owns it.

ALTER TABLE agents ADD COLUMN connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX idx_agents_connector ON agents(connector_id) WHERE connector_id IS NOT NULL;

-- The old standalone enrollment token table is dead: its issue/list API
-- and the AgentService.Enroll RPC are removed in the same release.
DROP TABLE IF EXISTS enrollment_tokens;
