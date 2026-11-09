-- Phones reach every node on their carrier's own WireGuard port (PLAN.md
-- M49): no public relay port is checked or kept any more.
DROP TABLE relay_ports;

-- A device exported with a relay has a `.conf` that dials a relay port
-- nothing serves now: it is stale until exported again (`list-peers` says
-- so, as for a device never exported), and it holds every released
-- address meanwhile, as one never exported does (PLAN.md #273).
UPDATE nodes SET exported_at = NULL
WHERE id IN (SELECT DISTINCT static_node_id FROM static_relay_peers);
