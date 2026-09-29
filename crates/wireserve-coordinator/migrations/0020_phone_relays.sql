-- Phones reach every node end to end (PLAN.md M40, M41).
--
-- The gateway forwarded a phone's mesh traffic hop by hop, reading it;
-- that is gone. What a static peer's export still records:
--
-- `exit_node_id` (was `gateway_node_id`): the node its full-tunnel profile
-- sends everything to (M27) — which an exit necessarily reads. Only kept
-- where the last export rendered one; a mesh-only device routes through
-- nobody now.
ALTER TABLE nodes RENAME COLUMN gateway_node_id TO exit_node_id;
UPDATE nodes SET exit_node_id = NULL WHERE exit_enabled = 0;
UPDATE nodes SET exit_enabled = 0 WHERE exit_node_id IS NULL;

-- `via-gateway` and the conf membership that derived hop-by-hop routes from
-- it go with the gateway.
ALTER TABLE nodes DROP COLUMN export_via_gateway;
DROP TABLE static_conf_peers;

-- When the device's `.conf` was last written: a node that joined later
-- isn't in it (`list-peers` says the device is stale).
ALTER TABLE nodes ADD COLUMN exported_at TIMESTAMP;

-- The nodes a device reaches through a carrier's public relay port, and
-- which carrier: the carrier forwards exactly these, since the device's
-- `.conf` names exactly these.
CREATE TABLE static_relay_peers (
    static_node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    peer_node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    carrier_node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (static_node_id, peer_node_id)
);

-- What was last seen of a carrier's public relay port from outside, so an
-- export needn't check it again for a while, and `relay-ports` can say
-- which ports are open and which may be closed. `address` is the carrier's
-- public IPv4 it was checked on: a new address means a new check.
CREATE TABLE relay_ports (
    carrier_node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    address         TEXT NOT NULL,
    open            BOOLEAN NOT NULL,
    checked_at      TIMESTAMP NOT NULL,
    PRIMARY KEY (carrier_node_id, port)
);
