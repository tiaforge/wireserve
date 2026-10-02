-- Service addresses held back after release (PLAN.md #273).
--
-- A phone's `.conf` is a snapshot (M41): it routes each service address it
-- was exported with to that service's node, for as long as nobody runs
-- `export-config --refresh`. An address handed to another node's service
-- in the meantime would reach the old node on that phone — which could
-- answer for the new service. So a released address waits here until every
-- device exported before its release has been exported again or deleted;
-- only its own node may take it back sooner.
--
-- Node addresses are left out: nothing is served on a node's own address,
-- so a stale phone sending one to the wrong node reaches nothing.
--
-- `node_id` is the node that held it, NULL once that node is gone (node ids
-- can be reused, and a new node must not take back another's address).
CREATE TABLE released_service_addresses (
    vip4        TEXT PRIMARY KEY,
    node_id     INTEGER,
    released_at TEXT NOT NULL
);

-- Every way an address leaves an approved service — only those reach a
-- `.conf`: withdrawn, revoked, the node deleted (the cascade fires this
-- too, after the node row is gone), or denied after approval. Triggers
-- rather than each code path, so a new path cannot forget one.
CREATE TRIGGER service_address_released_on_delete
AFTER DELETE ON services WHEN OLD.vip4 IS NOT NULL AND OLD.approved_at IS NOT NULL
BEGIN
    INSERT OR REPLACE INTO released_service_addresses (vip4, node_id, released_at)
    VALUES (OLD.vip4, (SELECT id FROM nodes WHERE id = OLD.node_id), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;

CREATE TRIGGER service_address_released_on_update
AFTER UPDATE OF vip4 ON services
WHEN OLD.vip4 IS NOT NULL AND OLD.approved_at IS NOT NULL AND (NEW.vip4 IS NULL OR NEW.vip4 <> OLD.vip4)
BEGIN
    INSERT OR REPLACE INTO released_service_addresses (vip4, node_id, released_at)
    VALUES (OLD.vip4, OLD.node_id, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;

-- A node deleted after its addresses were released (revoked first, the usual
-- way) no longer owns them: its id may be given to the next node created.
CREATE TRIGGER released_service_addresses_forget_deleted_node
AFTER DELETE ON nodes
BEGIN
    UPDATE released_service_addresses SET node_id = NULL WHERE node_id = OLD.id;
END;
