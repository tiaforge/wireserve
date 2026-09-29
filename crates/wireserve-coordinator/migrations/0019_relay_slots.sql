-- End-to-end relaying (PLAN.md M39): every node's relay slot, which makes
-- its relay port (`WIRESERVE_RELAY_PORT_BASE` + slot) — the port a carrier
-- receives its relayed sessions on. Stable for the life of the node, so a
-- port opened once in a firewall stays right; freed when the node is
-- deleted, and the smallest free one is handed out next. NULL once all
-- slots are taken: such a node is simply never relayed to.
ALTER TABLE nodes ADD COLUMN relay_slot INTEGER;
UPDATE nodes SET relay_slot = (SELECT COUNT(*) FROM nodes n2 WHERE n2.id < nodes.id);
UPDATE nodes SET relay_slot = NULL WHERE relay_slot >= 1000;
CREATE UNIQUE INDEX nodes_relay_slot ON nodes (relay_slot);
