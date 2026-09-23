-- Gateway routing for static peers (PLAN.md M24).
--
-- A static peer's .conf is a snapshot: a node added later is unroutable from
-- it until the whole thing is re-exported and re-imported. A gateway fixes
-- that by giving the device one peer that carries the whole mesh range, so
-- anything new is reachable the moment it joins.
--
-- `gateway_node_id` is the node that phone routes through. NULL for every
-- existing row and for any device exported without one, which is exactly
-- today's all-direct behaviour. Deliberately preserved by `reissue_join_token`
-- (unlike `transit_approved_at`): it is an addressing fact about the device,
-- in the same category as `ip4`/`ip6`, not a credential tied to the keypair.
ALTER TABLE nodes ADD COLUMN gateway_node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL;

-- Which peers were written into a static peer's .conf as direct `[Peer]`
-- blocks, recorded at export time.
--
-- This has to be persisted rather than recomputed, and that is the subtle
-- part. `transit_via` must be set on the phone for exactly the nodes *absent*
-- from its conf: `wg::desired_peers` pass 1 deletes a transited peer's kernel
-- entry outright rather than merely hinting a route, and WireGuard has no
-- failover — a /32 in the conf always wins over the gateway's covering route,
-- reachable or not. So naming a node that IS in the conf would make that node
-- drop the phone while the phone still dials it: a black hole.
--
-- Recomputing "is this node in the conf" from live endpoint state would drift
-- against the frozen file. The direction that bites is a node that *gains* a
-- routable endpoint after export: it would stop being given `transit_via`,
-- keep an endpoint-less phone peer it never handshook, and then reject the
-- phone's forwarded packets on the crypto source filter — broken both ways,
-- silently. The conf is a snapshot, so its membership is too.
CREATE TABLE static_conf_peers (
    static_node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    peer_node_id   INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (static_node_id, peer_node_id)
);
