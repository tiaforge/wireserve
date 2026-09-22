-- Admin approval for carrying transit traffic (PLAN.md M23 follow-up,
-- security review finding #1). NULL = not approved, which is every
-- existing node: a carrier sees the traffic it relays in the clear and
-- can send packets as either end, so being one was never something a
-- node should be able to grant itself by self-report, and no node is
-- grandfathered in. Cleared on revoke and on rejoin, both of which mean
-- the node's identity is no longer the one that was approved.
ALTER TABLE nodes ADD COLUMN transit_approved_at TIMESTAMP;
