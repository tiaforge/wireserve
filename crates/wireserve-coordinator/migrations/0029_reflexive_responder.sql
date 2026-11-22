-- The node that answers reflexive probes on its own WireGuard port (PLAN.md
-- M50): the one on the coordinator's host, named by an admin. At most one.
ALTER TABLE nodes ADD COLUMN reflexive_responder INTEGER NOT NULL DEFAULT 0;
