-- The services whose own node serves them with TLS right now (PLAN.md M33),
-- as each node last reported in `PollRequest.tls_ready`.
--
-- Persisted, not kept in memory like the other capability reports: a
-- coordinator restart would otherwise forget every one of them at once and
-- move every terminated name back to the proxy until each node polled again,
-- a swing the DNS records would carry for a full TTL. A poll that leaves a
-- name out removes it; revoking or re-joining the node removes them all.
CREATE TABLE tls_ready (
    name        TEXT PRIMARY KEY,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    reported_at TIMESTAMP NOT NULL
);
