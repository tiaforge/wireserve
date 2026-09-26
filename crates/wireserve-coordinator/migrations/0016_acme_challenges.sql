-- ACME DNS-01 challenge values a node asked the coordinator to publish for
-- one of its own services (PLAN.md M33), as `_acme-challenge.<name>` TXT
-- records. The DNS sync writes each one and removes it once it expires or
-- the node withdraws it, so a node that crashes mid-order leaves nothing
-- behind for long.
CREATE TABLE acme_challenges (
    fqdn       TEXT NOT NULL,
    value      TEXT NOT NULL,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    -- Set once the provider has the record; NULL until then.
    written_at TIMESTAMP,
    PRIMARY KEY (fqdn, value)
);
