-- Device owners (PLAN.md M38): the person, at the operator's identity
-- provider, a node belongs to — whose groups its grants then count.
--
-- One owner per node, gone with it. The refresh token is sealed with a key
-- kept outside this database (WIRESERVE_OIDC_TOKEN_KEY), bound to the node
-- it belongs to, and replaced whenever the provider rotates it.
-- `stale_since` is set while refreshing fails for reasons other than the
-- provider refusing the token; after an hour of that the groups count for
-- nothing until a refresh succeeds.
CREATE TABLE node_owners (
    node_id           INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    sub               TEXT NOT NULL,
    email             TEXT,
    name              TEXT,
    groups            TEXT NOT NULL,
    refresh_token_enc TEXT NOT NULL,
    claimed_at        TIMESTAMP NOT NULL,
    refreshed_at      TIMESTAMP NOT NULL,
    stale_since       TIMESTAMP
);

-- Claim links an admin handed out, by the hash of their code: single use,
-- short-lived, and only ever for the node named here.
CREATE TABLE claims (
    code_hash  TEXT PRIMARY KEY,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
