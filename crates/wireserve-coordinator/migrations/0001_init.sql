CREATE TABLE nodes (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL DEFAULT 'agent'
                    CHECK (kind IN ('agent', 'static')),
    pubkey          TEXT UNIQUE,
    ip4             TEXT UNIQUE,
    ip6             TEXT UNIQUE,
    bearer_token_hash TEXT UNIQUE,
    join_token_hash TEXT UNIQUE,
    join_token_used BOOLEAN NOT NULL DEFAULT 0,
    endpoint_addr   TEXT,
    listen_port     INTEGER,
    revoked         BOOLEAN NOT NULL DEFAULT 0,
    revoked_at      TIMESTAMP,
    last_seen       TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE services (
    id          INTEGER PRIMARY KEY,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name        TEXT NOT NULL UNIQUE,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL CHECK (proto IN ('tcp', 'udp')),
    declared_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
