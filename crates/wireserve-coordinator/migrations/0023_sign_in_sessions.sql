-- The sign-in (PLAN.md M48): the coordinator signs people in itself, with
-- the same identity provider client device owners use.
--
-- A session is one browser signed in as one person. `id` is named in the
-- session tokens the terminators check; `login_hash` is the hash of the
-- coordinator's own cookie for that browser, which lets it skip the
-- provider when the person signs in to a second service. The refresh token
-- is sealed like an owner's (WIRESERVE_OIDC_TOKEN_KEY), bound to the
-- session. `stale_since` as for owners: set while refreshing fails for
-- reasons other than the provider refusing the token.
CREATE TABLE sign_in_sessions (
    id                TEXT PRIMARY KEY,
    login_hash        TEXT NOT NULL UNIQUE,
    sub               TEXT NOT NULL,
    email             TEXT,
    name              TEXT,
    groups            TEXT NOT NULL,
    refresh_token_enc TEXT NOT NULL,
    created_at        TIMESTAMP NOT NULL,
    refreshed_at      TIMESTAMP NOT NULL,
    stale_since       TIMESTAMP,
    last_used_at      TIMESTAMP NOT NULL
);
CREATE INDEX sign_in_sessions_sub ON sign_in_sessions(sub);

-- What a browser carries from the coordinator back to a service, by its
-- hash: single use, a minute, and redeemable only for the service named.
-- `to_path` is where on the service the browser goes next.
CREATE TABLE sign_in_tickets (
    ticket_hash TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sign_in_sessions(id) ON DELETE CASCADE,
    fqdn        TEXT NOT NULL,
    to_path     TEXT NOT NULL,
    expires_at  TIMESTAMP NOT NULL
);
