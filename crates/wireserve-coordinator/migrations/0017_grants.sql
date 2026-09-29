-- Who can reach what (PLAN.md M36): service groups, grants and node tags.
--
-- A service's groups are keyed by its NAME, like the sign-in marks this
-- replaces were (see 0013): a `services` row is deleted when its node
-- withdraws the declaration and re-created when it declares it again, and a
-- group stored on the row would vanish in that round trip — dropping the
-- service back into `default`, which everyone reaches. Here only an admin
-- removes it.
--
-- A service with no row here is in the built-in `default` group. Every
-- service that exists when this runs has none, and `everyone -> default` is
-- seeded below, so a mesh upgrading to this reaches exactly what it did.
CREATE TABLE service_groups (
    name       TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL
);
INSERT INTO service_groups (name, created_at) VALUES ('default', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

CREATE TABLE service_group_members (
    service TEXT NOT NULL,
    grp     TEXT NOT NULL REFERENCES service_groups(name) ON DELETE RESTRICT,
    PRIMARY KEY (service, grp)
);

-- `source` is empty for `everyone`, a group name from the identity provider
-- for `oidc`, a node tag for `tag`.
CREATE TABLE grants (
    id          INTEGER PRIMARY KEY,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('everyone', 'oidc', 'tag')),
    source      TEXT NOT NULL,
    grp         TEXT NOT NULL REFERENCES service_groups(name) ON DELETE RESTRICT,
    UNIQUE (source_kind, source, grp)
);
INSERT INTO grants (source_kind, source, grp) VALUES ('everyone', '', 'default');

CREATE TABLE node_tags (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (node_id, tag)
);

-- The group a node named when it declared the service. It becomes
-- membership once, when the row is first approved and the name has no
-- groups yet, and is cleared then: a declaration never changes groups an
-- admin set, and a pending or denied one never sets any.
ALTER TABLE services ADD COLUMN declared_group TEXT;

-- The per-service sign-in marks (0013) are gone: a restricted service's
-- grants decide who may sign in. The coordinator refuses to reach this
-- migration while any mark exists (db::refuse_live_marks), so no marked
-- service ever turns public by being dropped here.
DROP TABLE service_auth;
