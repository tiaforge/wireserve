-- The public DNS records this coordinator wrote (PLAN.md M32).
--
-- The provider APIs have no "list what I own" call, and the zone may hold
-- records the operator made by hand. This table is therefore the only thing
-- that decides what may be deleted: a name is removed from DNS only while a
-- row here says this coordinator put it there. An empty table — a fresh
-- database, a restored backup — deletes nothing, it only writes.
CREATE TABLE dns_records (
    fqdn       TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    written_at TIMESTAMP NOT NULL
);
