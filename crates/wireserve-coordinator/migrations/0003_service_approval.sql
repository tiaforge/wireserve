-- Optional admin approval for service declarations
-- (WIRESERVE_REQUIRE_SERVICE_APPROVAL, default ON).
--
-- Service names are globally unique and first-come-first-served, so any
-- node holding a valid bearer token could claim an unclaimed name -- or
-- re-claim one freed a moment earlier when its owner was revoked -- and
-- every other node's /etc/hosts would point <name>.wg at it. Approval
-- puts a human between a declaration and mesh-wide propagation.
--
-- The approval lives ON the services row, deliberately, rather than in a
-- side table keyed on the name. A row IS the pair (node_id, name), so
-- binding approval to that pair is structural: there is no representable
-- state "the name plex is approved" independent of who holds it. It also
-- means approval dies with the node for free -- revoke() already deletes
-- a node's services rows and delete_node gets them via ON DELETE CASCADE
-- -- where a side table would have needed explicit cleanup in three
-- places, one of them the security-critical one.
--
-- NULL approved_at means pending, which is the fail-closed direction: a
-- future insert that forgets the column yields a row invisible to the
-- mesh, never an approved one. A `status TEXT NOT NULL DEFAULT
-- 'approved'` column would have given the backfill below for free and
-- auto-approved on that same mistake, silently, forever.

-- Order matters: normalise declared_at BEFORE copying it into
-- approved_at. SQLite's CURRENT_TIMESTAMP default writes
-- "YYYY-MM-DD HH:MM:SS", which DateTime::parse_from_rfc3339 rejects by
-- returning None -- silently, with no error anywhere. Every timestamp
-- this code writes from here on is RFC3339 via nodes::now_str().
UPDATE services
   SET declared_at = strftime('%Y-%m-%dT%H:%M:%SZ', declared_at)
 WHERE declared_at IS NOT NULL AND declared_at NOT LIKE '%T%';

ALTER TABLE services ADD COLUMN approved_at   TIMESTAMP;
ALTER TABLE services ADD COLUMN denied_at     TIMESTAMP;
ALTER TABLE services ADD COLUMN denied_reason TEXT;

-- Grandfather every service that already exists. ADD COLUMN gives them
-- NULL, which this schema reads as "pending" -- so without this line,
-- deploying a build whose approval flag defaults to ON would empty the
-- directory and every node's managed /etc/hosts block on the first poll
-- after the upgrade. This is the single most dangerous line in the
-- change; migration_grandfathers_existing_services_as_approved exists to
-- keep it honest.
UPDATE services
   SET approved_at = COALESCE(declared_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
 WHERE approved_at IS NULL;
