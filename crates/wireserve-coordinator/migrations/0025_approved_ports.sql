-- What an admin approved (PLAN.md #315): the mappings as they were declared
-- when the approval was given. A later declaration that reaches a target
-- address the approval did not cover, or adds TCP 443, waits for an admin
-- again; one back inside what was approved gets its approval back.
--
-- JSON, the same shape as `ports`. NULL on a row that was never approved,
-- and on a denied one: a denial takes back what was approved.
ALTER TABLE services ADD COLUMN approved_ports TEXT;

-- Every approval given so far was given to the declaration as it stands.
UPDATE services
   SET approved_ports = ports
 WHERE approved_at IS NOT NULL AND denied_at IS NULL;
