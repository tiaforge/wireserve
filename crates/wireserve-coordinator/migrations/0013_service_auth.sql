-- Services published behind the proxy's sign-in (PLAN.md M29).
--
-- Keyed by name and kept apart from `services`, on purpose. A `services` row
-- is deleted when its node withdraws the declaration, and re-created when it
-- declares it again — with approval disabled, instantly. A mark stored on the
-- row would vanish in that round trip and leave the service reachable with no
-- sign-in, silently. Here only an admin removes it, so a withdraw and
-- re-declare comes back as protected as it went.
--
-- A name marked while nothing declares it is allowed and inert: whoever
-- declares it next is published behind the sign-in, which is the safe
-- direction to err in.
CREATE TABLE service_auth (
    name      TEXT PRIMARY KEY,
    marked_at TIMESTAMP NOT NULL
);
