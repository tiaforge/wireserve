-- Service addresses and port mappings (PLAN.md M20).
--
-- vip4 is the service's own mesh address: <name>.wg resolves to it, every
-- peer routes it to the owning node, and the owner rewrites each mapped
-- public port on it to the target port the service really listens on.
-- Allocated from the same range as node addresses (so a static peer
-- routing the mesh range reaches it too), which is why the allocator's
-- "used" set is node addresses and service addresses together.
--
-- NULL is the state every existing row starts in, and the state of any
-- declaration from an agent that predates port mappings: such an agent
-- can't serve an address, so it is never given one, and <name>.wg keeps
-- resolving to the owning node exactly as before. An upgraded agent's
-- next poll allocates one.
--
-- ports is that declaration's mappings as JSON ([{"public","target",
-- "proto"}, ...]); NULL means the single identity mapping port:port/proto
-- a pre-mapping declaration stands for.
ALTER TABLE services ADD COLUMN vip4  TEXT;
ALTER TABLE services ADD COLUMN ports TEXT;
CREATE UNIQUE INDEX services_vip4 ON services (vip4);
