-- Reflexive (NAT-mapped) address discovery (PLAN.md M22, NAT-traversal
-- step 2): each node's own ip:port as observed by the coordinator's
-- self-hosted UDP reflexive responder, learned once per agent process
-- lifetime via a one-shot probe run immediately before bring_up claims
-- listen_port. Self-reported like lan_addr/endpoint_addr_v4/_v6 --
-- never derived passively by the coordinator -- and coalesced on poll
-- for the same reason: a cycle that can't (re-)probe must not erase a
-- previously-learned value. Folded into clear_endpoint's full-clear
-- (None family) branch, same as lan_addr.
ALTER TABLE nodes ADD COLUMN reflexive_addr TEXT;
