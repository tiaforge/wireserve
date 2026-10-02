-- A device owner's email only when the identity provider marks it verified
-- (PLAN.md #275). It goes to backends as the owner's email header, and an
-- unverified one is whatever the person typed into their profile. Nothing
-- says whether the ones stored so far were verified, so they go; the next
-- refresh brings a verified one back from the provider's ID token.
UPDATE node_owners SET email = NULL;
