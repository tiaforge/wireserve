-- A service whose backend reads who is calling from the identity headers
-- (PLAN.md #326): its node says so on every declaration, and its
-- terminated 443 then lets in only people who sign in, naming every one of
-- them. Without it no request to the service names anyone.
ALTER TABLE services ADD COLUMN always_sign_in INTEGER NOT NULL DEFAULT 0;
