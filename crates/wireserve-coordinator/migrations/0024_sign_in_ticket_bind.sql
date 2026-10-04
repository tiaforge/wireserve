-- A ticket is redeemed only for the browser that started its sign-in
-- (PLAN.md #312): the hash of that browser's bind cookie, as its service's
-- terminator saw it.
ALTER TABLE sign_in_tickets ADD COLUMN bind TEXT NOT NULL DEFAULT '';
