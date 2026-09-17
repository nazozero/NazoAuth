-- Downgrade intentionally keeps every revocation fact deadline: shortening a
-- stored retention deadline could drop revocation state that is still inside
-- a verifier's acceptance window.
SELECT 1;
