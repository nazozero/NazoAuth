COMMENT ON COLUMN oauth_clients.require_dpop_bound_tokens IS NULL;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS require_dpop_bound_tokens;
