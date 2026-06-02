ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_dpop_bound_tokens BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.require_dpop_bound_tokens IS
    'Whether this client must bind authorization code and refresh-token issued access tokens to a DPoP key.';
