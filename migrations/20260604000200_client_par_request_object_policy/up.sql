ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_par_request_object BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.require_par_request_object IS
    'Require pushed authorization requests for this client to carry a signed request object.';
