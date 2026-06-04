COMMENT ON COLUMN oauth_clients.require_par_request_object IS NULL;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS require_par_request_object;
