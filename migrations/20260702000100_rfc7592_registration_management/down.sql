COMMENT ON COLUMN oauth_clients.registration_access_token_blake3 IS NULL;

DROP INDEX IF EXISTS ux_oauth_clients_registration_access_token_blake3;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS registration_access_token_blake3;
