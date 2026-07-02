ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS registration_access_token_blake3 VARCHAR;

CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_clients_registration_access_token_blake3
    ON oauth_clients (registration_access_token_blake3)
    WHERE registration_access_token_blake3 IS NOT NULL;

COMMENT ON COLUMN oauth_clients.registration_access_token_blake3 IS
    'BLAKE3 hash of the RFC 7592 registration access token for dynamic client management.';
