ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allow_client_assertion_audience_array BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.allow_client_assertion_audience_array IS
    'Allows private_key_jwt client assertion aud to be a JSON array containing an accepted audience; disabled by default for FAPI security final negative tests';
