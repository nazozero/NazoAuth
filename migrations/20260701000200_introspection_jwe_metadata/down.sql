COMMENT ON COLUMN oauth_clients.introspection_encrypted_response_enc IS NULL;
COMMENT ON COLUMN oauth_clients.introspection_encrypted_response_alg IS NULL;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS introspection_encrypted_response_enc,
    DROP COLUMN IF EXISTS introspection_encrypted_response_alg;
