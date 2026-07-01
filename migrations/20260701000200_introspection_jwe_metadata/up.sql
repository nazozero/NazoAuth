ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS introspection_encrypted_response_alg VARCHAR,
    ADD COLUMN IF NOT EXISTS introspection_encrypted_response_enc VARCHAR;

COMMENT ON COLUMN oauth_clients.introspection_encrypted_response_alg IS
    'RFC 9701 JWE alg for encrypted token introspection responses, for example RSA-OAEP-256.';
COMMENT ON COLUMN oauth_clients.introspection_encrypted_response_enc IS
    'RFC 9701 JWE enc for encrypted token introspection responses, for example A256GCM.';
