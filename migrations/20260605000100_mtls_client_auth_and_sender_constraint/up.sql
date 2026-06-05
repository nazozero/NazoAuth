ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_mtls_bound_tokens BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS tls_client_auth_subject_dn VARCHAR(512),
    ADD COLUMN IF NOT EXISTS tls_client_auth_cert_sha256 VARCHAR(128);

ALTER TABLE oauth_tokens
    ADD COLUMN IF NOT EXISTS mtls_x5t_s256 VARCHAR(128);

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN (
            'none',
            'client_secret_basic',
            'client_secret_post',
            'private_key_jwt',
            'tls_client_auth',
            'self_signed_tls_client_auth'
        )
    );

COMMENT ON COLUMN oauth_clients.require_mtls_bound_tokens IS
    'Requires access tokens issued to this client to be bound to the verified mTLS client certificate thumbprint';
COMMENT ON COLUMN oauth_clients.tls_client_auth_subject_dn IS
    'Registered subject DN for tls_client_auth clients; retained for discovery/admin compatibility';
COMMENT ON COLUMN oauth_clients.tls_client_auth_cert_sha256 IS
    'Base64url SHA-256 thumbprint of the registered client certificate DER';
COMMENT ON COLUMN oauth_tokens.mtls_x5t_s256 IS
    'Base64url SHA-256 thumbprint used to bind refresh tokens to an mTLS client certificate';
