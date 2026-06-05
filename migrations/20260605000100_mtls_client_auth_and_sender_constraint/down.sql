UPDATE oauth_clients
SET token_endpoint_auth_method = 'client_secret_post'
WHERE token_endpoint_auth_method IN ('tls_client_auth', 'self_signed_tls_client_auth');

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN (
            'none',
            'client_secret_basic',
            'client_secret_post',
            'private_key_jwt'
        )
    );

COMMENT ON COLUMN oauth_clients.require_mtls_bound_tokens IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_subject_dn IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_cert_sha256 IS NULL;
COMMENT ON COLUMN oauth_tokens.mtls_x5t_s256 IS NULL;

ALTER TABLE oauth_tokens
    DROP COLUMN IF EXISTS mtls_x5t_s256;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS tls_client_auth_cert_sha256,
    DROP COLUMN IF EXISTS tls_client_auth_subject_dn,
    DROP COLUMN IF EXISTS require_mtls_bound_tokens;
