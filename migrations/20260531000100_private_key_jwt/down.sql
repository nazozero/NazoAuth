UPDATE oauth_clients
SET token_endpoint_auth_method = 'client_secret_post',
    jwks = NULL
WHERE token_endpoint_auth_method = 'private_key_jwt';

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post')
    );

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_jwks_object,
    DROP COLUMN IF EXISTS jwks;

COMMENT ON COLUMN oauth_clients.token_endpoint_auth_method IS
    'none=public client, client_secret_basic=HTTP Basic client authentication, client_secret_post=form body client authentication';
