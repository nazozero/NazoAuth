ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS jwks JSONB;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_jwks_object,
    ADD CONSTRAINT ck_oauth_clients_jwks_object CHECK (jwks IS NULL OR jsonb_typeof(jwks) = 'object');

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt')
    );

COMMENT ON COLUMN oauth_clients.jwks IS
    'Public JWKS used to verify private_key_jwt client assertions';
COMMENT ON COLUMN oauth_clients.token_endpoint_auth_method IS
    'none=public client, client_secret_basic=HTTP Basic client authentication, client_secret_post=form body client authentication, private_key_jwt=JWT client assertion authentication';
