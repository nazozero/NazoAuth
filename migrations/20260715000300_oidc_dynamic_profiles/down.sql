ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_tos_uri_https,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_policy_uri_https,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_logo_uri_https,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_initiate_login_uri_https,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_jwks_uri_https,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_request_uris_array,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_jwks_source,
    DROP COLUMN IF EXISTS tos_uri,
    DROP COLUMN IF EXISTS policy_uri,
    DROP COLUMN IF EXISTS logo_uri,
    DROP COLUMN IF EXISTS initiate_login_uri,
    DROP COLUMN IF EXISTS request_uris,
    DROP COLUMN IF EXISTS jwks_uri;
