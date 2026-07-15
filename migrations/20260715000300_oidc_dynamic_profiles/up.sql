ALTER TABLE oauth_clients
    ADD COLUMN jwks_uri TEXT,
    ADD COLUMN request_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN initiate_login_uri TEXT,
    ADD COLUMN logo_uri TEXT,
    ADD COLUMN policy_uri TEXT,
    ADD COLUMN tos_uri TEXT;

ALTER TABLE oauth_clients
    ADD CONSTRAINT ck_oauth_clients_jwks_source CHECK (jwks_uri IS NULL OR jwks IS NOT NULL),
    ADD CONSTRAINT ck_oauth_clients_request_uris_array CHECK (jsonb_typeof(request_uris) = 'array'),
    ADD CONSTRAINT ck_oauth_clients_jwks_uri_https CHECK (
        jwks_uri IS NULL OR lower(jwks_uri) LIKE 'https://%'
    ),
    ADD CONSTRAINT ck_oauth_clients_initiate_login_uri_https CHECK (
        initiate_login_uri IS NULL OR lower(initiate_login_uri) LIKE 'https://%'
    ),
    ADD CONSTRAINT ck_oauth_clients_logo_uri_https CHECK (
        logo_uri IS NULL OR lower(logo_uri) LIKE 'https://%'
    ),
    ADD CONSTRAINT ck_oauth_clients_policy_uri_https CHECK (
        policy_uri IS NULL OR lower(policy_uri) LIKE 'https://%'
    ),
    ADD CONSTRAINT ck_oauth_clients_tos_uri_https CHECK (
        tos_uri IS NULL OR lower(tos_uri) LIKE 'https://%'
    );

COMMENT ON COLUMN oauth_clients.jwks_uri IS
    'Dynamically registered HTTPS JWK Set URI; jwks stores the last validated snapshot.';
COMMENT ON COLUMN oauth_clients.request_uris IS
    'Exact dynamically registered HTTPS OIDC Request Object locations.';
COMMENT ON COLUMN oauth_clients.initiate_login_uri IS
    'HTTPS RP endpoint for OpenID Connect Third-Party Initiated Login.';
COMMENT ON COLUMN oauth_clients.logo_uri IS
    'Display-only HTTPS RP logo URI; never dereferenced by the authorization server.';
COMMENT ON COLUMN oauth_clients.policy_uri IS
    'Display-only HTTPS RP policy URI; never dereferenced by the authorization server.';
COMMENT ON COLUMN oauth_clients.tos_uri IS
    'Display-only HTTPS RP terms-of-service URI; never dereferenced by the authorization server.';
