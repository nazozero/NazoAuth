ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS allow_authorization_code_without_pkce;
