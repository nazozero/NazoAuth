ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allow_authorization_code_without_pkce BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.allow_authorization_code_without_pkce IS
    'Rollback-only compatibility column. Current application versions ignore it and always require S256 PKCE.';
