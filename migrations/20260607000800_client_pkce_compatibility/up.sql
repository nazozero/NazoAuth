ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allow_authorization_code_without_pkce BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.allow_authorization_code_without_pkce IS
    'Compatibility exception for explicitly registered confidential clients whose authorization_code requests may omit PKCE; defaults false for OAuth 2.1, Security BCP, and FAPI profiles.';
