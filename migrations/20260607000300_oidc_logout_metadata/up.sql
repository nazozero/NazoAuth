ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri VARCHAR,
    ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_post_logout_redirect_uris_array;

ALTER TABLE oauth_clients
    ADD CONSTRAINT ck_oauth_clients_post_logout_redirect_uris_array
    CHECK (jsonb_typeof(post_logout_redirect_uris) = 'array');
