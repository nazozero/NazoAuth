ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_post_logout_redirect_uris_array;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS backchannel_logout_session_required,
    DROP COLUMN IF EXISTS backchannel_logout_uri,
    DROP COLUMN IF EXISTS post_logout_redirect_uris;
