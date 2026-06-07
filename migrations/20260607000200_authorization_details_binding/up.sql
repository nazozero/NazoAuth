ALTER TABLE oauth_tokens
    ADD COLUMN IF NOT EXISTS authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE user_client_grants
    ADD COLUMN IF NOT EXISTS last_authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS ck_oauth_tokens_authorization_details_array;

ALTER TABLE oauth_tokens
    ADD CONSTRAINT ck_oauth_tokens_authorization_details_array
    CHECK (jsonb_typeof(authorization_details) = 'array');

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS ck_user_client_grants_authorization_details_array;

ALTER TABLE user_client_grants
    ADD CONSTRAINT ck_user_client_grants_authorization_details_array
    CHECK (jsonb_typeof(last_authorization_details) = 'array');
