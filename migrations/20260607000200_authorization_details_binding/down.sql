ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS ck_user_client_grants_authorization_details_array;

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS ck_oauth_tokens_authorization_details_array;

ALTER TABLE user_client_grants
    DROP COLUMN IF EXISTS last_authorization_details;

ALTER TABLE oauth_tokens
    DROP COLUMN IF EXISTS authorization_details;
