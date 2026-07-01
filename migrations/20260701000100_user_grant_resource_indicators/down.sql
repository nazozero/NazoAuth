ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS ck_user_client_grants_resource_indicators_array;

ALTER TABLE user_client_grants
    DROP COLUMN IF EXISTS last_resource_indicators;
