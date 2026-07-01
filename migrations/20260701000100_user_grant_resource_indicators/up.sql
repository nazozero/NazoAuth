ALTER TABLE user_client_grants
    ADD COLUMN IF NOT EXISTS last_resource_indicators JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS ck_user_client_grants_resource_indicators_array;

ALTER TABLE user_client_grants
    ADD CONSTRAINT ck_user_client_grants_resource_indicators_array
    CHECK (jsonb_typeof(last_resource_indicators) = 'array');
