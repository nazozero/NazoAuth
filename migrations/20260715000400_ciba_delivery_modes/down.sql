ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_ciba_user_code_disabled,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_ciba_request_signing_alg,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_ciba_notification_endpoint,
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_ciba_delivery_mode;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS backchannel_user_code_parameter,
    DROP COLUMN IF EXISTS backchannel_authentication_request_signing_alg,
    DROP COLUMN IF EXISTS backchannel_client_notification_endpoint,
    DROP COLUMN IF EXISTS backchannel_token_delivery_mode;
