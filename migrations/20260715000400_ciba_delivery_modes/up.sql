ALTER TABLE oauth_clients
    ADD COLUMN backchannel_token_delivery_mode VARCHAR NOT NULL DEFAULT 'poll',
    ADD COLUMN backchannel_client_notification_endpoint TEXT,
    ADD COLUMN backchannel_authentication_request_signing_alg VARCHAR,
    ADD COLUMN backchannel_user_code_parameter BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE oauth_clients
    ADD CONSTRAINT ck_oauth_clients_ciba_delivery_mode
        CHECK (backchannel_token_delivery_mode IN ('poll', 'ping')),
    ADD CONSTRAINT ck_oauth_clients_ciba_notification_endpoint
        CHECK (
            (backchannel_token_delivery_mode = 'poll'
                AND backchannel_client_notification_endpoint IS NULL)
            OR
            (backchannel_token_delivery_mode = 'ping'
                AND backchannel_client_notification_endpoint ~ '^https://[^[:space:]]+$')
        ),
    ADD CONSTRAINT ck_oauth_clients_ciba_request_signing_alg
        CHECK (
            backchannel_authentication_request_signing_alg IS NULL
            OR backchannel_authentication_request_signing_alg IN ('EdDSA', 'ES256', 'PS256')
        ),
    ADD CONSTRAINT ck_oauth_clients_ciba_user_code_disabled
        CHECK (backchannel_user_code_parameter = FALSE);

COMMENT ON COLUMN oauth_clients.backchannel_token_delivery_mode IS
    'CIBA delivery mode: poll or ping. FAPI-CIBA push is deliberately unsupported.';
COMMENT ON COLUMN oauth_clients.backchannel_client_notification_endpoint IS
    'Exact HTTPS endpoint used for CIBA ping notifications.';
