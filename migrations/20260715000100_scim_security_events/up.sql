ALTER TABLE scim_tokens
    ADD COLUMN event_audience VARCHAR(2048),
    ADD CONSTRAINT ck_scim_tokens_event_audience_non_empty
        CHECK (event_audience IS NULL OR length(btrim(event_audience)) > 0);

ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT ck_runtime_module_desired_module_id,
    ADD CONSTRAINT ck_runtime_module_desired_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );

ALTER TABLE runtime_module_instance_states
    DROP CONSTRAINT ck_runtime_module_instance_module_id,
    ADD CONSTRAINT ck_runtime_module_instance_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );

ALTER TABLE runtime_module_state_events
    DROP CONSTRAINT ck_runtime_module_event_module_id,
    ADD CONSTRAINT ck_runtime_module_event_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );

CREATE TABLE scim_security_events (
    id UUID PRIMARY KEY NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    transaction_id UUID NOT NULL,
    subject_uri TEXT NOT NULL,
    events JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_scim_security_events_subject_uri
        CHECK (subject_uri ~ '^/Users/[0-9a-fA-F-]{36}$'),
    CONSTRAINT ck_scim_security_events_payload_object
        CHECK (jsonb_typeof(events) = 'object' AND events <> '{}'::jsonb),
    CONSTRAINT ck_scim_security_events_retention
        CHECK (expires_at > occurred_at)
);

CREATE INDEX ix_scim_security_events_tenant_poll
    ON scim_security_events (tenant_id, occurred_at, id);

CREATE INDEX ix_scim_security_events_expiry
    ON scim_security_events (expires_at);

CREATE TABLE scim_security_event_receipts (
    event_id UUID NOT NULL REFERENCES scim_security_events(id) ON DELETE CASCADE,
    scim_token_id UUID NOT NULL REFERENCES scim_tokens(id) ON DELETE CASCADE,
    disposition VARCHAR(16) NOT NULL,
    error_code VARCHAR(64),
    error_description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id, scim_token_id),
    CONSTRAINT ck_scim_security_event_receipts_disposition
        CHECK (disposition IN ('acknowledged', 'error')),
    CONSTRAINT ck_scim_security_event_receipts_error_shape CHECK (
        (disposition = 'acknowledged' AND error_code IS NULL AND error_description IS NULL)
        OR
        (disposition = 'error' AND error_code IS NOT NULL AND error_description IS NOT NULL)
    )
);
