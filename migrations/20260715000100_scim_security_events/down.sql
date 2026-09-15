DROP TABLE IF EXISTS scim_security_event_receipts;
DROP TABLE IF EXISTS scim_security_events;
ALTER TABLE scim_tokens DROP COLUMN IF EXISTS event_audience;

DELETE FROM runtime_module_state_events WHERE module_id = 'scim_security_events';
DELETE FROM runtime_module_instance_states WHERE module_id = 'scim_security_events';
DELETE FROM runtime_module_desired_states WHERE module_id = 'scim_security_events';

ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT ck_runtime_module_desired_module_id,
    ADD CONSTRAINT ck_runtime_module_desired_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    );

ALTER TABLE runtime_module_instance_states
    DROP CONSTRAINT ck_runtime_module_instance_module_id,
    ADD CONSTRAINT ck_runtime_module_instance_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    );

ALTER TABLE runtime_module_state_events
    DROP CONSTRAINT ck_runtime_module_event_module_id,
    ADD CONSTRAINT ck_runtime_module_event_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    );
