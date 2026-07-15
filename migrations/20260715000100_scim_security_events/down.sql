DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_security_state();

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

CREATE FUNCTION nazo_oauth_cleanup_expired_security_state()
RETURNS TABLE (
    deleted_access_token_revocations INTEGER,
    deleted_refresh_tokens INTEGER,
    deleted_scim_audit_events INTEGER,
    deleted_backchannel_logout_deliveries INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_revocations INTEGER := 0;
    deleted_tokens_total INTEGER := 0;
    deleted_tokens_batch INTEGER := 0;
    deleted_scim_audit INTEGER := 0;
    deleted_backchannel_logout INTEGER := 0;
BEGIN
    DELETE FROM access_token_revocations WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_revocations = ROW_COUNT;

    LOOP
        DELETE FROM oauth_tokens token
        WHERE token.expires_at < CURRENT_TIMESTAMP
          AND token.revoked_at IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM oauth_tokens child WHERE child.rotated_from_id = token.id
          );
        GET DIAGNOSTICS deleted_tokens_batch = ROW_COUNT;
        deleted_tokens_total := deleted_tokens_total + deleted_tokens_batch;
        EXIT WHEN deleted_tokens_batch = 0;
    END LOOP;

    DELETE FROM scim_audit_events
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '180 days';
    GET DIAGNOSTICS deleted_scim_audit = ROW_COUNT;

    DELETE FROM backchannel_logout_deliveries WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_backchannel_logout = ROW_COUNT;

    deleted_access_token_revocations := deleted_revocations;
    deleted_refresh_tokens := deleted_tokens_total;
    deleted_scim_audit_events := deleted_scim_audit;
    deleted_backchannel_logout_deliveries := deleted_backchannel_logout;
    RETURN NEXT;
END;
$$;
