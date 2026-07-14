ALTER TABLE scim_tokens
    ADD COLUMN event_audience VARCHAR(2048),
    ADD CONSTRAINT ck_scim_tokens_event_audience_non_empty
        CHECK (event_audience IS NULL OR length(btrim(event_audience)) > 0);

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

DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_security_state();

CREATE FUNCTION nazo_oauth_cleanup_expired_security_state()
RETURNS TABLE (
    deleted_access_token_revocations INTEGER,
    deleted_refresh_tokens INTEGER,
    deleted_scim_audit_events INTEGER,
    deleted_backchannel_logout_deliveries INTEGER,
    deleted_scim_security_events INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_revocations INTEGER := 0;
    deleted_tokens_total INTEGER := 0;
    deleted_tokens_batch INTEGER := 0;
    deleted_scim_audit INTEGER := 0;
    deleted_backchannel_logout INTEGER := 0;
    deleted_scim_events INTEGER := 0;
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

    DELETE FROM scim_security_events WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_scim_events = ROW_COUNT;

    deleted_access_token_revocations := deleted_revocations;
    deleted_refresh_tokens := deleted_tokens_total;
    deleted_scim_audit_events := deleted_scim_audit;
    deleted_backchannel_logout_deliveries := deleted_backchannel_logout;
    deleted_scim_security_events := deleted_scim_events;
    RETURN NEXT;
END;
$$;
