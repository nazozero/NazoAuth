-- Restore unused adapter metadata without changing any credential fact.
-- These new surrogate IDs/timestamps are not the original historical values;
-- neither field is consumed by the old runtime or referenced by other rows.
DROP INDEX ix_user_mfa_remembered_devices_expiry;
ALTER TABLE user_mfa_remembered_devices DROP CONSTRAINT user_mfa_remembered_devices_pkey;
ALTER TABLE user_mfa_remembered_devices
    ADD COLUMN id UUID NOT NULL DEFAULT uuidv7(),
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT user_mfa_remembered_devices_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX ux_user_mfa_remembered_devices_tenant_token
    ON user_mfa_remembered_devices (tenant_id, token_hash);
DROP FUNCTION nazo_oauth_cleanup_expired_security_state(BOOLEAN);
-- Freeze one cutoff per bounded batch. A volatile per-row clock cannot be
-- an index scan bound and scans retained rows after the expired prefix drains.
-- Rows expiring during this call remain eligible for the next batch; no row
-- is reclaimed earlier than its existing retention/acceptance boundary.
CREATE FUNCTION nazo_oauth_cleanup_expired_security_state(p_include_history BOOLEAN)
RETURNS TABLE (
    deleted_issuances INTEGER,
    deleted_access_token_revocations INTEGER,
    deleted_scim_audit_events INTEGER,
    deleted_backchannel_logout_deliveries INTEGER,
    deleted_scim_security_events INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff TIMESTAMPTZ := clock_timestamp();
BEGIN
    WITH due AS (
        SELECT issuance_id FROM oauth_token_issuances
        WHERE retain_until <= v_cutoff
        ORDER BY retain_until, issuance_id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM oauth_token_issuances AS target
    USING due WHERE target.issuance_id = due.issuance_id;
    GET DIAGNOSTICS deleted_issuances = ROW_COUNT;

    WITH due AS (
        SELECT tenant_id, access_token_jti_blake3 FROM access_token_revocations
        WHERE expires_at <= v_cutoff
        ORDER BY expires_at, tenant_id, access_token_jti_blake3
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM access_token_revocations AS target
    USING due
    WHERE target.tenant_id = due.tenant_id
      AND target.access_token_jti_blake3 = due.access_token_jti_blake3;
    GET DIAGNOSTICS deleted_access_token_revocations = ROW_COUNT;

    deleted_scim_audit_events := 0;
    IF p_include_history THEN
        WITH due AS (
            SELECT id FROM scim_audit_events
            WHERE created_at < v_cutoff - INTERVAL '180 days'
            ORDER BY created_at, id
            LIMIT 256 FOR UPDATE SKIP LOCKED
        )
        DELETE FROM scim_audit_events AS target
        USING due WHERE target.id = due.id;
        GET DIAGNOSTICS deleted_scim_audit_events = ROW_COUNT;
    END IF;

    WITH due AS (
        SELECT id FROM backchannel_logout_deliveries
        WHERE expires_at <= v_cutoff
        ORDER BY expires_at, id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM backchannel_logout_deliveries AS target
    USING due WHERE target.id = due.id;
    GET DIAGNOSTICS deleted_backchannel_logout_deliveries = ROW_COUNT;

    WITH due AS (
        SELECT id FROM scim_security_events
        WHERE expires_at <= v_cutoff
        ORDER BY expires_at, id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM scim_security_events AS target
    USING due WHERE target.id = due.id;
    GET DIAGNOSTICS deleted_scim_security_events = ROW_COUNT;

    RETURN NEXT;
END;
$$;
