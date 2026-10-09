-- Restore the previous per-row wall-clock predicate without changing state.
CREATE OR REPLACE FUNCTION nazo_oauth_cleanup_expired_security_state()
RETURNS TABLE (
    deleted_issuances INTEGER,
    deleted_access_token_revocations INTEGER,
    deleted_scim_audit_events INTEGER,
    deleted_backchannel_logout_deliveries INTEGER,
    deleted_scim_security_events INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    WITH due AS (
        SELECT issuance_id FROM oauth_token_issuances
        WHERE retain_until <= clock_timestamp()
        ORDER BY retain_until, issuance_id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM oauth_token_issuances AS target
    USING due WHERE target.issuance_id = due.issuance_id;
    GET DIAGNOSTICS deleted_issuances = ROW_COUNT;

    WITH due AS (
        SELECT tenant_id, access_token_jti_blake3 FROM access_token_revocations
        WHERE expires_at <= clock_timestamp()
        ORDER BY expires_at, tenant_id, access_token_jti_blake3
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM access_token_revocations AS target
    USING due
    WHERE target.tenant_id = due.tenant_id
      AND target.access_token_jti_blake3 = due.access_token_jti_blake3;
    GET DIAGNOSTICS deleted_access_token_revocations = ROW_COUNT;

    WITH due AS (
        SELECT id FROM scim_audit_events
        WHERE created_at < clock_timestamp() - INTERVAL '180 days'
        ORDER BY created_at, id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM scim_audit_events AS target
    USING due WHERE target.id = due.id;
    GET DIAGNOSTICS deleted_scim_audit_events = ROW_COUNT;

    WITH due AS (
        SELECT id FROM backchannel_logout_deliveries
        WHERE expires_at <= clock_timestamp()
        ORDER BY expires_at, id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM backchannel_logout_deliveries AS target
    USING due WHERE target.id = due.id;
    GET DIAGNOSTICS deleted_backchannel_logout_deliveries = ROW_COUNT;

    WITH due AS (
        SELECT id FROM scim_security_events
        WHERE expires_at <= clock_timestamp()
        ORDER BY expires_at, id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM scim_security_events AS target
    USING due WHERE target.id = due.id;
    GET DIAGNOSTICS deleted_scim_security_events = ROW_COUNT;

    RETURN NEXT;
END;
$$;
