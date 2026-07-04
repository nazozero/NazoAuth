DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_security_state();

CREATE OR REPLACE FUNCTION nazo_oauth_cleanup_expired_security_state()
RETURNS TABLE (
    deleted_access_token_revocations INTEGER,
    deleted_refresh_tokens INTEGER,
    deleted_scim_audit_events INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_revocations INTEGER := 0;
    deleted_tokens_total INTEGER := 0;
    deleted_tokens_batch INTEGER := 0;
    deleted_scim_audit INTEGER := 0;
BEGIN
    DELETE FROM access_token_revocations
    WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_revocations = ROW_COUNT;

    LOOP
        DELETE FROM oauth_tokens token
        WHERE token.expires_at < CURRENT_TIMESTAMP
          AND NOT EXISTS (
              SELECT 1
              FROM oauth_tokens child
              WHERE child.rotated_from_id = token.id
          );
        GET DIAGNOSTICS deleted_tokens_batch = ROW_COUNT;
        deleted_tokens_total := deleted_tokens_total + deleted_tokens_batch;
        EXIT WHEN deleted_tokens_batch = 0;
    END LOOP;

    DELETE FROM scim_audit_events
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '180 days';
    GET DIAGNOSTICS deleted_scim_audit = ROW_COUNT;

    deleted_access_token_revocations := deleted_revocations;
    deleted_refresh_tokens := deleted_tokens_total;
    deleted_scim_audit_events := deleted_scim_audit;
    RETURN NEXT;
END;
$$;
