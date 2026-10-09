-- One ordered principal fence, still inside the caller's transaction.
-- No function SET clause: the transaction-local lock timeout must remain in
-- force after this call for the following receipt and family locks as well.
-- This is invoker-rights code and every relation/function is qualified.
CREATE OR REPLACE FUNCTION public.nazo_lock_token_principals(
    p_tenant UUID, p_client UUID, p_client_epoch BIGINT,
    p_user UUID, p_user_epoch BIGINT
) RETURNS TABLE(outcome TEXT, client_type TEXT)
LANGUAGE plpgsql SECURITY INVOKER
AS $$
DECLARE
    v_client RECORD;
    v_user RECORD;
BEGIN
    PERFORM pg_catalog.set_config('lock_timeout', '2s', true);
    SELECT c.is_active, c.access_token_epoch, c.client_type INTO v_client
    FROM public.oauth_clients c
    WHERE c.tenant_id=p_tenant AND c.id=p_client FOR SHARE;
    IF NOT FOUND OR NOT v_client.is_active OR v_client.access_token_epoch IS DISTINCT FROM p_client_epoch THEN
        outcome := 'client_inactive'; RETURN NEXT; RETURN;
    END IF;
    IF p_user IS NOT NULL THEN
        SELECT u.is_active, u.access_token_epoch INTO v_user
        FROM public.users u
        WHERE u.tenant_id=p_tenant AND u.id=p_user FOR SHARE;
        IF NOT FOUND OR NOT v_user.is_active
           OR v_user.access_token_epoch IS DISTINCT FROM p_user_epoch THEN
            outcome := 'subject_inactive'; RETURN NEXT; RETURN;
        END IF;
    END IF;
    outcome := 'ok'; client_type := v_client.client_type; RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION public.nazo_lock_token_principals(UUID,UUID,BIGINT,UUID,BIGINT) FROM PUBLIC;
