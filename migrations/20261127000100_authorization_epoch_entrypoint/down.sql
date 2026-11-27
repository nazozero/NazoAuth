-- Stop the updated application before reverting this interface.
CREATE OR REPLACE FUNCTION public.nazo_commit_authorization_decision(p_tenant_id uuid, p_user_id uuid, p_client_id text, p_request_id text, p_par_uri text, p_valid_until timestamp with time zone, p_retain_until timestamp with time zone, p_decision text, p_event_id uuid, p_occurred_at timestamp with time zone, p_audit_fields jsonb, p_scopes jsonb, p_resources jsonb, p_authorization_details jsonb) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET lock_timeout TO '2s'
    AS $_$
DECLARE
    v_user_epoch BIGINT;
    v_outcome TEXT;
BEGIN
    -- Restore the preceding interface for rollback. It does not receive the
    -- caller's authenticated epoch. The accepting function owns lock order.
    SELECT actor.access_token_epoch INTO v_user_epoch
    FROM public.users AS actor
    WHERE actor.tenant_id = p_tenant_id AND actor.id = p_user_id;
    IF NOT FOUND THEN RETURN 'client_unavailable'; END IF;
    v_outcome := public.nazo_commit_authorization_decision(
        p_tenant_id, p_user_id, p_client_id, p_request_id, p_par_uri,
        p_valid_until, p_retain_until, p_decision, p_event_id, p_occurred_at,
        p_audit_fields, p_scopes, p_resources, p_authorization_details, v_user_epoch
    );
    IF v_outcome = 'subject_unavailable' THEN RETURN 'client_unavailable'; END IF;
    RETURN v_outcome;
END;
$_$;

REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB) FROM PUBLIC;

-- Restore only the callers and owner of the epoch-bearing entry point.
DO $$
DECLARE
    v_owner NAME;
    v_grantee RECORD;
BEGIN
    SELECT pg_get_userbyid(proowner) INTO v_owner FROM pg_proc
    WHERE oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT)'::regprocedure;
    EXECUTE format('ALTER FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB) OWNER TO %I', v_owner);
    -- CREATE may inherit named-role grants from ALTER DEFAULT PRIVILEGES.
    -- Remove them before copying the existing function's exact caller set.
    FOR v_grantee IN
        SELECT pg_get_userbyid(privilege.grantee) AS role_name
        FROM pg_proc AS function_row
        CROSS JOIN LATERAL aclexplode(COALESCE(function_row.proacl,
            acldefault('f', function_row.proowner))) AS privilege
        WHERE function_row.oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB)'::regprocedure
          AND privilege.privilege_type = 'EXECUTE'
          AND privilege.grantee NOT IN (0, function_row.proowner)
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB) FROM %I', v_grantee.role_name);
    END LOOP;
    FOR v_grantee IN
        SELECT pg_get_userbyid(privilege.grantee) AS role_name, privilege.is_grantable
        FROM pg_proc AS function_row
        CROSS JOIN LATERAL aclexplode(COALESCE(function_row.proacl,
            acldefault('f', function_row.proowner))) AS privilege
        WHERE function_row.oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT)'::regprocedure
          AND privilege.privilege_type = 'EXECUTE' AND privilege.grantee <> 0
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB) TO %I%s',
            v_grantee.role_name,
            CASE WHEN v_grantee.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$$;
