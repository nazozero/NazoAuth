-- Admit browser authentication at the same fence that commits its decision.
CREATE FUNCTION public.nazo_commit_authorization_decision(p_tenant_id uuid, p_user_id uuid, p_client_id text, p_request_id text, p_par_uri text, p_valid_until timestamp with time zone, p_retain_until timestamp with time zone, p_decision text, p_event_id uuid, p_occurred_at timestamp with time zone, p_audit_fields jsonb, p_scopes jsonb, p_resources jsonb, p_authorization_details jsonb, p_user_epoch bigint) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET lock_timeout TO '2s'
    AS $_$
DECLARE
    v_client_id UUID;
    v_active BOOLEAN;
    v_user_epoch BIGINT;
    v_payload JSONB;
    v_inserted INTEGER;
    v_digest_key TEXT;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_user_id IS NULL OR p_user_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_user_epoch IS NULL OR p_user_epoch < 0
       OR p_event_id IS NULL OR p_event_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_client_id IS NULL OR octet_length(p_client_id) NOT BETWEEN 1 AND 512
       OR p_request_id IS NULL OR octet_length(p_request_id) NOT BETWEEN 1 AND 512
       OR (p_par_uri IS NOT NULL AND octet_length(p_par_uri) NOT BETWEEN 1 AND 1024)
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'deny', 'prompt_none')
       OR p_valid_until IS NULL OR NOT isfinite(p_valid_until)
       OR p_retain_until IS NULL OR NOT isfinite(p_retain_until)
       OR p_occurred_at IS NULL OR NOT isfinite(p_occurred_at)
       OR p_retain_until < p_valid_until OR p_retain_until < p_occurred_at
       OR jsonb_typeof(p_audit_fields) IS DISTINCT FROM 'object'
       OR jsonb_typeof(p_scopes) IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_resources) IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_authorization_details) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid authorization decision';
    END IF;
    IF p_decision IN ('approve', 'prompt_none') AND (
        jsonb_typeof(p_audit_fields -> 'code_id') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_id', '') = ''
        OR jsonb_typeof(p_audit_fields -> 'code_hash') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_hash', '') !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(p_audit_fields -> 'code_payload_digest') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_payload_digest', '') !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'authorization code binding is missing or invalid';
    END IF;
    IF p_decision = 'deny' AND p_audit_fields ?| ARRAY['code_id', 'code_hash', 'code_payload_digest'] THEN
        RAISE EXCEPTION 'denial cannot bind an authorization code';
    END IF;
    -- Digest preparation belongs to the Rust adapter (BLAKE3); validate their
    -- shape here. Export only this allowlist: raw request/PAR handles live in
    -- the fence columns, and full resources/details live in the grant alone.
    IF COALESCE(p_audit_fields ->> 'request_id_hash', '') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'authorization request digest is missing or invalid';
    END IF;
    FOREACH v_digest_key IN ARRAY ARRAY[
        'request_id_hash', 'source_ip_hash', 'resource_digest',
        'authorization_details_digest', 'pushed_request_digest', 'pushed_request_uri_hash'
    ] LOOP
        IF p_audit_fields ? v_digest_key AND (
            jsonb_typeof(p_audit_fields -> v_digest_key) IS DISTINCT FROM 'string'
            OR (p_audit_fields ->> v_digest_key) !~ '^[0-9a-f]{64}$'
        ) THEN
            RAISE EXCEPTION 'authorization audit digest is invalid';
        END IF;
    END LOOP;
    v_payload := jsonb_strip_nulls(jsonb_build_object(
        'schema_version', 'nazo.audit.v1', 'event_category', 'authorization',
        'tenant_id', p_tenant_id, 'user_id', p_user_id, 'client_id', p_client_id,
        'decision', p_decision, 'valid_until', p_valid_until, 'retain_until', p_retain_until,
        'scope', (SELECT string_agg(scope.value, ' ' ORDER BY scope.position)
                  FROM jsonb_array_elements_text(p_scopes) WITH ORDINALITY AS scope(value, position)),
        'request_id_hash', p_audit_fields -> 'request_id_hash',
        'source_ip_hash', p_audit_fields -> 'source_ip_hash',
        'resource_digest', p_audit_fields -> 'resource_digest',
        'authorization_details_digest', p_audit_fields -> 'authorization_details_digest',
        'pushed_request_digest', p_audit_fields -> 'pushed_request_digest',
        'pushed_request_uri_hash', p_audit_fields -> 'pushed_request_uri_hash',
        'code_id', p_audit_fields -> 'code_id',
        'code_hash', p_audit_fields -> 'code_hash',
        'code_payload_digest', p_audit_fields -> 'code_payload_digest'
    ));
    IF octet_length(convert_to(v_payload::TEXT, 'UTF8')) > 65536 THEN
        RAISE EXCEPTION 'authorization decision payload is too large';
    END IF;
    SELECT client.id, client.is_active INTO v_client_id, v_active
    FROM public.oauth_clients AS client
    WHERE client.tenant_id = p_tenant_id AND client.client_id = p_client_id
    FOR SHARE OF client;
    IF NOT FOUND OR NOT v_active THEN RETURN 'client_unavailable'; END IF;
    SELECT actor.is_active, actor.access_token_epoch INTO v_active, v_user_epoch
    FROM public.users AS actor
    WHERE actor.tenant_id = p_tenant_id AND actor.id = p_user_id
    FOR SHARE OF actor;
    IF NOT FOUND OR v_active IS DISTINCT FROM TRUE
       OR v_user_epoch IS DISTINCT FROM p_user_epoch THEN
        RETURN 'subject_unavailable';
    END IF;
    -- Both explicit approval and prompt-none lock an existing grant BEFORE
    -- claiming either unique fence. The opposite order can deadlock when an
    -- approval holds the PAR fence while waiting for prompt-none's grant lock.
    IF p_decision = 'approve' THEN
        PERFORM 1 FROM public.user_client_grants AS grant_row
        WHERE grant_row.tenant_id = p_tenant_id AND grant_row.user_id = p_user_id
          AND grant_row.client_id = v_client_id
        FOR UPDATE OF grant_row;
    END IF;
    IF clock_timestamp() >= p_valid_until THEN RETURN 'expired'; END IF;

    -- The exception block is a subtransaction: a deadline that passes while
    -- awaiting a unique/grant lock rolls back BOTH the fact and grant mutation.
    BEGIN
        INSERT INTO public.security_audit_events (
            event_id, event_type, event_category, payload, occurred_at,
            authorization_tenant_id, authorization_request_id, authorization_par_uri,
            authorization_decision, authorization_valid_until, business_retain_until
        ) VALUES (
            p_event_id, 'authorization_decision_committed', 'authorization', v_payload, p_occurred_at,
            p_tenant_id, p_request_id, p_par_uri, p_decision, p_valid_until, p_retain_until
        ) ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 0 THEN RETURN 'conflict'; END IF;
        IF p_decision = 'approve' THEN
            INSERT INTO public.user_client_grants (
                tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,
                last_scopes, last_resource_indicators, last_authorization_details, authorization_count
            ) VALUES (
                p_tenant_id, p_user_id, v_client_id, p_occurred_at, p_occurred_at,
                p_scopes, p_resources, p_authorization_details, 1
            ) ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE SET
                last_authorized_at = EXCLUDED.last_authorized_at,
                last_scopes = EXCLUDED.last_scopes,
                last_resource_indicators = EXCLUDED.last_resource_indicators,
                last_authorization_details = EXCLUDED.last_authorization_details,
                authorization_count = public.user_client_grants.authorization_count + 1;
        END IF;
        IF clock_timestamp() >= p_valid_until THEN
            RAISE EXCEPTION 'authorization decision expired during commit' USING ERRCODE = 'PZA01';
        END IF;
        RETURN 'committed';
    EXCEPTION WHEN SQLSTATE 'PZA01' THEN
        RETURN 'expired';
    END;
END;
$_$;

REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT) FROM PUBLIC;

-- Preserve the existing business-function owner and restricted callers during
-- a rolling upgrade; granting the new signature must not widen authority.
DO $$
DECLARE
    v_owner NAME;
    v_grantee RECORD;
BEGIN
    SELECT pg_get_userbyid(proowner) INTO v_owner FROM pg_proc
    WHERE oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB)'::regprocedure;
    EXECUTE format('ALTER FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT) OWNER TO %I', v_owner);
    -- CREATE may inherit named-role grants from ALTER DEFAULT PRIVILEGES.
    -- Remove them before copying the existing function's exact caller set.
    FOR v_grantee IN
        SELECT pg_get_userbyid(privilege.grantee) AS role_name
        FROM pg_proc AS function_row
        CROSS JOIN LATERAL aclexplode(COALESCE(function_row.proacl,
            acldefault('f', function_row.proowner))) AS privilege
        WHERE function_row.oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT)'::regprocedure
          AND privilege.privilege_type = 'EXECUTE'
          AND privilege.grantee NOT IN (0, function_row.proowner)
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT) FROM %I', v_grantee.role_name);
    END LOOP;
    FOR v_grantee IN
        SELECT pg_get_userbyid(privilege.grantee) AS role_name, privilege.is_grantable
        FROM pg_proc AS function_row
        CROSS JOIN LATERAL aclexplode(COALESCE(function_row.proacl,
            acldefault('f', function_row.proowner))) AS privilege
        WHERE function_row.oid = 'public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB)'::regprocedure
          AND privilege.privilege_type = 'EXECUTE' AND privilege.grantee <> 0
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB, BIGINT) TO %I%s',
            v_grantee.role_name,
            CASE WHEN v_grantee.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_commit_authorization_decision(p_tenant_id uuid, p_user_id uuid, p_client_id text, p_request_id text, p_par_uri text, p_valid_until timestamp with time zone, p_retain_until timestamp with time zone, p_decision text, p_event_id uuid, p_occurred_at timestamp with time zone, p_audit_fields jsonb, p_scopes jsonb, p_resources jsonb, p_authorization_details jsonb) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET lock_timeout TO '2s'
    AS $_$
DECLARE
    v_user_epoch BIGINT;
    v_outcome TEXT;
BEGIN
    -- Older service versions already checked their session before this call.
    -- Do not lock the actor here: the accepting function owns client -> user
    -- lock order, and rejects any generation change after this snapshot.
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
