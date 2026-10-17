-- Final PostgreSQL schema and initial facts of NazoAuth v0.3.2.
-- Earlier transformations remain in the v0.3.2 Git tag.
-- Diesel runs this block and records its version in the same transaction,
-- under the existing migration advisory lock.
DO $baseline$
DECLARE
    inherited_grant RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM __diesel_schema_migrations WHERE version = '20261017000300') THEN
        -- The released cutoff already has this schema. Keep all data, object
        -- identities, owners and grants; only Diesel's new version is recorded.
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM __diesel_schema_migrations) THEN
        RAISE EXCEPTION 'migration baseline requires NazoAuth v0.3.2: upgrade with v0.3.2 before this release';
    END IF;

    -- Functions precede their referenced tables in the canonical schema.
    SET LOCAL check_function_bodies = false;

CREATE FUNCTION public.nazo_ack_security_audit_batch(p_generation bigint, p_first_sequence bigint, p_last_sequence bigint, p_event_count integer, p_last_hash bytea, p_batch_digest bytea, p_deployment_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_anchor BIGINT;
    v_members BIGINT;
    v_deleted INTEGER;
    v_retained INTEGER;
    v_ids UUID[];
    v_occurred_at TIMESTAMPTZ;
    v_exported_at TIMESTAMPTZ;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255
       OR p_event_count IS NULL OR p_event_count NOT BETWEEN 1 AND 256
       OR p_last_hash IS NULL OR octet_length(p_last_hash) <> 32
       OR p_batch_digest IS NULL OR octet_length(p_batch_digest) <> 32 THEN
        RAISE EXCEPTION 'audit batch acknowledgement arguments are invalid';
    END IF;
    SELECT state.anchor_sequence INTO v_anchor
    FROM public.security_audit_chain_state AS state
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND (state.anchor_deployment_id IS NULL OR state.anchor_deployment_id = p_deployment_id)
      AND state.batch_generation = p_generation
      AND state.batch_first_sequence = p_first_sequence
      AND state.batch_last_sequence = p_last_sequence
      AND state.batch_event_count = p_event_count
      AND state.batch_digest = p_batch_digest
    FOR UPDATE OF state;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF p_first_sequence <> COALESCE(v_anchor, 0) + 1 THEN
        RAISE EXCEPTION 'audit batch acknowledgement does not continue the anchor checkpoint';
    END IF;
    -- Start from the committed prefix, never the estimated pending set.
    -- The extra member preserves rejection of an oversized prefix; the later
    -- DELETE row-count check still rejects corruption beyond this bound.
    WITH members AS MATERIALIZED (
        SELECT chain.event_id FROM public.security_audit_chain_entries AS chain
        WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence
        ORDER BY chain.sequence LIMIT 257
    )
    SELECT COUNT(*), COALESCE(array_agg(event.event_id), '{}'::UUID[]) INTO v_members, v_ids
    FROM members
    CROSS JOIN LATERAL (
        SELECT event.event_id, event.exported_at
        FROM public.security_audit_events AS event
        WHERE event.event_id = members.event_id LIMIT 1
    ) AS event
    WHERE event.exported_at IS NULL;
    IF v_members <> p_event_count OR NOT EXISTS (
        SELECT 1 FROM public.security_audit_chain_entries AS chain
        WHERE chain.sequence = p_last_sequence AND chain.event_hash = p_last_hash
    ) THEN
        RAISE EXCEPTION 'audit batch members no longer form the committed prefix';
    END IF;
    SELECT event.occurred_at INTO v_occurred_at
    FROM public.security_audit_chain_entries AS chain
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
    WHERE chain.sequence = p_last_sequence;

    -- Sample once after the head lock and complete batch validation. This is
    -- the ACK operation time, shared by retained facts and both checkpoints.
    v_exported_at := clock_timestamp();

    -- Chain proof is delivery-only. Decision rows also own business fences;
    -- retain their immutable business fields, but release delivered payload
    -- in this same validated ACK transaction. Failed/unknown commits never
    -- become permission to release an unacknowledged payload.
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
    DELETE FROM public.security_audit_chain_entries AS chain
    WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement reclaimed an unexpected chain count';
    END IF;
    PERFORM set_config('nazo.audit_ack', 'on', true);
    UPDATE public.security_audit_events AS event
    SET exported_at = v_exported_at, payload = '{}'::JSONB
    WHERE event.event_id = ANY(v_ids)
      AND event.event_type = 'authorization_decision_committed'
      AND event.exported_at IS NULL;
    GET DIAGNOSTICS v_retained = ROW_COUNT;
    PERFORM set_config('nazo.audit_ack', 'off', true);
    DELETE FROM public.security_audit_events AS event
    WHERE event.event_id = ANY(v_ids)
      AND event.event_type <> 'authorization_decision_committed';
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted + v_retained <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement reclaimed an unexpected event count';
    END IF;
    PERFORM set_config('nazo.audit_reclaim', 'off', true);

    UPDATE public.security_audit_chain_state AS state
    SET anchor_deployment_id = p_deployment_id,
        anchor_sequence = p_last_sequence,
        anchor_hash = p_last_hash,
        anchor_occurred_at = v_occurred_at,
        anchor_accepted_at = v_exported_at,
        anchor_observed_at = v_exported_at,
        batch_first_sequence = NULL, batch_last_sequence = NULL,
        batch_event_count = NULL, batch_digest = NULL,
        batch_attempts = 0, batch_available_at = NULL, batch_locked_until = NULL,
        batch_last_error = NULL, batch_blocked_reason = NULL
    WHERE state.singleton;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION public.nazo_advance_access_token_epoch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.is_active AND NOT NEW.is_active THEN
        NEW.access_token_epoch := OLD.access_token_epoch + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_bump_tenant_runtime_directory_revision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF TG_TABLE_NAME = 'tenants' THEN
        IF TG_OP <> 'TRUNCATE' AND NOT EXISTS (
            SELECT 1 FROM public.tenant_runtime_bindings WHERE tenant_id = NEW.id
        ) THEN
            RETURN NULL;
        END IF;
    ELSIF TG_TABLE_NAME = 'realms' THEN
        IF TG_OP <> 'TRUNCATE' AND NOT EXISTS (
            SELECT 1 FROM public.tenant_runtime_bindings WHERE realm_id = NEW.id
        ) THEN
            RETURN NULL;
        END IF;
    ELSIF TG_TABLE_NAME = 'organizations' THEN
        IF TG_OP <> 'TRUNCATE' AND NOT EXISTS (
            SELECT 1 FROM public.tenant_runtime_bindings WHERE organization_id = NEW.id
        ) THEN
            RETURN NULL;
        END IF;
    END IF;

    UPDATE public.tenant_runtime_directory_state
    SET revision = revision + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE singleton;
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.nazo_claim_security_audit_pending(p_limit bigint) RETURNS TABLE(event_id uuid, sequence bigint, event_type text, event_category text, payload_canonical text, occurred_at timestamp with time zone, previous_hash bytea, event_hash bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET enable_seqscan TO 'off'
    SET enable_bitmapscan TO 'off'
    AS $$
DECLARE
    v_claimed INTEGER;
    v_anchor BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'audit pending claim bounds are invalid';
    END IF;
    SELECT COALESCE(
        (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
         WHERE state.singleton), 0)
    INTO v_anchor;
    -- In-flight batch prefix: bound identities on the sequence index first,
    -- then resolve each row through the event primary key. LIMIT 1 preserves
    -- the parameterized lookup; a plain join can scan the entire event index
    -- even when the candidate CTE itself contains at most 256 identities.
    RETURN QUERY
    WITH chained AS MATERIALIZED (
        SELECT chain.event_id, chain.sequence, chain.previous_hash, chain.event_hash
        FROM public.security_audit_chain_entries AS chain
        WHERE chain.sequence > v_anchor
        ORDER BY chain.sequence
        LIMIT p_limit
    )
    SELECT event.event_id, chained.sequence, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           chained.previous_hash, chained.event_hash
    FROM chained
    CROSS JOIN LATERAL (
        SELECT candidate.event_id, candidate.event_type, candidate.event_category,
               candidate.payload, candidate.occurred_at
        FROM public.security_audit_events AS candidate
        WHERE candidate.event_id = chained.event_id AND candidate.exported_at IS NULL
        LIMIT 1
    ) AS event
    ORDER BY chained.sequence;
    GET DIAGNOSTICS v_claimed = ROW_COUNT;
    IF v_claimed > 0 THEN RETURN; END IF;
    -- Only unexported rows participate; retained business facts are not pending.
    -- Read full rows directly through the ordered index. A bounded ID CTE
    -- followed by a self-join adds no information and can scan the backlog.
    RETURN QUERY
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM public.security_audit_events AS event
    WHERE event.exported_at IS NULL
    ORDER BY event.occurred_at, event.event_id
    LIMIT p_limit;
END;
$$;

CREATE FUNCTION public.nazo_cleanup_authorization_decisions() RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_deleted BIGINT;
BEGIN
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
    WITH due AS MATERIALIZED (
        SELECT event.event_id FROM public.security_audit_events AS event
        WHERE event.event_type = 'authorization_decision_committed'
          AND event.exported_at IS NOT NULL
          AND event.business_retain_until <= CURRENT_TIMESTAMP
        ORDER BY event.business_retain_until, event.event_id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.security_audit_events AS event USING due
    WHERE event.event_id = due.event_id
      AND event.exported_at IS NOT NULL
      AND event.business_retain_until <= CURRENT_TIMESTAMP;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    PERFORM set_config('nazo.audit_reclaim', 'off', true);
    RETURN v_deleted;
END;
$$;

CREATE FUNCTION public.nazo_client_security_policy_is_current(policy jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$
    SELECT jsonb_typeof(policy) = 'object'
       AND policy ?& ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ]
       AND policy - ARRAY[
            'version', 'assurance', 'require_pushed_authorization_requests',
            'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ] = '{}'::jsonb
       AND jsonb_typeof(policy -> 'version') = 'number'
       AND policy ->> 'version' = '1'
       AND jsonb_typeof(policy -> 'assurance') = 'string'
       AND policy ->> 'assurance' IN ('baseline', 'fapi2')
       AND (
            NOT policy ? 'require_pushed_authorization_requests'
            OR jsonb_typeof(policy -> 'require_pushed_authorization_requests') = 'boolean'
       )
       AND jsonb_typeof(policy -> 'require_signed_authorization_request') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_authorization_response') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_introspection_response') = 'boolean'
       AND jsonb_typeof(policy -> 'session_management') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_cross_device_flows') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_confidential_oidc_without_pkce') = 'boolean';
$$;

CREATE FUNCTION public.nazo_commit_authorization_decision(p_tenant_id uuid, p_user_id uuid, p_client_id text, p_request_id text, p_par_uri text, p_valid_until timestamp with time zone, p_retain_until timestamp with time zone, p_decision text, p_event_id uuid, p_occurred_at timestamp with time zone, p_audit_fields jsonb, p_scopes jsonb, p_resources jsonb, p_authorization_details jsonb) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET lock_timeout TO '2s'
    AS $_$
DECLARE
    v_client_id UUID;
    v_active BOOLEAN;
    v_payload JSONB;
    v_inserted INTEGER;
    v_digest_key TEXT;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_user_id IS NULL OR p_user_id = '00000000-0000-0000-0000-000000000000'::UUID
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
    SELECT actor.is_active INTO v_active FROM public.users AS actor
    WHERE actor.tenant_id = p_tenant_id AND actor.id = p_user_id
    FOR SHARE OF actor;
    IF NOT FOUND OR NOT v_active THEN RETURN 'client_unavailable'; END IF;
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

CREATE FUNCTION public.nazo_create_refresh_family(p_tenant uuid, p_family uuid, p_client uuid, p_user uuid, p_contract_key bytea, p_contract jsonb, p_member uuid, p_token_digest bytea, p_audience jsonb, p_issued_at timestamp with time zone, p_expires_at timestamp with time zone, p_sid text, p_dpop text, p_mtls text, p_attestation text, p_scope_lock bigint, p_max_families bigint, p_issuance uuid, p_native_source uuid, p_audit_schema text) RETURNS TABLE(outcome text, retired_source jsonb)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET plan_cache_mode TO 'force_custom_plan'
    AS $$
DECLARE
    v_victim UUID;
    v_revoked RECORD;
    v_hex TEXT;
BEGIN
    IF p_max_families IS NULL OR p_max_families < 1 THEN
        RAISE EXCEPTION 'invalid refresh family capacity';
    END IF;
    PERFORM pg_advisory_xact_lock(p_scope_lock);
    -- Same big-endian UUID-half XOR as refresh_family_lock_key and maintenance.
    v_hex := replace(p_family::TEXT, '-', '');
    PERFORM pg_advisory_xact_lock(
        ('x' || substr(v_hex, 1, 16))::BIT(64)::BIGINT #
        ('x' || substr(v_hex, 17, 16))::BIT(64)::BIGINT);
    IF EXISTS (SELECT 1 FROM public.oauth_refresh_families
               WHERE tenant_id=p_tenant AND token_family_id=p_family) THEN
        UPDATE public.oauth_refresh_families
        SET reuse_detected_at=CURRENT_TIMESTAMP,
            revoked_at=COALESCE(revoked_at, CURRENT_TIMESTAMP)
        WHERE tenant_id=p_tenant AND token_family_id=p_family
          AND reuse_detected_at IS NULL;
        outcome := 'conflict';
        RETURN NEXT;
        RETURN;
    END IF;
    IF p_user IS NOT NULL THEN
        FOR v_victim IN
            WITH ranked AS (
                SELECT token_family_id, current_issued_at,
                       row_number() OVER (ORDER BY current_issued_at, token_family_id) AS rn,
                       count(*) OVER () AS total
                FROM public.oauth_refresh_families
                WHERE tenant_id=p_tenant AND user_id=p_user AND client_id=p_client
                  AND revoked_at IS NULL AND reuse_detected_at IS NULL
                  AND current_expires_at>CURRENT_TIMESTAMP
            ) SELECT token_family_id FROM ranked WHERE rn<=total-(p_max_families-1)
              ORDER BY current_issued_at, token_family_id
        LOOP
            v_hex := replace(v_victim::TEXT, '-', '');
            PERFORM pg_advisory_xact_lock(
                ('x' || substr(v_hex, 1, 16))::BIT(64)::BIGINT #
                ('x' || substr(v_hex, 17, 16))::BIT(64)::BIGINT);
            UPDATE public.oauth_refresh_families AS family
            SET revoked_at=CURRENT_TIMESTAMP
            WHERE family.tenant_id=p_tenant AND family.token_family_id=v_victim
              AND family.revoked_at IS NULL AND family.reuse_detected_at IS NULL
              AND family.current_expires_at>CURRENT_TIMESTAMP
            RETURNING family.tenant_id, family.user_id, family.token_family_id,
                      family.current_expires_at AS expires_at,
                      (SELECT client.client_id FROM public.oauth_clients AS client
                       WHERE client.tenant_id=family.tenant_id AND client.id=family.client_id)
                          AS source_client_id
            INTO v_revoked;
            IF NOT FOUND THEN CONTINUE; END IF;
            IF p_native_source=v_revoked.token_family_id THEN
                retired_source := to_jsonb(v_revoked);
            END IF;
            IF NOT public.nazo_persist_security_audit_event(
                uuidv7(), 'refresh_family_capacity_retired', 'token_lifecycle',
                jsonb_build_object(
                    'schema_version', p_audit_schema, 'tenant_id', p_tenant,
                    'issuance_id', p_issuance, 'event_category', 'token_lifecycle',
                    'token_family_id', v_victim, 'client_id', p_client, 'user_id', p_user,
                    'reason', 'active_family_cap', 'max_active_families', p_max_families),
                clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'fresh refresh retirement audit identity already exists';
            END IF;
        END LOOP;
    END IF;
    -- Retains the existing collision validation and KEY SHARE reclaim fence.
    PERFORM public.nazo_oauth_refresh_contract_ensure(p_tenant,p_contract_key,p_contract);
    INSERT INTO public.oauth_refresh_families (
        tenant_id, token_family_id, client_id, user_id, contract_blake3,
        current_member_id, current_token_blake3, current_audience,
        current_issued_at, current_expires_at, current_id_token_sid,
        dpop_jkt, mtls_x5t_s256, client_attestation_jkt, created_at
    ) VALUES (
        p_tenant,p_family,p_client,p_user,p_contract_key,p_member,p_token_digest,p_audience,
        p_issued_at,p_expires_at,p_sid,p_dpop,p_mtls,p_attestation,p_issued_at
    );
    outcome := 'inserted';
    RETURN NEXT;
END;
$$;

CREATE FUNCTION public.nazo_fail_security_audit_batch(p_generation bigint, p_available_at timestamp with time zone, p_last_error text, p_blocked boolean) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_available_at IS NULL
       OR p_available_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes'
       OR p_last_error IS NULL OR char_length(p_last_error) > 128 THEN
        RAISE EXCEPTION 'audit batch failure arguments are invalid';
    END IF;
    UPDATE public.security_audit_chain_state AS state
    SET batch_locked_until = NULL,
        batch_available_at = p_available_at,
        batch_attempts = state.batch_attempts + 1,
        batch_last_error = left(p_last_error, 128),
        batch_blocked_reason = CASE WHEN p_blocked THEN left(p_last_error, 128) ELSE NULL END
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND state.batch_generation = p_generation;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_finalize_security_audit_claim(p_previous_sequence bigint, p_previous_hash bytea, p_event_ids uuid[], p_event_hashes bytea[], p_first_sequence bigint, p_last_sequence bigint, p_event_count integer, p_batch_digest bytea, p_lock_timeout_seconds integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_head RECORD;
    v_generation BIGINT;
BEGIN
    IF p_first_sequence IS NULL OR p_last_sequence IS NULL
       OR p_event_count IS NULL OR p_batch_digest IS NULL
       OR octet_length(p_batch_digest) <> 32
       OR p_lock_timeout_seconds IS NULL OR p_lock_timeout_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'audit batch open arguments are invalid';
    END IF;
    SELECT * INTO STRICT v_head
    FROM public.nazo_stage_security_audit_chain(
        p_previous_sequence, p_previous_hash, p_event_ids, p_event_hashes
    );
    UPDATE public.security_audit_chain_state AS state
    SET last_sequence = v_head.last_sequence,
        last_hash = v_head.last_hash,
        batch_first_sequence = p_first_sequence,
        batch_last_sequence = p_last_sequence,
        batch_event_count = p_event_count,
        batch_digest = p_batch_digest,
        batch_generation = state.batch_generation + 1,
        batch_attempts = 0,
        batch_available_at = CURRENT_TIMESTAMP,
        batch_locked_until = CURRENT_TIMESTAMP + (p_lock_timeout_seconds * INTERVAL '1 second'),
        batch_last_error = NULL,
        batch_blocked_reason = NULL
    WHERE state.singleton AND state.batch_last_sequence IS NULL
      AND p_first_sequence = COALESCE(state.anchor_sequence, 0) + 1
      AND p_last_sequence >= p_first_sequence
      AND p_last_sequence <= v_head.last_sequence
      AND p_event_count = p_last_sequence - p_first_sequence + 1
      AND p_event_count BETWEEN 1 AND 256
    RETURNING state.batch_generation INTO v_generation;
    IF v_generation IS NULL THEN
        -- The exception also rolls back every staged proof in this statement.
        RAISE EXCEPTION 'audit batch open conflicts with the committed chain state';
    END IF;
    RETURN v_generation;
END;
$$;

CREATE FUNCTION public.nazo_guard_active_tenant_resource_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    managed_kind VARCHAR(64);
    managed_locator TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'users'
       AND (to_jsonb(OLD) - 'updated_at' - 'mfa_enabled')
           = (to_jsonb(NEW) - 'updated_at' - 'mfa_enabled') THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'oauth_clients'
       AND (to_jsonb(OLD) - 'updated_at') = (to_jsonb(NEW) - 'updated_at') THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'users' THEN
        managed_kind := 'user';
        managed_locator := 'user/' || OLD.id::text;
    ELSIF TG_TABLE_NAME = 'oauth_clients' THEN
        managed_kind := 'oauth-client';
        managed_locator := 'oauth-client/' || OLD.id::text;
    ELSE
        RAISE EXCEPTION 'tenant resource ownership guard attached to unsupported table'
            USING ERRCODE = '55006';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM tenant_resource_bindings binding
        WHERE binding.tenant_id = OLD.tenant_id
          AND binding.resource_kind = managed_kind
          AND binding.locator = managed_locator
          AND binding.active
    ) THEN
        RAISE EXCEPTION 'active tenant resource must be changed through its signed change set'
            USING ERRCODE = '55006';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE FUNCTION public.nazo_guard_openid4vc_trust_policy_client_generation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (NOT OLD.active AND NEW.active)
       OR OLD.policy_id <> NEW.policy_id
       OR OLD.tenant_id <> NEW.tenant_id
       OR OLD.oauth_client_id <> NEW.oauth_client_id THEN
        RAISE EXCEPTION 'OpenID4VC trust policy client bindings are immutable and cannot reactivate'
            USING ERRCODE = '55006';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_guard_openid4vc_trust_policy_generation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (NOT OLD.active AND NEW.active)
       OR OLD.tenant_id <> NEW.tenant_id
       OR OLD.resource_id <> NEW.resource_id
       OR OLD.resource_digest <> NEW.resource_digest
       OR OLD.public_material <> NEW.public_material
       OR OLD.wallet_origins <> NEW.wallet_origins
       OR OLD.source <> NEW.source THEN
        RAISE EXCEPTION 'OpenID4VC trust policy generations are immutable and cannot reactivate'
            USING ERRCODE = '55006';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_lock_token_principals(p_tenant uuid, p_client uuid, p_client_epoch bigint, p_user uuid, p_user_epoch bigint) RETURNS TABLE(outcome text, client_type text)
    LANGUAGE plpgsql
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

CREATE FUNCTION public.nazo_oauth_cleanup_expired_security_state(p_include_history boolean) RETURNS TABLE(deleted_issuances integer, deleted_access_token_revocations integer, deleted_scim_audit_events integer, deleted_backchannel_logout_deliveries integer, deleted_scim_security_events integer, deleted_remembered_mfa_devices integer, deleted_identity_approvals integer)
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

    deleted_remembered_mfa_devices := 0;
    IF p_include_history THEN
        WITH due AS (
            SELECT tenant_id, token_hash FROM user_mfa_remembered_devices
            WHERE expires_at <= v_cutoff
            ORDER BY expires_at
            LIMIT 256 FOR UPDATE SKIP LOCKED
        )
        DELETE FROM user_mfa_remembered_devices AS target
        USING due WHERE target.tenant_id = due.tenant_id AND target.token_hash = due.token_hash;
        GET DIAGNOSTICS deleted_remembered_mfa_devices = ROW_COUNT;
    END IF;

    deleted_identity_approvals := 0;
    IF p_include_history THEN
        WITH due AS (
            SELECT approval_id FROM controller_identity_approvals
            WHERE expires_at <= v_cutoff
            ORDER BY expires_at, approval_id
            LIMIT 256 FOR UPDATE SKIP LOCKED
        )
        DELETE FROM controller_identity_approvals AS target
        USING due WHERE target.approval_id = due.approval_id;
        GET DIAGNOSTICS deleted_identity_approvals = ROW_COUNT;
    END IF;

    RETURN NEXT;
END;
$$;

CREATE FUNCTION public.nazo_oauth_refresh_contract_ensure(p_tenant_id uuid, p_contract_blake3 bytea, p_contract jsonb) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_inserted INTEGER;
BEGIN
    FOR attempt IN 1..3 LOOP
        PERFORM 1 FROM public.oauth_refresh_contracts AS contract
        WHERE contract.tenant_id = p_tenant_id
          AND contract.contract_blake3 = p_contract_blake3
        FOR KEY SHARE OF contract;
        IF FOUND THEN RETURN; END IF;
        INSERT INTO public.oauth_refresh_contracts (tenant_id, contract_blake3, contract)
        VALUES (p_tenant_id, p_contract_blake3, p_contract)
        ON CONFLICT (tenant_id, contract_blake3) DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 1 THEN RETURN; END IF;
        -- A concurrent creator or reclaimer changed the row; obtain its lock
        -- or create the missing row in the next statement snapshot.
    END LOOP;
    RAISE EXCEPTION 'oauth refresh contract could not be safely referenced';
END;
$$;

COMMENT ON FUNCTION public.nazo_oauth_refresh_contract_ensure(p_tenant_id uuid, p_contract_blake3 bytea, p_contract jsonb) IS 'Content-addressed contract reference with KEY SHARE reclamation protection and bounded create/reclaim retry.';

CREATE FUNCTION public.nazo_oauth_validate_mtls_trust_event_actor() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    request_source VARCHAR(32);
BEGIN
    SELECT source INTO request_source
    FROM oauth_client_mtls_trust_anchor_requests
    WHERE tenant_id = NEW.tenant_id AND id = NEW.request_id;
    IF request_source IS NULL THEN
        RAISE EXCEPTION 'mTLS trust event request does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF request_source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session trust events require an actor'
            USING ERRCODE = '23514';
    END IF;
    IF request_source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed trust events cannot carry a user actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_oauth_validate_openid4vci_dataset_event_actor() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session dataset events require a user actor'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed dataset events cannot carry a user actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    -- Sample observation time after the shared row lock has been acquired.
    -- Wrong deployment identity cannot lock an observation into another owner.
    PERFORM 1 FROM public.security_audit_chain_state
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id)
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = COALESCE(anchor_deployment_id, p_deployment_id),
        anchor_observed_at = clock_timestamp()
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    RETURN FOUND;
END;
$$;

CREATE FUNCTION public.nazo_openid4vp_cleanup_expired_transactions() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_transactions INTEGER := 0;
BEGIN
    WITH expired AS (
        SELECT id
        FROM openid4vp_transactions
        WHERE expires_at <= CURRENT_TIMESTAMP
        ORDER BY expires_at, id
        LIMIT 256
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM openid4vp_transactions AS target
    USING expired
    WHERE target.id = expired.id;
    GET DIAGNOSTICS deleted_transactions = ROW_COUNT;
    RETURN deleted_transactions;
END;
$$;

CREATE FUNCTION public.nazo_persist_security_audit_event(p_event_id uuid, p_event_type text, p_event_category text, p_payload jsonb, p_occurred_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_inserted INTEGER;
BEGIN
    IF p_event_type = 'authorization_decision_committed' THEN
        RAISE EXCEPTION 'authorization decision requires its atomic commit API';
    END IF;
    IF p_event_id IS NULL OR p_event_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_payload IS NULL OR octet_length(convert_to(p_payload::text, 'UTF8')) > 65536 THEN
        RAISE EXCEPTION 'invalid security audit event';
    END IF;
    INSERT INTO public.security_audit_events (event_id, event_type, event_category, payload, occurred_at)
    VALUES (p_event_id, p_event_type, p_event_category, p_payload, p_occurred_at)
    ON CONFLICT (event_id) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted = 0 THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.security_audit_events AS event
            WHERE event.event_id = p_event_id AND event.event_type = p_event_type
              AND event.event_category = p_event_category AND event.payload = p_payload
              AND event.occurred_at = p_occurred_at
        ) THEN
            RAISE EXCEPTION 'security audit event id collision';
        END IF;
        RETURN FALSE;
    END IF;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION public.nazo_reclaim_security_audit_batch(p_batch_digest bytea, p_lock_timeout_seconds integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_generation BIGINT;
BEGIN
    IF p_batch_digest IS NULL OR octet_length(p_batch_digest) <> 32
       OR p_lock_timeout_seconds IS NULL OR p_lock_timeout_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'audit batch reclaim arguments are invalid';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no in-flight audit batch to re-claim';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton
      AND (state.batch_digest IS NULL OR state.batch_digest = p_batch_digest);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit batch content digest changed under the lease';
    END IF;
    UPDATE public.security_audit_chain_state AS state
    SET batch_generation = state.batch_generation + 1,
        batch_digest = p_batch_digest,
        batch_locked_until = CURRENT_TIMESTAMP + (p_lock_timeout_seconds * INTERVAL '1 second')
    WHERE state.singleton
      AND (state.batch_locked_until IS NULL OR state.batch_locked_until <= CURRENT_TIMESTAMP)
      AND (state.batch_available_at IS NULL OR state.batch_available_at <= CURRENT_TIMESTAMP)
      AND state.batch_blocked_reason IS NULL
    RETURNING state.batch_generation INTO v_generation;
    IF v_generation IS NULL THEN
        RAISE EXCEPTION 'audit batch lease is not claimable';
    END IF;
    RETURN v_generation;
END;
$$;

CREATE FUNCTION public.nazo_record_security_audit_genesis(p_deployment_id text, p_head_hash bytea) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255
       OR p_head_hash IS NULL OR octet_length(p_head_hash) <> 32 THEN
        RAISE EXCEPTION 'audit anchor genesis is invalid';
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = p_deployment_id,
        anchor_sequence = 0,
        anchor_hash = p_head_hash,
        anchor_occurred_at = 'epoch'::TIMESTAMPTZ,
        anchor_accepted_at = CURRENT_TIMESTAMP,
        anchor_observed_at = CURRENT_TIMESTAMP
    WHERE singleton IS TRUE AND last_sequence = 0 AND last_hash = p_head_hash
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_recovery_invalidations_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'recovery invalidations are append-only' USING ERRCODE = '55006';
END;
$$;

CREATE FUNCTION public.nazo_refresh_contract_well_formed(contract jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $_$
    -- COALESCE guards the CHECK semantics: jsonb_path_match on a missing key
    -- yields NULL, and a CHECK constraint accepts NULL. NULL must fail.
    SELECT COALESCE(
       contract IS NOT NULL
       AND jsonb_path_match(contract, '$.type() == "object"')
       AND jsonb_path_match(contract -> 'subject', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'scopes', '$.type() == "array" && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'audiences', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'authorization_details', '$.type() == "array"')
       AND jsonb_path_match(contract -> 'authentication_context', '$.type() == "object"')
       AND (contract #>> '{authentication_context,version}')::INT IN (1, 2)
       AND jsonb_path_match(contract -> 'authentication_context' -> 'issuer', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'audience', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND (contract #>> '{authentication_context,auth_time}')::BIGINT > 0
       AND jsonb_path_match(contract -> 'authentication_context' -> 'amr', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND COALESCE(contract #>> '{authentication_context,nonce}', '') = ''
       AND COALESCE(contract #>> '{authentication_context,id_token_sid}', '') = ''
       AND CASE (contract #>> '{authentication_context,version}')::INT
         WHEN 1 THEN
           jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
         WHEN 2 THEN
           NOT ((contract -> 'authentication_context') ? 'userinfo_claims')
           AND NOT ((contract -> 'authentication_context') ? 'id_token_claims')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claim_requests', '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string" || @.name like_regex "^\\s*$" || (exists(@.essential) && @.essential.type() != "boolean") || (exists(@.values) && @.values.type() != "array")))')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claim_requests', '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string" || @.name like_regex "^\\s*$" || (exists(@.essential) && @.essential.type() != "boolean") || (exists(@.values) && @.values.type() != "array")))')
         ELSE FALSE
       END,
       FALSE
    );
$_$;

CREATE FUNCTION public.nazo_reject_security_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'security_audit_events' THEN
        IF current_setting('nazo.audit_ack', true) IS NOT DISTINCT FROM 'on'
           AND OLD.event_type = 'authorization_decision_committed'
           AND OLD.exported_at IS NULL AND NEW.exported_at IS NOT NULL
           AND isfinite(NEW.exported_at)
           AND (to_jsonb(OLD) - ARRAY['exported_at', 'payload']) =
               (to_jsonb(NEW) - ARRAY['exported_at', 'payload'])
           AND NEW.payload = '{}'::JSONB THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' AND current_setting('nazo.audit_reclaim', true) IS NOT DISTINCT FROM 'on' THEN
        IF TG_TABLE_NAME = 'security_audit_events' THEN
            IF OLD.event_type = 'authorization_decision_committed'
               AND (OLD.exported_at IS NULL OR OLD.business_retain_until > clock_timestamp()) THEN
                RAISE EXCEPTION 'authorization decision still owns a live consumption fence';
            END IF;
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security audit ledger is append-only';
END;
$$;

CREATE FUNCTION public.nazo_revoke_refresh_on_client_public() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_family RECORD;
    v_occurred_at TIMESTAMPTZ := CURRENT_TIMESTAMP;
BEGIN
    FOR v_family IN
        UPDATE public.oauth_refresh_families AS family
        SET revoked_at = v_occurred_at
        WHERE family.tenant_id = NEW.tenant_id AND family.client_id = NEW.id
          AND family.revoked_at IS NULL
        RETURNING family.token_family_id
    LOOP
        -- Required evidence shares the client UPDATE transaction. An audit
        -- failure rolls back the class change and every family revocation.
        PERFORM public.nazo_persist_security_audit_event(
            gen_random_uuid(), 'refresh_family_security_revoked', 'token_lifecycle',
            jsonb_build_object(
                'schema_version', 'nazo.audit.v1',
                'tenant_id', NEW.tenant_id,
                'token_family_id', v_family.token_family_id,
                'client_id', NEW.id,
                'event_category', 'token_lifecycle',
                'reason', 'client_authentication_class_downgrade'
            ), v_occurred_at
        );
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.nazo_security_audit_batch_members() RETURNS TABLE(event_id uuid, sequence bigint, event_type text, event_category text, payload_canonical text, occurred_at timestamp with time zone, previous_hash bytea, event_hash bytea)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    SELECT event.event_id, chain.sequence, event.event_type::TEXT, event.event_category::TEXT,
           event.payload::TEXT, event.occurred_at,
           chain.previous_hash, chain.event_hash
    FROM public.security_audit_chain_state AS state
    JOIN public.security_audit_chain_entries AS chain
      ON chain.sequence > COALESCE(state.anchor_sequence, 0)
     AND chain.sequence <= state.batch_last_sequence
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND event.exported_at IS NULL
    ORDER BY chain.sequence
$$;

CREATE FUNCTION public.nazo_security_audit_chain_head_for_update() RETURNS TABLE(last_sequence bigint, last_hash bytea, anchor_sequence bigint, anchor_hash bytea, anchor_deployment_id text, batch_first_sequence bigint, batch_last_sequence bigint, batch_event_count integer, batch_digest bytea, batch_generation bigint, batch_attempts integer, batch_available_at timestamp with time zone, batch_locked_until timestamp with time zone, batch_last_error text, batch_blocked_reason text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    SELECT state.last_sequence, state.last_hash,
           state.anchor_sequence, state.anchor_hash, state.anchor_deployment_id::TEXT,
           state.batch_first_sequence, state.batch_last_sequence, state.batch_event_count,
           state.batch_digest, state.batch_generation, state.batch_attempts,
           state.batch_available_at, state.batch_locked_until,
           state.batch_last_error, state.batch_blocked_reason
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE
$$;

CREATE FUNCTION public.nazo_security_audit_shared_anchor_health() RETURNS TABLE(last_sequence bigint, last_hash bytea, chain_valid boolean, pending_exists boolean, pending_estimate bigint, pending_orphan_exists boolean, oldest_pending_occurred_at timestamp with time zone, anchor_deployment_id text, anchor_sequence bigint, anchor_hash bytea, anchor_occurred_at timestamp with time zone, anchor_accepted_at timestamp with time zone, anchor_observed_at timestamp with time zone, batch_first_sequence bigint, batch_last_sequence bigint, batch_event_count integer, batch_generation bigint, batch_attempts integer, batch_available_at timestamp with time zone, batch_locked_until timestamp with time zone, batch_last_error text, batch_blocked_reason text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    WITH head AS (
        SELECT chain.sequence, chain.event_hash FROM public.security_audit_chain_entries AS chain
        ORDER BY chain.sequence DESC LIMIT 1
    ), backlog AS (
        SELECT EXISTS (SELECT 1 FROM public.security_audit_events WHERE exported_at IS NULL) AS pending_exists,
               (SELECT event.occurred_at FROM public.security_audit_events AS event
                WHERE event.exported_at IS NULL
                ORDER BY event.occurred_at, event.event_id LIMIT 1) AS oldest_pending_occurred_at,
               EXISTS (
                   SELECT 1 FROM public.security_audit_chain_entries AS chain
                   WHERE chain.sequence <= COALESCE(
                       (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
                        WHERE state.singleton), -1)
               ) AS pending_orphan_exists,
               GREATEST(relation.reltuples, 0)::BIGINT AS pending_estimate
        FROM pg_class AS relation
        WHERE relation.oid = 'public.idx_security_audit_events_pending_order'::REGCLASS
    )
    SELECT state.last_sequence, state.last_hash,
           (head.sequence IS NULL AND state.last_sequence = 0 AND state.last_hash = decode(repeat('00',32),'hex'))
            OR (head.sequence IS NULL AND state.last_sequence > 0 AND state.last_sequence = state.anchor_sequence)
            OR (head.sequence = state.last_sequence AND head.event_hash = state.last_hash),
           backlog.pending_exists, backlog.pending_estimate, backlog.pending_orphan_exists,
           backlog.oldest_pending_occurred_at,
           state.anchor_deployment_id::TEXT, state.anchor_sequence, state.anchor_hash,
           state.anchor_occurred_at, state.anchor_accepted_at, state.anchor_observed_at,
           state.batch_first_sequence, state.batch_last_sequence, state.batch_event_count,
           state.batch_generation, state.batch_attempts,
           state.batch_available_at, state.batch_locked_until,
           state.batch_last_error, state.batch_blocked_reason
    FROM public.security_audit_chain_state AS state
    LEFT JOIN head ON TRUE CROSS JOIN backlog WHERE state.singleton
$$;

CREATE FUNCTION public.nazo_security_audit_shared_privilege_preflight(p_require_least_privilege boolean, p_require_append boolean, p_require_exporter boolean) RETURNS TABLE(policy_satisfied boolean)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    WITH RECURSIVE login_role(oid) AS (
        SELECT oid FROM pg_roles WHERE rolname = session_user
    ), membership(oid) AS (
        SELECT oid FROM login_role
        UNION
        SELECT edge.roleid
        FROM pg_auth_members AS edge
        JOIN membership AS member ON member.oid = edge.member
    ), eligible(oid) AS (
        SELECT member.oid
        FROM membership AS member
        WHERE member.oid = (SELECT oid FROM login_role)
            OR pg_has_role(session_user, member.oid,
                CASE WHEN current_setting('server_version_num')::INTEGER >= 160000
                    THEN 'SET' ELSE 'MEMBER' END)
    )
    SELECT (NOT COALESCE(p_require_append, FALSE) OR has_function_privilege(session_user,
        'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE, 'EXECUTE'))
    AND (NOT COALESCE(p_require_exporter, FALSE) OR (
        has_function_privilege(session_user, 'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_batch_members()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_claim_security_audit_pending(bigint)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reclaim_security_audit_batch(bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
    ))
    AND (NOT COALESCE(p_require_least_privilege, TRUE) OR (
        -- Neither the writer nor exporter may assume receiver ACK authority.
        NOT EXISTS (
            SELECT 1 FROM eligible AS role
            WHERE has_function_privilege(role.oid, 'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::REGPROCEDURE, 'EXECUTE')
               OR has_function_privilege(role.oid, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
        ) AND
        NOT EXISTS (
            SELECT 1 FROM membership AS member
            JOIN pg_roles AS role ON role.oid = member.oid
            WHERE role.rolsuper AND pg_has_role(session_user, role.oid, 'MEMBER')
        )
        AND NOT EXISTS (
            SELECT 1 FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public' AND relation.relname IN (
                'security_audit_chain_state', 'security_audit_events', 'security_audit_chain_entries'
            ) AND (
                pg_has_role(session_user, relation.relowner, 'MEMBER')
                OR EXISTS (
                    SELECT 1 FROM eligible AS role
                    WHERE has_table_privilege(role.oid, relation.oid,
                        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                        OR has_any_column_privilege(role.oid, relation.oid,
                            'SELECT,INSERT,UPDATE,REFERENCES')
                )
            )
        )
    )) AS policy_satisfied
$$;

CREATE FUNCTION public.nazo_stage_security_audit_chain(p_previous_sequence bigint, p_previous_hash bytea, p_event_ids uuid[], p_event_hashes bytea[]) RETURNS TABLE(last_sequence bigint, last_hash bytea)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_sequence BIGINT;
    v_hash BYTEA;
    v_anchor BIGINT;
    v_entry RECORD;
BEGIN
    IF p_event_ids IS NULL OR cardinality(p_event_ids) NOT BETWEEN 0 AND 256
       OR p_event_hashes IS NULL OR cardinality(p_event_ids) <> cardinality(p_event_hashes) THEN
        RAISE EXCEPTION 'audit chain batch bounds are invalid';
    END IF;
    SELECT state.last_sequence, state.last_hash, state.anchor_sequence
      INTO STRICT v_sequence, v_hash, v_anchor
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE;
    IF v_sequence IS DISTINCT FROM p_previous_sequence OR v_hash IS DISTINCT FROM p_previous_hash
       OR (v_sequence = 0 AND v_hash <> decode(repeat('00', 32), 'hex'))
       OR (v_sequence > 0 AND v_sequence IS DISTINCT FROM v_anchor AND NOT EXISTS (
           SELECT 1 FROM public.security_audit_chain_entries AS chain
           WHERE chain.sequence = v_sequence AND chain.event_hash = v_hash
       )) THEN
        RAISE EXCEPTION 'security audit append head is stale or invalid';
    END IF;
    FOR v_entry IN SELECT * FROM unnest(p_event_ids, p_event_hashes) AS item(event_id, event_hash) LOOP
        -- ACK shares the locked chain-state row with this operation. Reject
        -- an already-exported retained decision even for a direct API caller.
        -- Resolve one primary-key identity before checking its delivery state.
        -- The barrier prevents a stale pending estimate from scanning that set
        -- once for every identity; retain the same row lock and rejection.
        PERFORM 1 FROM (
            SELECT event.exported_at FROM public.security_audit_events AS event
            WHERE event.event_id = v_entry.event_id
            LIMIT 1 FOR SHARE OF event
        ) AS event WHERE event.exported_at IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'audit chain event is missing or already exported';
        END IF;
        v_sequence := v_sequence + 1;
        INSERT INTO public.security_audit_chain_entries (event_id, sequence, previous_hash, event_hash)
        VALUES (v_entry.event_id, v_sequence, v_hash, v_entry.event_hash);
        v_hash := v_entry.event_hash;
    END LOOP;
    RETURN QUERY SELECT v_sequence, v_hash;
END;
$$;

CREATE FUNCTION public.nazo_tenant_directory_control_operations_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'tenant directory control outcomes are append-only'
        USING ERRCODE = '55006';
END;
$$;

CREATE FUNCTION public.nazo_tenant_resource_control_operations_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'tenant resource control outcomes are append-only'
        USING ERRCODE = '55006';
END;
$$;

CREATE FUNCTION public.nazo_unblock_security_audit_batch() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE v_updated INTEGER;
BEGIN
    UPDATE public.security_audit_chain_state AS state
    SET batch_blocked_reason = NULL, batch_locked_until = NULL,
        batch_available_at = CURRENT_TIMESTAMP
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND state.batch_blocked_reason IS NOT NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_valid_openid4vc_wallet_origins(origins jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT jsonb_typeof(origins) = 'array'
       AND jsonb_array_length(origins) BETWEEN 1 AND 16
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(origins) AS element(value)
           WHERE jsonb_typeof(value) <> 'string'
              OR char_length(btrim(value #>> '{}')) NOT BETWEEN 1 AND 2048
              OR value #>> '{}' <> btrim(value #>> '{}')
              OR value #>> '{}' !~ '^https://'
              OR value #>> '{}' ~ '[[:cntrl:]]'
       )
       AND jsonb_array_length(origins) = (
           SELECT COUNT(DISTINCT value #>> '{}')
           FROM jsonb_array_elements(origins) AS element(value)
       );
$$;

CREATE FUNCTION public.nazo_validate_openid4vp_trust_policy_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT openid4vc_presentation_trust_policy_is_active(
        NEW.tenant_id,
        NEW.openid4vc_trust_policy_binding_id,
        NEW.openid4vc_trust_policy_resource_id,
        NEW.openid4vc_trust_policy_digest
    ) THEN
        RAISE EXCEPTION 'OpenID4VP trust policy binding is incomplete or inactive'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.openid4vc_presentation_trust_policy_is_active(requested_tenant_id uuid, requested_binding_id uuid, requested_resource_id character varying, requested_digest character varying) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT CASE
        WHEN requested_binding_id IS NULL
         AND requested_resource_id IS NULL
         AND requested_digest IS NULL THEN TRUE
        WHEN requested_binding_id IS NULL
          OR requested_resource_id IS NULL
          OR requested_digest IS NULL THEN FALSE
        ELSE EXISTS (
            SELECT 1
            FROM openid4vc_trust_policies policy
            WHERE policy.tenant_id = requested_tenant_id
              AND policy.id = requested_binding_id
              AND policy.resource_id = requested_resource_id
              AND policy.resource_digest = requested_digest
              AND policy.source = 'operator-managed'
              AND policy.active
        )
    END;
$$;

CREATE TABLE public.access_token_revocations (
    access_token_jti_blake3 character varying(64) NOT NULL,
    client_id uuid NOT NULL,
    revoked_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL
);

CREATE TABLE public.admin_provision_receipts (
    operation_id character varying(128) NOT NULL,
    deployment_id character varying(128) NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    CONSTRAINT ck_admin_provision_receipts_deployment_id CHECK (((deployment_id)::text ~ '^[-A-Za-z0-9._:+]{1,128}$'::text)),
    CONSTRAINT ck_admin_provision_receipts_operation_id CHECK (((operation_id)::text ~ '^[-A-Za-z0-9._:+]{1,128}$'::text))
);

COMMENT ON TABLE public.admin_provision_receipts IS 'Durable idempotency receipt for local controller administrator provisioning.';

COMMENT ON COLUMN public.admin_provision_receipts.operation_id IS 'Controller operation identity; retries of the same delivered operation return this receipt.';

CREATE TABLE public.backchannel_logout_deliveries (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    client_public_id character varying NOT NULL,
    logout_uri text NOT NULL,
    logout_token text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    locked_at timestamp with time zone,
    delivered_at timestamp with time zone,
    failed_at timestamp with time zone,
    last_error text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    operation_key character varying,
    CONSTRAINT ck_backchannel_logout_delivery_attempts_non_negative CHECK ((attempts >= 0)),
    CONSTRAINT ck_backchannel_logout_delivery_terminal_once CHECK (((delivered_at IS NULL) OR (failed_at IS NULL)))
);

CREATE TABLE public.client_access_requests (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    site_name character varying(120) NOT NULL,
    site_url character varying(512) NOT NULL,
    request_description character varying(2000) NOT NULL,
    status smallint DEFAULT 0 NOT NULL,
    admin_note character varying(1000),
    resolved_by_user_id uuid,
    approved_client_id uuid,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    required_approval_event_id uuid,
    CONSTRAINT ck_access_request_required_approval CHECK (((required_approval_event_id IS NULL) OR (status = 1))),
    CONSTRAINT ck_client_access_requests_status_code CHECK ((status = ANY (ARRAY[0, 1, 2])))
);

COMMENT ON COLUMN public.client_access_requests.status IS '0=pending, 1=approved, 2=rejected';

COMMENT ON COLUMN public.client_access_requests.required_approval_event_id IS 'Required approval commit marker and external audit correlation; retained with the approval after audit delivery reclaims the event.';

CREATE TABLE public.controller_identity_approvals (
    approval_id uuid NOT NULL,
    deployment_id character varying(128) NOT NULL,
    action character varying(32) NOT NULL,
    action_sha256 character varying(64) NOT NULL,
    admin_user_id uuid NOT NULL,
    token_hash character varying(64) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_controller_identity_approvals_action_catalog CHECK (((action)::text = ANY ((ARRAY['bind'::character varying, 'add'::character varying, 'rotate'::character varying, 'revoke'::character varying, 'recovery-root-rotate'::character varying])::text[]))),
    CONSTRAINT ck_controller_identity_approvals_action_digest_shape CHECK (((action_sha256)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_controller_identity_approvals_deployment_shape CHECK (((deployment_id)::text ~ '^[A-Za-z0-9.:_+-]{1,128}$'::text)),
    CONSTRAINT ck_controller_identity_approvals_single_use CHECK (((consumed_at IS NULL) OR (consumed_at >= created_at))),
    CONSTRAINT ck_controller_identity_approvals_token_hash_shape CHECK (((token_hash)::text ~ '^[0-9a-f]{64}$'::text))
);

COMMENT ON TABLE public.controller_identity_approvals IS 'Single-use fresh-2FA approvals binding one controller identity action hash to one administrator.';

CREATE TABLE public.controller_recovery_challenges (
    challenge_id uuid NOT NULL,
    deployment_id character varying(128) NOT NULL,
    nonce bytea NOT NULL,
    controller_label character varying(128) NOT NULL,
    controller_kid character varying(43) NOT NULL,
    controller_public_key bytea NOT NULL,
    recovery_kid character varying(43) NOT NULL,
    recovery_public_key bytea NOT NULL,
    attempts smallint DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    accepted_signature_sha256 bytea,
    recovered_controller_id character varying(36),
    recovered_slot_index smallint,
    recovered_slot_issued_at timestamp with time zone,
    recovered_slot_expires_at timestamp with time zone,
    recovery_generation integer,
    allocation_nonce bytea NOT NULL,
    CONSTRAINT ck_controller_recovery_challenges_allocation_nonce_length CHECK ((octet_length(allocation_nonce) = 32)),
    CONSTRAINT ck_controller_recovery_challenges_attempts_bounded CHECK (((attempts >= 0) AND (attempts <= 64))),
    CONSTRAINT ck_controller_recovery_challenges_deployment_shape CHECK (((deployment_id)::text ~ '^[A-Za-z0-9.:_+-]{1,128}$'::text)),
    CONSTRAINT ck_controller_recovery_challenges_fixed_ttl CHECK ((expires_at = (created_at + '00:10:00'::interval))),
    CONSTRAINT ck_controller_recovery_challenges_key_lengths CHECK (((octet_length(controller_public_key) = 32) AND (octet_length(recovery_public_key) = 32))),
    CONSTRAINT ck_controller_recovery_challenges_kids_shape CHECK ((((controller_kid)::text ~ '^[A-Za-z0-9_-]{43}$'::text) AND ((recovery_kid)::text ~ '^[A-Za-z0-9_-]{43}$'::text))),
    CONSTRAINT ck_controller_recovery_challenges_label_bounded CHECK (((length((controller_label)::text) >= 1) AND (length((controller_label)::text) <= 128))),
    CONSTRAINT ck_controller_recovery_challenges_nonce_length CHECK ((octet_length(nonce) = 32)),
    CONSTRAINT ck_controller_recovery_challenges_receipt_shape CHECK ((((accepted_signature_sha256 IS NULL) AND (recovered_controller_id IS NULL) AND (recovered_slot_index IS NULL) AND (recovered_slot_issued_at IS NULL) AND (recovered_slot_expires_at IS NULL) AND (recovery_generation IS NULL)) OR ((octet_length(accepted_signature_sha256) = 32) AND (recovered_controller_id IS NOT NULL) AND ((recovered_slot_index >= 0) AND (recovered_slot_index <= 2)) AND (recovered_slot_issued_at IS NOT NULL) AND (recovered_slot_expires_at > recovered_slot_issued_at) AND (recovery_generation IS NOT NULL) AND (consumed_at IS NOT NULL)))),
    CONSTRAINT ck_controller_recovery_challenges_single_use CHECK (((consumed_at IS NULL) OR (consumed_at >= created_at)))
);

COMMENT ON TABLE public.controller_recovery_challenges IS 'Single-use nonce-bound recovery challenges; expired or consumed rows are dead.';

COMMENT ON COLUMN public.controller_recovery_challenges.accepted_signature_sha256 IS 'SHA-256 of the accepted recovery signature; binds an idempotent retry to the exact submission.';

COMMENT ON COLUMN public.controller_recovery_challenges.recovered_controller_id IS 'Controller slot committed by the accepted recovery, returned on exact retry.';

COMMENT ON COLUMN public.controller_recovery_challenges.recovered_slot_index IS 'Immutable slot index from the accepted recovery result.';

COMMENT ON COLUMN public.controller_recovery_challenges.recovered_slot_issued_at IS 'Immutable issuance time from the accepted recovery result.';

COMMENT ON COLUMN public.controller_recovery_challenges.recovered_slot_expires_at IS 'Immutable expiry time from the accepted recovery result.';

COMMENT ON COLUMN public.controller_recovery_challenges.recovery_generation IS 'Recovery Root generation committed by the accepted recovery, returned on exact retry.';

COMMENT ON COLUMN public.controller_recovery_challenges.allocation_nonce IS 'Client-generated nonce in the current-Recovery-Root allocation proof; unique per deployment and retained after consumption to reject replay.';

CREATE TABLE public.controller_recovery_root_key_history (
    deployment_id character varying(128) NOT NULL,
    recovery_public_key bytea CONSTRAINT controller_recovery_root_key_histo_recovery_public_key_not_null NOT NULL,
    CONSTRAINT ck_controller_recovery_root_key_history_deployment_shape CHECK (((deployment_id)::text ~ '^[A-Za-z0-9.:_+-]{1,128}$'::text)),
    CONSTRAINT ck_controller_recovery_root_key_history_public_key_length CHECK ((octet_length(recovery_public_key) = 32))
);

CREATE TABLE public.controller_recovery_roots (
    deployment_id character varying(128) NOT NULL,
    recovery_kid character varying(43) NOT NULL,
    recovery_public_key bytea NOT NULL,
    kdf character varying(32) NOT NULL,
    generation integer NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_controller_recovery_roots_deployment_shape CHECK (((deployment_id)::text ~ '^[A-Za-z0-9.:_+-]{1,128}$'::text)),
    CONSTRAINT ck_controller_recovery_roots_generation_positive CHECK ((generation >= 1)),
    CONSTRAINT ck_controller_recovery_roots_kdf_pinned CHECK (((kdf)::text = 'hkdf-sha256-v1'::text)),
    CONSTRAINT ck_controller_recovery_roots_kid_shape CHECK (((recovery_kid)::text ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT ck_controller_recovery_roots_public_key_length CHECK ((octet_length(recovery_public_key) = 32))
);

COMMENT ON TABLE public.controller_recovery_roots IS 'Single per-deployment Recovery Public Key anchor; derived public material only.';

CREATE TABLE public.controller_registry_slots (
    deployment_id character varying(128) NOT NULL,
    controller_id character varying(36) NOT NULL,
    label character varying(128) NOT NULL,
    kid character varying(43) NOT NULL,
    public_key bytea NOT NULL,
    slot_index smallint NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    status character varying(16) NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_controller_registry_slots_controller_id_is_uuidv7 CHECK (((controller_id)::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT ck_controller_registry_slots_deployment_shape CHECK (((deployment_id)::text ~ '^[A-Za-z0-9.:_+-]{1,128}$'::text)),
    CONSTRAINT ck_controller_registry_slots_fixed_ttl CHECK ((expires_at = (issued_at + '720:00:00'::interval))),
    CONSTRAINT ck_controller_registry_slots_kid_shape CHECK (((kid)::text ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT ck_controller_registry_slots_public_key_length CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT ck_controller_registry_slots_revocation_terminal CHECK (((((status)::text = 'active'::text) AND (revoked_at IS NULL)) OR (((status)::text = 'revoked'::text) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT ck_controller_registry_slots_slot_index_range CHECK (((slot_index >= 0) AND (slot_index <= 2))),
    CONSTRAINT ck_controller_registry_slots_status_catalog CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'revoked'::character varying])::text[])))
);

COMMENT ON TABLE public.controller_registry_slots IS 'Authoritative per-deployment Controller Public Key registry; public material only.';

CREATE TABLE public.external_identity_links (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_type character varying(16) NOT NULL,
    provider_id character varying(120) NOT NULL,
    subject character varying(512) NOT NULL,
    email character varying(254) NOT NULL,
    claims jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_login_at timestamp with time zone,
    CONSTRAINT ck_external_identity_links_provider_id_non_empty CHECK ((length(TRIM(BOTH FROM provider_id)) > 0)),
    CONSTRAINT ck_external_identity_links_provider_type CHECK (((provider_type)::text = ANY ((ARRAY['oidc'::character varying, 'saml'::character varying, 'oauth2_social'::character varying])::text[]))),
    CONSTRAINT ck_external_identity_links_subject_non_empty CHECK ((length(TRIM(BOTH FROM subject)) > 0))
);

CREATE TABLE public.identity_security_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    category character varying(16) NOT NULL,
    event_type character varying(32) NOT NULL,
    outcome character varying(32) NOT NULL,
    actor_id uuid,
    target_user_id uuid,
    reason_code character varying(64) NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    request_id character varying(128),
    CONSTRAINT ck_identity_security_event_category CHECK (((category)::text = ANY ((ARRAY['mfa'::character varying, 'admin'::character varying])::text[]))),
    CONSTRAINT ck_identity_security_event_category_type CHECK (((((category)::text = 'mfa'::text) AND ((event_type)::text = ANY ((ARRAY['mfa_totp_attempt'::character varying, 'mfa_backup_code_attempt'::character varying])::text[]))) OR (((category)::text = 'admin'::text) AND ((event_type)::text = ANY ((ARRAY['admin_user_update'::character varying, 'initial_admin_bootstrap'::character varying, 'admin_user_created'::character varying])::text[]))))),
    CONSTRAINT ck_identity_security_event_outcome CHECK (((outcome)::text = ANY ((ARRAY['success'::character varying, 'denied'::character varying, 'invalid_credential'::character varying, 'replay'::character varying, 'conflict'::character varying, 'dependency_failure'::character varying])::text[]))),
    CONSTRAINT ck_identity_security_event_reason_code CHECK ((((char_length((reason_code)::text) >= 1) AND (char_length((reason_code)::text) <= 64)) AND ((reason_code)::text ~ '^[a-z0-9_]+$'::text))),
    CONSTRAINT ck_identity_security_event_request_binding CHECK (((((event_type)::text = 'initial_admin_bootstrap'::text) AND (request_id IS NOT NULL) AND ((request_id)::text ~ '^bootstrap-admin-[0-9a-f]{32}$'::text) AND (actor_id IS NULL) AND (target_user_id IS NOT NULL)) OR (((event_type)::text = 'admin_user_created'::text) AND (request_id IS NOT NULL) AND ((request_id)::text ~ '^[-A-Za-z0-9._:+]{1,128}$'::text) AND (actor_id IS NULL) AND (target_user_id IS NOT NULL)) OR (((event_type)::text <> ALL ((ARRAY['initial_admin_bootstrap'::character varying, 'admin_user_created'::character varying])::text[])) AND (request_id IS NULL)))),
    CONSTRAINT ck_identity_security_event_semantics CHECK (((((event_type)::text = 'mfa_totp_attempt'::text) AND ((((outcome)::text = 'success'::text) AND ((reason_code)::text = 'totp_accepted'::text)) OR (((outcome)::text = 'invalid_credential'::text) AND ((reason_code)::text = 'totp_invalid'::text)) OR (((outcome)::text = 'replay'::text) AND ((reason_code)::text = 'totp_replay'::text)) OR (((outcome)::text = 'dependency_failure'::text) AND ((reason_code)::text = 'dependency_unavailable'::text)))) OR (((event_type)::text = 'mfa_backup_code_attempt'::text) AND ((((outcome)::text = 'success'::text) AND ((reason_code)::text = 'backup_code_accepted'::text)) OR (((outcome)::text = 'invalid_credential'::text) AND ((reason_code)::text = 'backup_code_invalid'::text)) OR (((outcome)::text = 'replay'::text) AND ((reason_code)::text = 'backup_code_replay'::text)) OR (((outcome)::text = 'dependency_failure'::text) AND ((reason_code)::text = 'dependency_unavailable'::text)))) OR (((event_type)::text = 'admin_user_update'::text) AND ((((outcome)::text = 'success'::text) AND ((reason_code)::text = 'admin_updated'::text)) OR (((outcome)::text = 'denied'::text) AND ((reason_code)::text = ANY ((ARRAY['target_not_found'::character varying, 'actor_not_authorized'::character varying, 'cross_tenant'::character varying, 'self_elevation'::character varying, 'self_demotion_or_disable'::character varying, 'target_at_or_above_actor'::character varying, 'grant_at_or_above_actor'::character varying, 'invalid_role_level'::character varying])::text[]))) OR (((outcome)::text = 'conflict'::text) AND ((reason_code)::text = 'dependency_unavailable'::text)) OR (((outcome)::text = 'dependency_failure'::text) AND ((reason_code)::text = 'dependency_unavailable'::text)))) OR (((event_type)::text = 'initial_admin_bootstrap'::text) AND ((outcome)::text = 'success'::text) AND ((reason_code)::text = 'initial_admin_created'::text)) OR (((event_type)::text = 'admin_user_created'::text) AND ((outcome)::text = 'success'::text) AND ((reason_code)::text = 'admin_created'::text)))),
    CONSTRAINT ck_identity_security_event_type CHECK (((event_type)::text = ANY ((ARRAY['mfa_totp_attempt'::character varying, 'mfa_backup_code_attempt'::character varying, 'admin_user_update'::character varying, 'initial_admin_bootstrap'::character varying, 'admin_user_created'::character varying])::text[])))
);

CREATE TABLE public.oauth_client_mtls_trust_anchor_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    actor_user_id uuid,
    action smallint NOT NULL,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_mtls_trust_anchor_event_action CHECK ((action = ANY (ARRAY[0, 1, 2, 3]))),
    CONSTRAINT ck_mtls_trust_anchor_event_note CHECK (((note IS NULL) OR ((octet_length(note) >= 1) AND (octet_length(note) <= 1000))))
);

COMMENT ON TABLE public.oauth_client_mtls_trust_anchor_events IS 'Append-only control-plane audit trail for trust-anchor request, approval, rejection, and revocation actions.';

COMMENT ON COLUMN public.oauth_client_mtls_trust_anchor_events.action IS '0=requested, 1=approved, 2=rejected, 3=revoked';

CREATE TABLE public.oauth_client_mtls_trust_anchor_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    client_id uuid NOT NULL,
    certificate_pem text CONSTRAINT oauth_client_mtls_trust_anchor_request_certificate_pem_not_null NOT NULL,
    certificate_sha256 character varying(64) CONSTRAINT oauth_client_mtls_trust_anchor_requ_certificate_sha256_not_null NOT NULL,
    subject_dn text NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    status smallint DEFAULT 0 NOT NULL,
    admin_note text,
    resolved_by_user_id uuid,
    resolved_at timestamp with time zone,
    revoked_by_user_id uuid,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    source character varying(32) DEFAULT 'admin-session'::character varying NOT NULL,
    CONSTRAINT ck_mtls_trust_anchor_digest CHECK (((certificate_sha256)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_mtls_trust_anchor_distinct_approver CHECK (((resolved_by_user_id IS NULL) OR (resolved_by_user_id <> user_id))),
    CONSTRAINT ck_mtls_trust_anchor_single_certificate CHECK ((((octet_length(certificate_pem) >= 1) AND (octet_length(certificate_pem) <= 16384)) AND (certificate_pem ~~ '-----BEGIN CERTIFICATE-----%'::text) AND (certificate_pem ~~ '%-----END CERTIFICATE-----%'::text))),
    CONSTRAINT ck_mtls_trust_anchor_source CHECK (((source)::text = ANY ((ARRAY['admin-session'::character varying, 'operator-managed'::character varying])::text[]))),
    CONSTRAINT ck_mtls_trust_anchor_state CHECK ((((status = 0) AND ((source)::text = 'admin-session'::text) AND (user_id IS NOT NULL) AND (resolved_by_user_id IS NULL) AND (resolved_at IS NULL) AND (revoked_by_user_id IS NULL) AND (revoked_at IS NULL)) OR ((status = 0) AND ((source)::text = 'operator-managed'::text) AND (user_id IS NULL) AND (resolved_by_user_id IS NULL) AND (resolved_at IS NULL) AND (revoked_by_user_id IS NULL) AND (revoked_at IS NULL)) OR ((status = ANY (ARRAY[1, 2])) AND ((source)::text = 'admin-session'::text) AND (user_id IS NOT NULL) AND (resolved_by_user_id IS NOT NULL) AND (resolved_at IS NOT NULL) AND (revoked_by_user_id IS NULL) AND (revoked_at IS NULL)) OR ((status = ANY (ARRAY[1, 2])) AND ((source)::text = 'operator-managed'::text) AND (user_id IS NULL) AND (resolved_by_user_id IS NULL) AND (resolved_at IS NOT NULL) AND (revoked_by_user_id IS NULL) AND (revoked_at IS NULL)) OR ((status = 3) AND ((source)::text = 'admin-session'::text) AND (user_id IS NOT NULL) AND (resolved_by_user_id IS NOT NULL) AND (resolved_at IS NOT NULL) AND (revoked_by_user_id IS NOT NULL) AND (revoked_at IS NOT NULL)) OR ((status = 3) AND ((source)::text = 'operator-managed'::text) AND (user_id IS NULL) AND (resolved_by_user_id IS NULL) AND (resolved_at IS NOT NULL) AND (revoked_by_user_id IS NULL) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT ck_mtls_trust_anchor_status CHECK ((status = ANY (ARRAY[0, 1, 2, 3]))),
    CONSTRAINT ck_mtls_trust_anchor_subject CHECK (((octet_length(subject_dn) >= 1) AND (octet_length(subject_dn) <= 2048))),
    CONSTRAINT ck_mtls_trust_anchor_validity CHECK ((not_after > not_before))
);

COMMENT ON TABLE public.oauth_client_mtls_trust_anchor_requests IS 'Deployment trust-management records for RFC 8705 tls_client_auth or certificate-bound-token clients; OAuth protocol handlers never mutate this table.';

COMMENT ON COLUMN public.oauth_client_mtls_trust_anchor_requests.status IS '0=pending, 1=approved, 2=rejected, 3=revoked';

CREATE TABLE public.oauth_clients (
    id uuid DEFAULT uuidv7() NOT NULL,
    client_id character varying(128) NOT NULL,
    client_name character varying(200) NOT NULL,
    client_type character varying(32) NOT NULL,
    client_secret_hash character varying(512),
    redirect_uris jsonb NOT NULL,
    scopes jsonb NOT NULL,
    grant_types jsonb NOT NULL,
    token_endpoint_auth_method character varying(64) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    allowed_audiences jsonb DEFAULT '["resource://default"]'::jsonb NOT NULL,
    jwks jsonb,
    require_dpop_bound_tokens boolean DEFAULT false NOT NULL,
    allow_client_assertion_audience_array boolean DEFAULT false NOT NULL,
    allow_client_assertion_endpoint_audience boolean DEFAULT false NOT NULL,
    require_par_request_object boolean DEFAULT false NOT NULL,
    require_mtls_bound_tokens boolean DEFAULT false NOT NULL,
    tls_client_auth_subject_dn character varying(512),
    tls_client_auth_cert_sha256 character varying(128),
    tls_client_auth_san_dns jsonb DEFAULT '[]'::jsonb NOT NULL,
    tls_client_auth_san_uri jsonb DEFAULT '[]'::jsonb NOT NULL,
    tls_client_auth_san_ip jsonb DEFAULT '[]'::jsonb NOT NULL,
    tls_client_auth_san_email jsonb DEFAULT '[]'::jsonb NOT NULL,
    post_logout_redirect_uris jsonb DEFAULT '[]'::jsonb NOT NULL,
    backchannel_logout_uri character varying,
    backchannel_logout_session_required boolean DEFAULT true NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    realm_id uuid DEFAULT '00000000-0000-0000-0000-000000000002'::uuid NOT NULL,
    organization_id uuid DEFAULT '00000000-0000-0000-0000-000000000003'::uuid NOT NULL,
    subject_type text DEFAULT 'public'::text NOT NULL,
    sector_identifier_uri text,
    sector_identifier_host text,
    introspection_encrypted_response_alg character varying,
    introspection_encrypted_response_enc character varying,
    registration_access_token_blake3 character varying,
    frontchannel_logout_uri character varying,
    frontchannel_logout_session_required boolean DEFAULT true NOT NULL,
    userinfo_signed_response_alg character varying,
    userinfo_encrypted_response_alg character varying,
    userinfo_encrypted_response_enc character varying,
    authorization_signed_response_alg character varying,
    authorization_encrypted_response_alg character varying,
    authorization_encrypted_response_enc character varying,
    jwks_uri text,
    request_uris jsonb DEFAULT '[]'::jsonb NOT NULL,
    initiate_login_uri text,
    logo_uri text,
    policy_uri text,
    tos_uri text,
    backchannel_token_delivery_mode character varying DEFAULT 'poll'::character varying NOT NULL,
    backchannel_client_notification_endpoint text,
    backchannel_authentication_request_signing_alg character varying,
    security_policy jsonb NOT NULL,
    id_token_signed_response_alg character varying,
    id_token_encrypted_response_alg character varying,
    id_token_encrypted_response_enc character varying,
    request_object_signing_alg character varying,
    request_object_encryption_alg character varying,
    request_object_encryption_enc character varying,
    token_endpoint_auth_signing_alg character varying,
    introspection_signed_response_alg character varying,
    access_token_epoch bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_oauth_clients_allowed_audiences_array CHECK ((jsonb_typeof(allowed_audiences) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_ciba_delivery_mode CHECK (((backchannel_token_delivery_mode)::text = ANY ((ARRAY['poll'::character varying, 'ping'::character varying])::text[]))),
    CONSTRAINT ck_oauth_clients_ciba_notification_endpoint CHECK (((((backchannel_token_delivery_mode)::text = 'poll'::text) AND (backchannel_client_notification_endpoint IS NULL)) OR (((backchannel_token_delivery_mode)::text = 'ping'::text) AND (backchannel_client_notification_endpoint ~ '^https://[^[:space:]]+$'::text)))),
    CONSTRAINT ck_oauth_clients_ciba_request_signing_alg CHECK (((backchannel_authentication_request_signing_alg IS NULL) OR ((backchannel_authentication_request_signing_alg)::text = ANY ((ARRAY['EdDSA'::character varying, 'ES256'::character varying, 'PS256'::character varying])::text[])))),
    CONSTRAINT ck_oauth_clients_client_type_value CHECK (((client_type)::text = ANY ((ARRAY['public'::character varying, 'confidential'::character varying])::text[]))),
    CONSTRAINT ck_oauth_clients_grant_types_array CHECK ((jsonb_typeof(grant_types) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_initiate_login_uri_https CHECK (((initiate_login_uri IS NULL) OR (lower(initiate_login_uri) ~~ 'https://%'::text))),
    CONSTRAINT ck_oauth_clients_jwks_object CHECK (((jwks IS NULL) OR (jsonb_typeof(jwks) = 'object'::text))),
    CONSTRAINT ck_oauth_clients_jwks_source CHECK (((jwks_uri IS NULL) OR (jwks IS NOT NULL))),
    CONSTRAINT ck_oauth_clients_jwks_uri_https CHECK (((jwks_uri IS NULL) OR (lower(jwks_uri) ~~ 'https://%'::text))),
    CONSTRAINT ck_oauth_clients_logo_uri_https CHECK (((logo_uri IS NULL) OR (lower(logo_uri) ~~ 'https://%'::text))),
    CONSTRAINT ck_oauth_clients_policy_uri_https CHECK (((policy_uri IS NULL) OR (lower(policy_uri) ~~ 'https://%'::text))),
    CONSTRAINT ck_oauth_clients_post_logout_redirect_uris_array CHECK ((jsonb_typeof(post_logout_redirect_uris) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_redirect_uris_array CHECK ((jsonb_typeof(redirect_uris) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_request_uris_array CHECK ((jsonb_typeof(request_uris) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_scopes_array CHECK ((jsonb_typeof(scopes) = 'array'::text)),
    CONSTRAINT ck_oauth_clients_security_policy_object CHECK (public.nazo_client_security_policy_is_current(security_policy)),
    CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (((token_endpoint_auth_method)::text = ANY ((ARRAY['none'::character varying, 'client_secret_basic'::character varying, 'client_secret_post'::character varying, 'private_key_jwt'::character varying, 'tls_client_auth'::character varying, 'self_signed_tls_client_auth'::character varying, 'attest_jwt_client_auth'::character varying])::text[]))),
    CONSTRAINT ck_oauth_clients_tos_uri_https CHECK (((tos_uri IS NULL) OR (lower(tos_uri) ~~ 'https://%'::text))),
    CONSTRAINT oauth_clients_access_token_epoch_check CHECK ((access_token_epoch >= 0)),
    CONSTRAINT oauth_clients_subject_type_check CHECK ((subject_type = ANY (ARRAY['public'::text, 'pairwise'::text])))
);

COMMENT ON COLUMN public.oauth_clients.token_endpoint_auth_method IS 'none=public client, client_secret_basic=HTTP Basic client authentication, client_secret_post=form body client authentication, private_key_jwt=JWT client assertion authentication';

COMMENT ON COLUMN public.oauth_clients.jwks IS 'Public JWKS used to verify private_key_jwt client assertions';

COMMENT ON COLUMN public.oauth_clients.require_dpop_bound_tokens IS 'Whether this client must bind authorization code and refresh-token issued access tokens to a DPoP key.';

COMMENT ON COLUMN public.oauth_clients.allow_client_assertion_audience_array IS 'Allows private_key_jwt client assertion aud to be a JSON array containing an accepted audience.';

COMMENT ON COLUMN public.oauth_clients.allow_client_assertion_endpoint_audience IS 'Allows private_key_jwt client assertion aud to match the authenticated endpoint URL.';

COMMENT ON COLUMN public.oauth_clients.require_par_request_object IS 'Require pushed authorization requests for this client to carry a signed request object.';

COMMENT ON COLUMN public.oauth_clients.require_mtls_bound_tokens IS 'Requires access tokens issued to this client to be bound to the verified mTLS client certificate thumbprint';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_subject_dn IS 'Registered exact subject DN for tls_client_auth client authentication';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_cert_sha256 IS 'Base64url SHA-256 thumbprint of the registered client certificate DER';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_san_dns IS 'Registered DNS subjectAltName values for tls_client_auth client authentication';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_san_uri IS 'Registered URI subjectAltName values for tls_client_auth client authentication';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_san_ip IS 'Registered IP subjectAltName values for tls_client_auth client authentication';

COMMENT ON COLUMN public.oauth_clients.tls_client_auth_san_email IS 'Registered email subjectAltName values for tls_client_auth client authentication';

COMMENT ON COLUMN public.oauth_clients.tenant_id IS 'Tenant isolation key; client_id uniqueness is tenant-scoped.';

COMMENT ON COLUMN public.oauth_clients.introspection_encrypted_response_alg IS 'RFC 9701 JWE alg for encrypted token introspection responses, for example RSA-OAEP-256.';

COMMENT ON COLUMN public.oauth_clients.introspection_encrypted_response_enc IS 'RFC 9701 JWE enc for encrypted token introspection responses, for example A256GCM.';

COMMENT ON COLUMN public.oauth_clients.registration_access_token_blake3 IS 'BLAKE3 hash of the RFC 7592 registration access token for dynamic client management.';

COMMENT ON COLUMN public.oauth_clients.userinfo_signed_response_alg IS 'OIDC JWS alg required for signed UserInfo responses.';

COMMENT ON COLUMN public.oauth_clients.userinfo_encrypted_response_alg IS 'OIDC JWE alg required for encrypted UserInfo responses.';

COMMENT ON COLUMN public.oauth_clients.userinfo_encrypted_response_enc IS 'OIDC JWE enc required for encrypted UserInfo responses.';

COMMENT ON COLUMN public.oauth_clients.authorization_signed_response_alg IS 'JARM JWS alg required for signed authorization responses.';

COMMENT ON COLUMN public.oauth_clients.authorization_encrypted_response_alg IS 'JARM JWE alg required for encrypted authorization responses.';

COMMENT ON COLUMN public.oauth_clients.authorization_encrypted_response_enc IS 'JARM JWE enc required for encrypted authorization responses.';

COMMENT ON COLUMN public.oauth_clients.jwks_uri IS 'Dynamically registered HTTPS JWK Set URI; jwks stores the last validated snapshot.';

COMMENT ON COLUMN public.oauth_clients.request_uris IS 'Exact dynamically registered HTTPS OIDC Request Object locations.';

COMMENT ON COLUMN public.oauth_clients.initiate_login_uri IS 'HTTPS RP endpoint for OpenID Connect Third-Party Initiated Login.';

COMMENT ON COLUMN public.oauth_clients.logo_uri IS 'Display-only HTTPS RP logo URI; never dereferenced by the authorization server.';

COMMENT ON COLUMN public.oauth_clients.policy_uri IS 'Display-only HTTPS RP policy URI; never dereferenced by the authorization server.';

COMMENT ON COLUMN public.oauth_clients.tos_uri IS 'Display-only HTTPS RP terms-of-service URI; never dereferenced by the authorization server.';

COMMENT ON COLUMN public.oauth_clients.backchannel_token_delivery_mode IS 'CIBA delivery mode: poll or ping. FAPI-CIBA push is deliberately unsupported.';

COMMENT ON COLUMN public.oauth_clients.backchannel_client_notification_endpoint IS 'Exact HTTPS endpoint used for CIBA ping notifications.';

CREATE TABLE public.oauth_refresh_contracts (
    tenant_id uuid NOT NULL,
    contract_blake3 bytea NOT NULL,
    contract jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_oauth_refresh_contracts_digest CHECK ((octet_length(contract_blake3) = 32)),
    CONSTRAINT ck_oauth_refresh_contracts_shape CHECK (public.nazo_refresh_contract_well_formed(contract))
);

COMMENT ON TABLE public.oauth_refresh_contracts IS 'Immutable per-family authorization contract, content-addressed by BLAKE3. Rows are reference-counted by families and reclaimed once unreferenced.';

CREATE TABLE public.oauth_refresh_families (
    tenant_id uuid NOT NULL,
    token_family_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    contract_blake3 bytea NOT NULL,
    current_member_id uuid NOT NULL,
    current_token_blake3 bytea NOT NULL,
    current_audience jsonb NOT NULL,
    current_issued_at timestamp with time zone NOT NULL,
    current_expires_at timestamp with time zone NOT NULL,
    current_id_token_sid character varying(128),
    dpop_jkt character varying(128),
    mtls_x5t_s256 character varying(128),
    client_attestation_jkt character varying(128),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at timestamp with time zone,
    reuse_detected_at timestamp with time zone,
    CONSTRAINT ck_orf_current_audience CHECK (jsonb_path_match(current_audience, '(($.type() == "array" && $.size() > 0) && !(exists ($[*]?(@.type() != "string" || @ like_regex "^\\s*$"))))'::jsonpath)),
    CONSTRAINT ck_orf_digest CHECK (((octet_length(current_token_blake3) = 32) AND (octet_length(contract_blake3) = 32))),
    CONSTRAINT ck_orf_timeline CHECK ((current_expires_at > current_issued_at))
);

COMMENT ON TABLE public.oauth_refresh_families IS 'One row per refresh family: grant authority plus the current generation. Compromise and revocation are single-row facts; rotation updates the current-* columns in place.';

CREATE TABLE public.oauth_refresh_spent_tokens (
    tenant_id uuid NOT NULL,
    refresh_token_blake3 bytea NOT NULL,
    token_family_id uuid NOT NULL,
    member_id uuid NOT NULL,
    successor_member_id uuid NOT NULL,
    spent_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_orst_digest CHECK ((octet_length(refresh_token_blake3) = 32)),
    CONSTRAINT ck_orst_timeline CHECK ((expires_at > spent_at))
);

COMMENT ON TABLE public.oauth_refresh_spent_tokens IS 'Minimal reuse/lost-response proofs without authorization payload. Unbound public families retain every unexpired proof; confidential or DPoP/mTLS-bound families retain at most the newest 64. All proofs expire at their original token expiry or with family retirement.';

CREATE TABLE public.oauth_subject_bindings (
    tenant_id uuid NOT NULL,
    subject character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    CONSTRAINT oauth_subject_bindings_subject_check CHECK (((subject)::text <> ''::text))
);

CREATE TABLE public.oauth_token_issuances (
    issuance_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    single_use_key_blake3 bytea,
    access_token_jti character varying(128) NOT NULL,
    access_token_expires_at timestamp with time zone NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    refresh_token_family_id uuid,
    principal_epoch_bound boolean DEFAULT false NOT NULL,
    receipt_contract_version smallint DEFAULT 0 NOT NULL,
    authorization_code_holder jsonb,
    CONSTRAINT oauth_token_issuances_retention_check CHECK ((retain_until >= access_token_expires_at)),
    CONSTRAINT oauth_token_issuances_single_use_digest_check CHECK (((single_use_key_blake3 IS NULL) OR (octet_length(single_use_key_blake3) = 32)))
);

COMMENT ON TABLE public.oauth_token_issuances IS 'Terminal token issuance facts: access-token ownership plus the single-use grant fence. retain_until bounds the fence (access-token acceptance window, extended by the grant deadline).';

COMMENT ON COLUMN public.oauth_token_issuances.refresh_token_family_id IS 'Refresh-token family issued by this redemption. Read back through the single-use fence on replay so revoke-on-replay can retire the family; NULL when the issuance produced no refresh token and for pre-migration rows.';

COMMENT ON COLUMN public.oauth_token_issuances.authorization_code_holder IS 'Versioned original proof requirements for code replay revocation; independent of the stable one-use code identity. Legacy receipts remain NULL.';

CREATE TABLE public.openid4vc_trust_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    resource_id character varying(255) NOT NULL,
    resource_digest character varying(64) NOT NULL,
    public_material jsonb NOT NULL,
    wallet_origins jsonb NOT NULL,
    source character varying(32) DEFAULT 'operator-managed'::character varying NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT ck_openid4vc_trust_policy_active_state CHECK (((active AND (revoked_at IS NULL)) OR ((NOT active) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT ck_openid4vc_trust_policy_digest CHECK (((resource_digest)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_openid4vc_trust_policy_material CHECK (((jsonb_typeof(public_material) = 'object'::text) AND (octet_length(convert_to((public_material)::text, 'UTF8'::name)) <= 32768))),
    CONSTRAINT ck_openid4vc_trust_policy_resource_id CHECK ((((char_length(btrim((resource_id)::text)) >= 1) AND (char_length(btrim((resource_id)::text)) <= 255)) AND ((resource_id)::text = btrim((resource_id)::text)) AND ((resource_id)::text !~ '[[:cntrl:]]'::text))),
    CONSTRAINT ck_openid4vc_trust_policy_source CHECK (((source)::text = 'operator-managed'::text)),
    CONSTRAINT ck_openid4vc_trust_policy_wallet_origins CHECK ((public.nazo_valid_openid4vc_wallet_origins(wallet_origins) AND (octet_length(convert_to((wallet_origins)::text, 'UTF8'::name)) <= 32768)))
);

COMMENT ON TABLE public.openid4vc_trust_policies IS 'Tenant-scoped public OpenID4VC trust material installed by the ordinary operator resource control plane.';

CREATE TABLE public.openid4vc_trust_policy_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    oauth_client_id uuid NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

COMMENT ON TABLE public.openid4vc_trust_policy_clients IS 'Explicit historical OAuth client bindings to ordinary OpenID4VC trust policy versions.';

CREATE TABLE public.openid4vci_access_grants (
    token_id uuid NOT NULL,
    token_hash character varying(64) NOT NULL,
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    client_id character varying(255) NOT NULL,
    credential_configuration_ids jsonb NOT NULL,
    credential_identifiers jsonb NOT NULL,
    dpop_jkt character varying(128),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    proof_origin text DEFAULT 'legacy_unspecified'::text NOT NULL,
    authorization_id uuid,
    mtls_x5t_s256 text,
    CONSTRAINT ck_openid4vci_access_configuration_ids CHECK (((jsonb_typeof(credential_configuration_ids) = 'array'::text) AND (jsonb_array_length(credential_configuration_ids) > 0))),
    CONSTRAINT ck_openid4vci_access_dpop CHECK (((dpop_jkt IS NULL) OR ((char_length(btrim((dpop_jkt)::text)) >= 20) AND (char_length(btrim((dpop_jkt)::text)) <= 128)))),
    CONSTRAINT ck_openid4vci_access_expiry CHECK ((expires_at > created_at)),
    CONSTRAINT ck_openid4vci_access_identifiers CHECK ((jsonb_typeof(credential_identifiers) = 'array'::text)),
    CONSTRAINT ck_openid4vci_proof_origin CHECK ((proof_origin = ANY (ARRAY['registered_client'::text, 'anonymous_pre_authorized'::text, 'legacy_unspecified'::text])))
);

CREATE TABLE public.openid4vci_credential_dataset_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    credential_configuration_id character varying(255) CONSTRAINT openid4vci_credential_data_credential_configuration_i_not_null1 NOT NULL,
    action smallint NOT NULL,
    actor_user_id uuid,
    source character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_openid4vci_dataset_event_action CHECK ((action = ANY (ARRAY[1, 2]))),
    CONSTRAINT ck_openid4vci_dataset_event_configuration_id CHECK (((char_length(btrim((credential_configuration_id)::text)) >= 1) AND (char_length(btrim((credential_configuration_id)::text)) <= 255))),
    CONSTRAINT ck_openid4vci_dataset_event_source CHECK (((source)::text = ANY ((ARRAY['admin-session'::character varying, 'operator-managed'::character varying])::text[])))
);

COMMENT ON TABLE public.openid4vci_credential_dataset_events IS 'Append-only administrative audit for credential dataset mutations; action 1=upsert, 2=delete.';

CREATE TABLE public.openid4vci_credential_datasets (
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    credential_configuration_id character varying(255) CONSTRAINT openid4vci_credential_datas_credential_configuration_i_not_null NOT NULL,
    claims_ciphertext bytea NOT NULL,
    source character varying(255) NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_openid4vci_dataset_ciphertext CHECK (((octet_length(claims_ciphertext) >= 29) AND (octet_length(claims_ciphertext) <= 1048576))),
    CONSTRAINT ck_openid4vci_dataset_configuration_id CHECK (((char_length(btrim((credential_configuration_id)::text)) >= 1) AND (char_length(btrim((credential_configuration_id)::text)) <= 255))),
    CONSTRAINT ck_openid4vci_dataset_source CHECK (((char_length(btrim((source)::text)) >= 1) AND (char_length(btrim((source)::text)) <= 255))),
    CONSTRAINT ck_openid4vci_dataset_validity CHECK (((valid_until IS NULL) OR (valid_from IS NULL) OR (valid_until > valid_from)))
);

COMMENT ON TABLE public.openid4vci_credential_datasets IS 'Application-encrypted issuer-authoritative credential claims. Protocol handlers never synthesize credential evidence from request inputs.';

CREATE TABLE public.openid4vci_deferred_transactions (
    id uuid NOT NULL,
    transaction_hash character varying(64) NOT NULL,
    token_id uuid NOT NULL,
    credential_configuration_id character varying(255) CONSTRAINT openid4vci_deferred_transac_credential_configuration_i_not_null NOT NULL,
    credential_format character varying(32) NOT NULL,
    holder_bindings jsonb NOT NULL,
    payload_ciphertext bytea NOT NULL,
    ready_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    claim_id character varying(128),
    claim_expires_at timestamp with time zone,
    authorization_id uuid,
    credential_selection jsonb,
    claim_token_id uuid,
    CONSTRAINT ck_openid4vci_deferred_claim CHECK ((((claim_id IS NULL) AND (claim_expires_at IS NULL)) OR ((claim_id IS NOT NULL) AND (claim_expires_at IS NOT NULL) AND ((char_length(btrim((claim_id)::text)) >= 1) AND (char_length(btrim((claim_id)::text)) <= 128))))),
    CONSTRAINT ck_openid4vci_deferred_consumed CHECK (((consumed_at IS NULL) OR (consumed_at >= ready_at))),
    CONSTRAINT ck_openid4vci_deferred_format CHECK (((credential_format)::text = ANY ((ARRAY['dc+sd-jwt'::character varying, 'mso_mdoc'::character varying])::text[]))),
    CONSTRAINT ck_openid4vci_deferred_holder_bindings CHECK (((jsonb_typeof(holder_bindings) = 'array'::text) AND (jsonb_array_length(holder_bindings) > 0))),
    CONSTRAINT ck_openid4vci_deferred_times CHECK (((ready_at >= created_at) AND (expires_at > ready_at)))
);

COMMENT ON COLUMN public.openid4vci_deferred_transactions.payload_ciphertext IS 'AEAD-encrypted deferred credential dataset; plaintext claims are never persisted.';

COMMENT ON COLUMN public.openid4vci_deferred_transactions.claim_id IS 'Ephemeral deferred-issuance lease owner; consumed_at is set only after signing succeeds.';

CREATE TABLE public.openid4vci_issuance_responses (
    issuance_id uuid NOT NULL,
    token_id uuid NOT NULL,
    request_digest character varying(64) NOT NULL,
    body_ciphertext bytea NOT NULL,
    encoding character varying(16) NOT NULL,
    status smallint NOT NULL,
    dpop_nonce character varying(256),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    credential_selection jsonb,
    CONSTRAINT ck_openid4vci_issuance_response_digest CHECK (((request_digest)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_openid4vci_issuance_response_encoding CHECK (((encoding)::text = ANY ((ARRAY['json'::character varying, 'jwt'::character varying])::text[]))),
    CONSTRAINT ck_openid4vci_issuance_response_expiry CHECK ((expires_at > created_at)),
    CONSTRAINT ck_openid4vci_issuance_response_status CHECK ((status = ANY (ARRAY[200, 202])))
);

COMMENT ON COLUMN public.openid4vci_issuance_responses.body_ciphertext IS 'AEAD-encrypted exact credential HTTP response body; plaintext is never persisted.';

CREATE TABLE public.openid4vci_nonces (
    nonce_hash character varying(64) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    claim_id character varying(128),
    claim_expires_at timestamp with time zone,
    CONSTRAINT ck_openid4vci_nonce_claim CHECK ((((claim_id IS NULL) AND (claim_expires_at IS NULL)) OR ((claim_id IS NOT NULL) AND (claim_expires_at IS NOT NULL) AND ((char_length(btrim((claim_id)::text)) >= 1) AND (char_length(btrim((claim_id)::text)) <= 128))))),
    CONSTRAINT ck_openid4vci_nonce_consumed CHECK (((consumed_at IS NULL) OR (consumed_at >= created_at))),
    CONSTRAINT ck_openid4vci_nonce_expiry CHECK ((expires_at > created_at))
);

COMMENT ON COLUMN public.openid4vci_nonces.claim_id IS 'Ephemeral issuance lease owner; consumed_at remains the permanent single-use marker.';

CREATE TABLE public.openid4vci_notifications (
    notification_id character varying(128) NOT NULL,
    token_id uuid NOT NULL,
    event character varying(32),
    description character varying(1024),
    expires_at timestamp with time zone NOT NULL,
    occurred_at timestamp with time zone,
    issued_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    credential_selection jsonb,
    CONSTRAINT ck_openid4vci_notification_description CHECK (((description IS NULL) OR ((char_length(btrim((description)::text)) >= 1) AND (char_length(btrim((description)::text)) <= 1024)))),
    CONSTRAINT ck_openid4vci_notification_event CHECK (((event IS NULL) OR ((event)::text = ANY ((ARRAY['credential_accepted'::character varying, 'credential_failure'::character varying, 'credential_deleted'::character varying])::text[])))),
    CONSTRAINT ck_openid4vci_notification_expiry CHECK ((expires_at > issued_at)),
    CONSTRAINT ck_openid4vci_notification_terminal CHECK ((((event IS NULL) AND (occurred_at IS NULL)) OR ((event IS NOT NULL) AND (occurred_at IS NOT NULL))))
);

CREATE TABLE public.openid4vci_offers (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    subject_id uuid,
    credential_configuration_ids jsonb NOT NULL,
    grants_ciphertext bytea NOT NULL,
    issuer_state_hash character varying(64),
    pre_authorized_code_hash character varying(64),
    tx_code_hash character varying(255),
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_openid4vci_offer_configuration_ids CHECK (((jsonb_typeof(credential_configuration_ids) = 'array'::text) AND (jsonb_array_length(credential_configuration_ids) > 0))),
    CONSTRAINT ck_openid4vci_offer_consumed CHECK (((consumed_at IS NULL) OR (consumed_at >= created_at))),
    CONSTRAINT ck_openid4vci_offer_expiry CHECK ((expires_at > created_at))
);

COMMENT ON COLUMN public.openid4vci_offers.consumed_at IS 'Single-use consumption timestamp shared by authorization-code and pre-authorized-code grants.';

CREATE TABLE public.openid4vp_transactions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    client_id_prefix character varying(32) NOT NULL,
    request_method character varying(32) NOT NULL,
    wallet_authorization_endpoint text NOT NULL,
    state_hash character varying(64) NOT NULL,
    request jsonb NOT NULL,
    request_object text,
    request_uri text,
    ephemeral_private_key_ciphertext bytea,
    result_ciphertext bytea,
    completed_at timestamp with time zone,
    create_request_jti character varying(36) NOT NULL,
    create_request_sha256 character varying(64) NOT NULL,
    create_request_canonical_json text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    openid4vc_trust_policy_binding_id uuid,
    openid4vc_trust_policy_resource_id character varying(255),
    openid4vc_trust_policy_digest character varying(64),
    CONSTRAINT ck_openid4vp_client_id_prefix CHECK (((client_id_prefix)::text = ANY ((ARRAY['redirect_uri'::character varying, 'x509_san_dns'::character varying, 'x509_hash'::character varying])::text[]))),
    CONSTRAINT ck_openid4vp_create_request_shape CHECK ((((create_request_jti)::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) AND ((create_request_sha256)::text ~ '^[0-9a-f]{64}$'::text) AND (create_request_canonical_json <> ''::text) AND (octet_length(create_request_canonical_json) <= 65536))),
    CONSTRAINT ck_openid4vp_expiry CHECK ((expires_at > created_at)),
    CONSTRAINT ck_openid4vp_request_method CHECK (((request_method)::text = ANY ((ARRAY['url_query'::character varying, 'request_uri_signed_get'::character varying, 'request_uri_signed_post'::character varying])::text[]))),
    CONSTRAINT ck_openid4vp_request_object CHECK (((jsonb_typeof(request) = 'object'::text) AND (request <> '{}'::jsonb))),
    CONSTRAINT ck_openid4vp_request_response_mode CHECK (COALESCE(((request ->> 'response_mode'::text) = ANY (ARRAY['direct_post'::text, 'direct_post.jwt'::text])), false)),
    CONSTRAINT ck_openid4vp_result_shape CHECK ((((completed_at IS NULL) AND (result_ciphertext IS NULL)) OR ((completed_at IS NOT NULL) AND (result_ciphertext IS NOT NULL)))),
    CONSTRAINT ck_openid4vp_transactions_trust_policy_binding CHECK ((((openid4vc_trust_policy_binding_id IS NULL) AND (openid4vc_trust_policy_resource_id IS NULL) AND (openid4vc_trust_policy_digest IS NULL)) OR ((openid4vc_trust_policy_binding_id IS NOT NULL) AND (openid4vc_trust_policy_resource_id IS NOT NULL) AND (openid4vc_trust_policy_digest IS NOT NULL) AND ((char_length(btrim((openid4vc_trust_policy_resource_id)::text)) >= 1) AND (char_length(btrim((openid4vc_trust_policy_resource_id)::text)) <= 255)) AND ((openid4vc_trust_policy_resource_id)::text = btrim((openid4vc_trust_policy_resource_id)::text)) AND ((openid4vc_trust_policy_digest)::text ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT ck_openid4vp_wallet_endpoint CHECK ((wallet_authorization_endpoint ~ '^https://'::text))
);

COMMENT ON COLUMN public.openid4vp_transactions.ephemeral_private_key_ciphertext IS 'AEAD-encrypted per-request response-decryption key; plaintext is never persisted.';

COMMENT ON COLUMN public.openid4vp_transactions.result_ciphertext IS 'AEAD-encrypted disclosed presentation result with short retention.';

COMMENT ON COLUMN public.openid4vp_transactions.create_request_jti IS 'Caller-generated, tenant-bound management idempotency key for exact OpenID4VP create response recovery.';

COMMENT ON COLUMN public.openid4vp_transactions.create_request_canonical_json IS 'Canonical normalized management request compared with its SHA-256 digest to prevent JTI aliasing.';

CREATE TABLE public.organizations (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    slug character varying(120) NOT NULL,
    display_name character varying(200) NOT NULL,
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_organizations_slug_non_empty CHECK ((length(TRIM(BOTH FROM slug)) > 0)),
    CONSTRAINT ck_organizations_status_value CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'deleted'::character varying])::text[])))
);

COMMENT ON TABLE public.organizations IS 'Organization boundary within a tenant; future SCIM provisioning binds here.';

CREATE TABLE public.realms (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    slug character varying(120) NOT NULL,
    display_name character varying(200) NOT NULL,
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_realms_slug_non_empty CHECK ((length(TRIM(BOTH FROM slug)) > 0)),
    CONSTRAINT ck_realms_status_value CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'deleted'::character varying])::text[])))
);

COMMENT ON TABLE public.realms IS 'Authentication realm within a tenant; future external IdP federation binds here.';

CREATE TABLE public.recovery_invalidations (
    operation_id uuid NOT NULL,
    request_hash character varying(64) NOT NULL,
    tenant_id uuid NOT NULL,
    state_epoch uuid NOT NULL,
    not_before timestamp with time zone NOT NULL,
    revoked_refresh_tokens bigint NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    coverage_version smallint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_recovery_invalidations_coverage CHECK ((coverage_version = ANY (ARRAY[0, 1]))),
    CONSTRAINT ck_recovery_invalidations_not_before CHECK ((not_before > completed_at)),
    CONSTRAINT ck_recovery_invalidations_request_hash CHECK (((request_hash)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_recovery_invalidations_revoked_refresh_tokens CHECK ((revoked_refresh_tokens >= 0))
);

CREATE TABLE public.runtime_module_desired_states (
    module_id character varying(64) NOT NULL,
    desired_mode character varying(16) NOT NULL,
    revision bigint NOT NULL,
    actor_id uuid,
    reason character varying(500),
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT ck_runtime_module_desired_mode CHECK (((desired_mode)::text = ANY ((ARRAY['enabled'::character varying, 'disabled'::character varying])::text[]))),
    CONSTRAINT ck_runtime_module_desired_module_id CHECK (((module_id)::text = ANY ((ARRAY['device_authorization'::character varying, 'token_exchange'::character varying, 'jwt_bearer_grant'::character varying, 'ciba'::character varying, 'dynamic_client_registration'::character varying, 'request_objects'::character varying, 'jarm'::character varying, 'authorization_details'::character varying, 'http_message_signatures'::character varying, 'scim'::character varying, 'scim_security_events'::character varying, 'native_sso'::character varying, 'frontchannel_logout'::character varying, 'session_management'::character varying, 'openid4vci_issuer'::character varying, 'openid4vp_verifier'::character varying])::text[]))),
    CONSTRAINT ck_runtime_module_desired_reason CHECK (((reason IS NULL) OR ((char_length(btrim((reason)::text)) >= 1) AND (char_length(btrim((reason)::text)) <= 500)))),
    CONSTRAINT ck_runtime_module_desired_revision CHECK ((revision > 0))
);

CREATE TABLE public.runtime_module_instance_states (
    instance_id character varying(255) NOT NULL,
    module_id character varying(64) NOT NULL,
    actual_state character varying(16) NOT NULL,
    transition_revision bigint NOT NULL,
    applied_revision bigint,
    drain_deadline timestamp with time zone,
    error_code character varying(128),
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT ck_runtime_module_actual_state CHECK (((actual_state)::text = ANY ((ARRAY['disabled'::character varying, 'starting'::character varying, 'enabled'::character varying, 'draining'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT ck_runtime_module_applied_revision CHECK (((applied_revision IS NULL) OR ((applied_revision >= 0) AND (applied_revision <= transition_revision)))),
    CONSTRAINT ck_runtime_module_instance_error_code CHECK (((error_code IS NULL) OR ((char_length(btrim((error_code)::text)) >= 1) AND (char_length(btrim((error_code)::text)) <= 128)))),
    CONSTRAINT ck_runtime_module_instance_id CHECK (((char_length(btrim((instance_id)::text)) >= 1) AND (char_length(btrim((instance_id)::text)) <= 255))),
    CONSTRAINT ck_runtime_module_instance_module_id CHECK (((module_id)::text = ANY ((ARRAY['device_authorization'::character varying, 'token_exchange'::character varying, 'jwt_bearer_grant'::character varying, 'ciba'::character varying, 'dynamic_client_registration'::character varying, 'request_objects'::character varying, 'jarm'::character varying, 'authorization_details'::character varying, 'http_message_signatures'::character varying, 'scim'::character varying, 'scim_security_events'::character varying, 'native_sso'::character varying, 'frontchannel_logout'::character varying, 'session_management'::character varying, 'openid4vci_issuer'::character varying, 'openid4vp_verifier'::character varying])::text[]))),
    CONSTRAINT ck_runtime_module_transition_revision CHECK ((transition_revision >= 0))
);

CREATE TABLE public.runtime_module_state_events (
    event_id uuid NOT NULL,
    module_id character varying(64) NOT NULL,
    event_type character varying(32) NOT NULL,
    revision bigint NOT NULL,
    instance_id character varying(255),
    actor_id uuid,
    reason character varying(500),
    before_state character varying(16),
    after_state character varying(16),
    outcome_code character varying(128),
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT ck_runtime_module_event_after_state CHECK (((after_state IS NULL) OR ((after_state)::text = ANY ((ARRAY['inherit'::character varying, 'disabled'::character varying, 'starting'::character varying, 'enabled'::character varying, 'draining'::character varying, 'failed'::character varying])::text[])))),
    CONSTRAINT ck_runtime_module_event_before_state CHECK (((before_state IS NULL) OR ((before_state)::text = ANY ((ARRAY['inherit'::character varying, 'disabled'::character varying, 'starting'::character varying, 'enabled'::character varying, 'draining'::character varying, 'failed'::character varying])::text[])))),
    CONSTRAINT ck_runtime_module_event_instance_id CHECK (((instance_id IS NULL) OR ((char_length(btrim((instance_id)::text)) >= 1) AND (char_length(btrim((instance_id)::text)) <= 255)))),
    CONSTRAINT ck_runtime_module_event_module_id CHECK (((module_id)::text = ANY ((ARRAY['device_authorization'::character varying, 'token_exchange'::character varying, 'jwt_bearer_grant'::character varying, 'ciba'::character varying, 'dynamic_client_registration'::character varying, 'request_objects'::character varying, 'jarm'::character varying, 'authorization_details'::character varying, 'http_message_signatures'::character varying, 'scim'::character varying, 'scim_security_events'::character varying, 'native_sso'::character varying, 'frontchannel_logout'::character varying, 'session_management'::character varying, 'openid4vci_issuer'::character varying, 'openid4vp_verifier'::character varying])::text[]))),
    CONSTRAINT ck_runtime_module_event_outcome_code CHECK (((outcome_code IS NULL) OR ((char_length(btrim((outcome_code)::text)) >= 1) AND (char_length(btrim((outcome_code)::text)) <= 128)))),
    CONSTRAINT ck_runtime_module_event_reason CHECK (((reason IS NULL) OR ((char_length(btrim((reason)::text)) >= 1) AND (char_length(btrim((reason)::text)) <= 500)))),
    CONSTRAINT ck_runtime_module_event_revision CHECK ((revision >= 0)),
    CONSTRAINT ck_runtime_module_event_state_kind CHECK (((((event_type)::text = 'desired_state_changed'::text) AND ((before_state IS NULL) OR ((before_state)::text = ANY ((ARRAY['inherit'::character varying, 'enabled'::character varying, 'disabled'::character varying])::text[]))) AND ((after_state IS NULL) OR ((after_state)::text = ANY ((ARRAY['inherit'::character varying, 'enabled'::character varying, 'disabled'::character varying])::text[])))) OR (((event_type)::text <> 'desired_state_changed'::text) AND ((before_state IS NULL) OR ((before_state)::text = ANY ((ARRAY['disabled'::character varying, 'starting'::character varying, 'enabled'::character varying, 'draining'::character varying, 'failed'::character varying])::text[]))) AND ((after_state IS NULL) OR ((after_state)::text = ANY ((ARRAY['disabled'::character varying, 'starting'::character varying, 'enabled'::character varying, 'draining'::character varying, 'failed'::character varying])::text[])))))),
    CONSTRAINT ck_runtime_module_event_type CHECK (((event_type)::text = ANY ((ARRAY['desired_state_changed'::character varying, 'transition_started'::character varying, 'transition_completed'::character varying, 'transition_failed'::character varying, 'drain_started'::character varying, 'drain_completed'::character varying, 'stale_transition_discarded'::character varying])::text[])))
);

CREATE TABLE public.scim_audit_events (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    scim_token_id uuid,
    event_type character varying(64) NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    ip_hash character varying(64),
    user_agent_hash character varying(64),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_scim_audit_events_event_type CHECK (((event_type)::text = ANY ((ARRAY['scim_token_used'::character varying, 'scim_token_denied'::character varying])::text[]))),
    CONSTRAINT ck_scim_audit_events_scopes_array CHECK ((jsonb_typeof(scopes) = 'array'::text))
);

CREATE TABLE public.scim_security_event_receipts (
    event_id uuid NOT NULL,
    scim_token_id uuid NOT NULL,
    disposition character varying(16) NOT NULL,
    error_code character varying(64),
    error_description text,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_scim_security_event_receipts_disposition CHECK (((disposition)::text = ANY ((ARRAY['acknowledged'::character varying, 'error'::character varying])::text[]))),
    CONSTRAINT ck_scim_security_event_receipts_error_shape CHECK (((((disposition)::text = 'acknowledged'::text) AND (error_code IS NULL) AND (error_description IS NULL)) OR (((disposition)::text = 'error'::text) AND (error_code IS NOT NULL) AND (error_description IS NOT NULL))))
);

CREATE TABLE public.scim_security_events (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    subject_uri text NOT NULL,
    events jsonb NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_scim_security_events_payload_object CHECK (((jsonb_typeof(events) = 'object'::text) AND (events <> '{}'::jsonb))),
    CONSTRAINT ck_scim_security_events_retention CHECK ((expires_at > occurred_at)),
    CONSTRAINT ck_scim_security_events_subject_uri CHECK ((subject_uri ~ '^/Users/[0-9a-fA-F-]{36}$'::text))
);

CREATE TABLE public.scim_tokens (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    token_hash character varying(64) NOT NULL,
    label character varying(120) NOT NULL,
    scopes jsonb DEFAULT '["scim:read", "scim:write"]'::jsonb NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    event_audience character varying(2048),
    CONSTRAINT ck_scim_tokens_event_audience_non_empty CHECK (((event_audience IS NULL) OR (length(btrim((event_audience)::text)) > 0))),
    CONSTRAINT ck_scim_tokens_label_non_empty CHECK ((length(btrim((label)::text)) > 0)),
    CONSTRAINT ck_scim_tokens_scopes_array CHECK ((jsonb_typeof(scopes) = 'array'::text)),
    CONSTRAINT ck_scim_tokens_token_hash_hex CHECK (((token_hash)::text ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.security_audit_chain_entries (
    event_id uuid NOT NULL,
    sequence bigint NOT NULL,
    previous_hash bytea NOT NULL,
    event_hash bytea NOT NULL,
    CONSTRAINT security_audit_chain_entries_event_hash_check CHECK ((octet_length(event_hash) = 32)),
    CONSTRAINT security_audit_chain_entries_previous_hash_check CHECK ((octet_length(previous_hash) = 32)),
    CONSTRAINT security_audit_chain_entries_sequence_check CHECK ((sequence > 0))
)
WITH (autovacuum_vacuum_scale_factor='0', autovacuum_vacuum_threshold='500', autovacuum_vacuum_cost_delay='0', autovacuum_analyze_scale_factor='0', autovacuum_analyze_threshold='500');

COMMENT ON TABLE public.security_audit_chain_entries IS 'Immutable global chain assigned only by the exporter after event commit.';

CREATE TABLE public.security_audit_chain_state (
    singleton boolean NOT NULL,
    last_sequence bigint NOT NULL,
    last_hash bytea NOT NULL,
    anchor_deployment_id character varying(255),
    anchor_sequence bigint,
    anchor_hash bytea,
    anchor_occurred_at timestamp with time zone,
    anchor_accepted_at timestamp with time zone,
    anchor_observed_at timestamp with time zone,
    batch_first_sequence bigint,
    batch_last_sequence bigint,
    batch_event_count integer,
    batch_digest bytea,
    batch_generation bigint DEFAULT 0 NOT NULL,
    batch_attempts integer DEFAULT 0 NOT NULL,
    batch_available_at timestamp with time zone,
    batch_locked_until timestamp with time zone,
    batch_last_error character varying(128),
    batch_blocked_reason character varying(128),
    CONSTRAINT ck_security_audit_anchor_checkpoint_complete CHECK ((((anchor_deployment_id IS NULL) AND (anchor_sequence IS NULL) AND (anchor_hash IS NULL) AND (anchor_occurred_at IS NULL) AND (anchor_accepted_at IS NULL)) OR (((anchor_deployment_id IS NULL) OR ((char_length((anchor_deployment_id)::text) >= 1) AND (char_length((anchor_deployment_id)::text) <= 255))) AND (anchor_sequence IS NOT NULL) AND (anchor_sequence >= 0) AND (anchor_hash IS NOT NULL) AND (octet_length(anchor_hash) = 32) AND (anchor_occurred_at IS NOT NULL) AND (anchor_accepted_at IS NOT NULL) AND (anchor_accepted_at >= anchor_occurred_at)))),
    CONSTRAINT ck_security_audit_batch_attempts_non_negative CHECK ((batch_attempts >= 0)),
    CONSTRAINT ck_security_audit_batch_digest_length CHECK (((batch_digest IS NULL) OR (octet_length(batch_digest) = 32))),
    CONSTRAINT ck_security_audit_batch_shape CHECK ((((batch_first_sequence IS NULL) AND (batch_last_sequence IS NULL) AND (batch_event_count IS NULL) AND (batch_digest IS NULL)) OR ((batch_first_sequence IS NOT NULL) AND (batch_first_sequence > 0) AND (batch_last_sequence IS NOT NULL) AND (batch_last_sequence >= batch_first_sequence) AND (batch_event_count IS NOT NULL) AND (batch_event_count = ((batch_last_sequence - batch_first_sequence) + 1)) AND ((batch_event_count >= 1) AND (batch_event_count <= 256))))),
    CONSTRAINT ck_security_audit_chain_hash_length CHECK ((octet_length(last_hash) = 32)),
    CONSTRAINT ck_security_audit_chain_sequence_non_negative CHECK ((last_sequence >= 0)),
    CONSTRAINT ck_security_audit_chain_singleton CHECK (singleton)
);

COMMENT ON TABLE public.security_audit_chain_state IS 'Immutable audit chain head; owned by the dedicated migration owner; runtime roles use SECURITY DEFINER APIs.';

CREATE TABLE public.security_audit_events (
    event_id uuid NOT NULL,
    event_type character varying(64) NOT NULL,
    event_category character varying(64) NOT NULL,
    payload jsonb NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    authorization_tenant_id uuid,
    authorization_request_id text,
    authorization_par_uri text,
    authorization_decision text,
    authorization_valid_until timestamp with time zone,
    business_retain_until timestamp with time zone,
    exported_at timestamp with time zone,
    CONSTRAINT ck_security_audit_authorization_decision CHECK (
CASE
    WHEN ((event_type)::text = 'authorization_decision_committed'::text) THEN ((authorization_tenant_id IS NOT NULL) AND (authorization_tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (authorization_request_id IS NOT NULL) AND ((octet_length(authorization_request_id) >= 1) AND (octet_length(authorization_request_id) <= 512)) AND ((authorization_par_uri IS NULL) OR ((octet_length(authorization_par_uri) >= 1) AND (octet_length(authorization_par_uri) <= 1024))) AND (authorization_decision IS NOT NULL) AND (authorization_decision = ANY (ARRAY['approve'::text, 'deny'::text, 'prompt_none'::text])) AND (authorization_valid_until IS NOT NULL) AND isfinite(authorization_valid_until) AND (business_retain_until IS NOT NULL) AND isfinite(business_retain_until) AND (business_retain_until >= authorization_valid_until) AND (business_retain_until >= occurred_at) AND ((event_category)::text = 'authorization'::text))
    ELSE ((authorization_tenant_id IS NULL) AND (authorization_request_id IS NULL) AND (authorization_par_uri IS NULL) AND (authorization_decision IS NULL) AND (authorization_valid_until IS NULL) AND (business_retain_until IS NULL) AND (exported_at IS NULL))
END),
    CONSTRAINT ck_security_audit_event_category CHECK ((((char_length((event_category)::text) >= 1) AND (char_length((event_category)::text) <= 64)) AND ((event_category)::text ~ '^[a-z][a-z0-9_]*$'::text))),
    CONSTRAINT ck_security_audit_event_payload_object CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT ck_security_audit_event_type CHECK ((((char_length((event_type)::text) >= 1) AND (char_length((event_type)::text) <= 64)) AND ((event_type)::text ~ '^[a-z][a-z0-9_]*$'::text)))
)
WITH (autovacuum_analyze_scale_factor='0', autovacuum_analyze_threshold='500', autovacuum_vacuum_scale_factor='0', autovacuum_vacuum_threshold='2000', autovacuum_vacuum_cost_delay='0');

COMMENT ON TABLE public.security_audit_events IS 'Canonical immutable audit facts and pending deliveries. Authorization decisions remain after ACK until business retention expires; other events leave at ACK.';

CREATE TABLE public.tenant_directory_control_operations (
    operation_id uuid NOT NULL,
    request_hash character varying(64) NOT NULL,
    tenant_id uuid,
    operation character varying(16) NOT NULL,
    outcome jsonb NOT NULL,
    CONSTRAINT ck_tenant_directory_control_operation CHECK (((operation)::text = ANY ((ARRAY['create'::character varying, 'update'::character varying, 'disable'::character varying, 'reload'::character varying, 'finalize'::character varying, 'describe'::character varying])::text[]))),
    CONSTRAINT ck_tenant_directory_control_outcome CHECK (((jsonb_typeof(outcome) = 'object'::text) AND (octet_length(convert_to((outcome)::text, 'UTF8'::name)) <= 1048576))),
    CONSTRAINT ck_tenant_directory_control_request_hash CHECK (((request_hash)::text ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.tenant_resource_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    resource_kind character varying(64) NOT NULL,
    resource_id character varying(255) NOT NULL,
    resource_digest character varying(64) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    locator text NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_tenant_resource_binding_digest CHECK (((resource_digest)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_tenant_resource_binding_id CHECK ((((char_length(btrim((resource_id)::text)) >= 1) AND (char_length(btrim((resource_id)::text)) <= 255)) AND ((resource_id)::text = btrim((resource_id)::text)))),
    CONSTRAINT ck_tenant_resource_binding_kind CHECK (((resource_kind)::text = ANY ((ARRAY['oauth-client'::character varying, 'mtls-trust-anchor'::character varying, 'openid4vc-dataset'::character varying, 'openid4vc-trust-policy'::character varying, 'user'::character varying])::text[]))),
    CONSTRAINT ck_tenant_resource_binding_locator CHECK (((char_length(btrim(locator)) >= 1) AND (char_length(btrim(locator)) <= 2048)))
);

COMMENT ON TABLE public.tenant_resource_bindings IS 'Tenant-scoped resource identity/version bindings. Active rows are unique per typed resource identity.';

CREATE TABLE public.tenant_resource_control_operations (
    operation_id uuid NOT NULL,
    request_hash character varying(64) NOT NULL,
    tenant_id uuid NOT NULL,
    operation character varying(32) NOT NULL,
    outcome jsonb NOT NULL,
    CONSTRAINT ck_tenant_resource_control_operation CHECK (((operation)::text = ANY ((ARRAY['apply'::character varying, 'enumerate'::character varying, 'revoke'::character varying])::text[]))),
    CONSTRAINT ck_tenant_resource_control_outcome CHECK (((jsonb_typeof(outcome) = 'object'::text) AND (octet_length(convert_to((outcome)::text, 'UTF8'::name)) <= 1048576))),
    CONSTRAINT ck_tenant_resource_control_request_hash CHECK (((request_hash)::text ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.tenant_resource_states (
    tenant_id uuid NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    resource_manifest_sha256 character varying(64) NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_tenant_resource_state_manifest_sha256 CHECK (((resource_manifest_sha256)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_tenant_resource_state_revision CHECK ((revision >= 0))
);

COMMENT ON TABLE public.tenant_resource_states IS 'Authoritative tenant-scoped desired resource revision and canonical manifest digest.';

CREATE TABLE public.tenant_runtime_bindings (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    issuer text NOT NULL,
    external_host character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    runtime_revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT ck_tenant_runtime_binding_host CHECK ((((char_length(btrim((external_host)::text)) >= 1) AND (char_length(btrim((external_host)::text)) <= 255)) AND ((external_host)::text = btrim((external_host)::text)) AND ((external_host)::text = lower((external_host)::text)))),
    CONSTRAINT ck_tenant_runtime_binding_issuer CHECK ((((char_length(btrim(issuer)) >= 1) AND (char_length(btrim(issuer)) <= 2048)) AND (issuer = btrim(issuer)))),
    CONSTRAINT ck_tenant_runtime_binding_revision CHECK ((runtime_revision > 0))
);

CREATE TABLE public.tenant_runtime_directory_state (
    singleton boolean DEFAULT true NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_tenant_runtime_directory_revision CHECK ((revision >= 0)),
    CONSTRAINT ck_tenant_runtime_directory_singleton CHECK (singleton)
);

CREATE TABLE public.tenant_signing_keysets (
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL,
    public_metadata jsonb NOT NULL,
    encrypted_private_material bytea NOT NULL,
    wrapping_key_id character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT tenant_signing_keysets_revision_check CHECK ((revision >= 1))
);

CREATE TABLE public.tenants (
    id uuid DEFAULT uuidv7() NOT NULL,
    slug character varying(120) NOT NULL,
    display_name character varying(200) NOT NULL,
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_tenants_slug_non_empty CHECK ((length(TRIM(BOTH FROM slug)) > 0)),
    CONSTRAINT ck_tenants_status_value CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'deleted'::character varying])::text[])))
);

COMMENT ON TABLE public.tenants IS 'Top-level isolation boundary for users, clients, grants, tokens, and enterprise identity integrations.';

CREATE TABLE public.user_client_grants (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    first_authorized_at timestamp with time zone NOT NULL,
    last_authorized_at timestamp with time zone NOT NULL,
    last_scopes jsonb NOT NULL,
    authorization_count integer DEFAULT 1 NOT NULL,
    last_authorization_details jsonb DEFAULT '[]'::jsonb NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    last_resource_indicators jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT ck_user_client_grants_authorization_details_array CHECK ((jsonb_typeof(last_authorization_details) = 'array'::text)),
    CONSTRAINT ck_user_client_grants_last_scopes_array CHECK ((jsonb_typeof(last_scopes) = 'array'::text)),
    CONSTRAINT ck_user_client_grants_resource_indicators_array CHECK ((jsonb_typeof(last_resource_indicators) = 'array'::text))
);

CREATE TABLE public.user_mfa_backup_codes (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash character varying(255) NOT NULL,
    CONSTRAINT ck_user_mfa_backup_codes_hash_non_empty CHECK ((length(TRIM(BOTH FROM code_hash)) > 0))
);

CREATE TABLE public.user_mfa_remembered_devices (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash character varying(64) NOT NULL,
    user_agent_hash character varying(64),
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_user_mfa_remembered_devices_token_hash CHECK ((length(TRIM(BOTH FROM token_hash)) = 64))
);

CREATE TABLE public.user_passkey_credentials (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_id character varying(2048) NOT NULL,
    credential jsonb NOT NULL,
    label character varying(120) NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_user_passkey_credentials_credential_id_non_empty CHECK ((length(TRIM(BOTH FROM credential_id)) > 0)),
    CONSTRAINT ck_user_passkey_credentials_label_non_empty CHECK ((length(TRIM(BOTH FROM label)) > 0)),
    CONSTRAINT ck_user_passkey_credentials_sign_count_non_negative CHECK ((sign_count >= 0))
);

CREATE TABLE public.user_totp_credentials (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    confirmed_at timestamp with time zone,
    last_used_step bigint,
    secret_ciphertext bytea NOT NULL,
    secret_key_id character varying(128) NOT NULL,
    CONSTRAINT ck_user_totp_credentials_secret_envelope CHECK ((((octet_length(secret_ciphertext) >= 45) AND (octet_length(secret_ciphertext) <= 157)) AND (get_byte(secret_ciphertext, 0) = 1) AND ((char_length(btrim((secret_key_id)::text)) >= 1) AND (char_length(btrim((secret_key_id)::text)) <= 128))))
);

CREATE TABLE public.users (
    id uuid DEFAULT uuidv7() NOT NULL,
    username character varying(150) NOT NULL,
    email character varying(254) NOT NULL,
    password_hash character varying(512) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    mfa_enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    display_name character varying(80),
    avatar_url character varying(512),
    role character varying(16) DEFAULT 'user'::character varying NOT NULL,
    admin_level integer DEFAULT 0 NOT NULL,
    given_name character varying(80),
    family_name character varying(80),
    middle_name character varying(80),
    nickname character varying(80),
    profile_url character varying(512),
    website_url character varying(512),
    gender character varying(40),
    birthdate character varying(10),
    zoneinfo character varying(64),
    locale character varying(35),
    address_formatted character varying(512),
    address_street_address character varying(256),
    address_locality character varying(128),
    address_region character varying(128),
    address_postal_code character varying(64),
    address_country character varying(64),
    phone_number character varying(32),
    phone_number_verified boolean DEFAULT false NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    realm_id uuid DEFAULT '00000000-0000-0000-0000-000000000002'::uuid NOT NULL,
    organization_id uuid DEFAULT '00000000-0000-0000-0000-000000000003'::uuid NOT NULL,
    access_token_epoch bigint DEFAULT 0 NOT NULL,
    CONSTRAINT ck_users_admin_level_non_negative CHECK ((admin_level >= 0)),
    CONSTRAINT ck_users_role_value CHECK (((role)::text = ANY ((ARRAY['user'::character varying, 'admin'::character varying])::text[]))),
    CONSTRAINT users_access_token_epoch_check CHECK ((access_token_epoch >= 0))
);

COMMENT ON COLUMN public.users.role IS 'user=normal account, admin=administrator';

COMMENT ON COLUMN public.users.tenant_id IS 'Tenant isolation key; default preserves existing single-tenant deployments.';

ALTER TABLE ONLY public.access_token_revocations
    ADD CONSTRAINT access_token_revocations_pkey PRIMARY KEY (tenant_id, access_token_jti_blake3);

ALTER TABLE ONLY public.admin_provision_receipts
    ADD CONSTRAINT admin_provision_receipts_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY public.backchannel_logout_deliveries
    ADD CONSTRAINT backchannel_logout_deliveries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT client_access_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.external_identity_links
    ADD CONSTRAINT external_identity_links_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.identity_security_events
    ADD CONSTRAINT identity_security_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_events
    ADD CONSTRAINT oauth_client_mtls_trust_anchor_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT oauth_client_mtls_trust_anchor_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_subject_bindings
    ADD CONSTRAINT oauth_subject_bindings_pkey PRIMARY KEY (tenant_id, subject);

ALTER TABLE ONLY public.oauth_token_issuances
    ADD CONSTRAINT oauth_token_issuances_pkey PRIMARY KEY (issuance_id);

ALTER TABLE public.oauth_token_issuances
    ADD CONSTRAINT oauth_token_issuances_receipt_contract_check CHECK (((single_use_key_blake3 IS NULL) OR (receipt_contract_version = 2))) NOT VALID;

ALTER TABLE ONLY public.openid4vc_trust_policies
    ADD CONSTRAINT openid4vc_trust_policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vc_trust_policy_clients
    ADD CONSTRAINT openid4vc_trust_policy_clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vci_access_grants
    ADD CONSTRAINT openid4vci_access_grants_pkey PRIMARY KEY (token_id);

ALTER TABLE ONLY public.openid4vci_access_grants
    ADD CONSTRAINT openid4vci_access_grants_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.openid4vci_credential_dataset_events
    ADD CONSTRAINT openid4vci_credential_dataset_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vci_credential_datasets
    ADD CONSTRAINT openid4vci_credential_datasets_pkey PRIMARY KEY (tenant_id, subject_id, credential_configuration_id);

ALTER TABLE ONLY public.openid4vci_deferred_transactions
    ADD CONSTRAINT openid4vci_deferred_transactions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vci_deferred_transactions
    ADD CONSTRAINT openid4vci_deferred_transactions_transaction_hash_key UNIQUE (transaction_hash);

ALTER TABLE ONLY public.openid4vci_issuance_responses
    ADD CONSTRAINT openid4vci_issuance_responses_pkey PRIMARY KEY (issuance_id);

ALTER TABLE ONLY public.openid4vci_nonces
    ADD CONSTRAINT openid4vci_nonces_pkey PRIMARY KEY (nonce_hash);

ALTER TABLE ONLY public.openid4vci_notifications
    ADD CONSTRAINT openid4vci_notifications_pkey PRIMARY KEY (notification_id);

ALTER TABLE ONLY public.openid4vci_offers
    ADD CONSTRAINT openid4vci_offers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vp_transactions
    ADD CONSTRAINT openid4vp_transactions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.openid4vp_transactions
    ADD CONSTRAINT openid4vp_transactions_state_hash_key UNIQUE (state_hash);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.controller_identity_approvals
    ADD CONSTRAINT pk_controller_identity_approvals PRIMARY KEY (approval_id);

ALTER TABLE ONLY public.controller_recovery_challenges
    ADD CONSTRAINT pk_controller_recovery_challenges PRIMARY KEY (challenge_id);

ALTER TABLE ONLY public.controller_recovery_root_key_history
    ADD CONSTRAINT pk_controller_recovery_root_key_history PRIMARY KEY (deployment_id, recovery_public_key);

ALTER TABLE ONLY public.controller_recovery_roots
    ADD CONSTRAINT pk_controller_recovery_roots PRIMARY KEY (deployment_id);

ALTER TABLE ONLY public.controller_registry_slots
    ADD CONSTRAINT pk_controller_registry_slots PRIMARY KEY (deployment_id, controller_id);

ALTER TABLE ONLY public.oauth_refresh_contracts
    ADD CONSTRAINT pk_oauth_refresh_contracts PRIMARY KEY (tenant_id, contract_blake3);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT pk_oauth_refresh_families PRIMARY KEY (tenant_id, token_family_id);

ALTER TABLE ONLY public.oauth_refresh_spent_tokens
    ADD CONSTRAINT pk_oauth_refresh_spent_tokens PRIMARY KEY (tenant_id, refresh_token_blake3);

ALTER TABLE ONLY public.realms
    ADD CONSTRAINT realms_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.recovery_invalidations
    ADD CONSTRAINT recovery_invalidations_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY public.runtime_module_desired_states
    ADD CONSTRAINT runtime_module_desired_states_pkey PRIMARY KEY (tenant_id, module_id);

ALTER TABLE ONLY public.runtime_module_instance_states
    ADD CONSTRAINT runtime_module_instance_states_pkey PRIMARY KEY (tenant_id, instance_id, module_id);

ALTER TABLE ONLY public.runtime_module_state_events
    ADD CONSTRAINT runtime_module_state_events_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY public.scim_audit_events
    ADD CONSTRAINT scim_audit_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scim_security_event_receipts
    ADD CONSTRAINT scim_security_event_receipts_pkey PRIMARY KEY (event_id, scim_token_id);

ALTER TABLE ONLY public.scim_security_events
    ADD CONSTRAINT scim_security_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.security_audit_chain_entries
    ADD CONSTRAINT security_audit_chain_entries_event_hash_key UNIQUE (event_hash);

ALTER TABLE ONLY public.security_audit_chain_entries
    ADD CONSTRAINT security_audit_chain_entries_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY public.security_audit_chain_entries
    ADD CONSTRAINT security_audit_chain_entries_sequence_key UNIQUE (sequence);

ALTER TABLE ONLY public.security_audit_chain_state
    ADD CONSTRAINT security_audit_chain_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.security_audit_events
    ADD CONSTRAINT security_audit_events_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY public.tenant_directory_control_operations
    ADD CONSTRAINT tenant_directory_control_operations_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY public.tenant_resource_bindings
    ADD CONSTRAINT tenant_resource_bindings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.tenant_resource_control_operations
    ADD CONSTRAINT tenant_resource_control_operations_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY public.tenant_resource_states
    ADD CONSTRAINT tenant_resource_states_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT tenant_runtime_bindings_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.tenant_runtime_directory_state
    ADD CONSTRAINT tenant_runtime_directory_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.tenant_signing_keysets
    ADD CONSTRAINT tenant_signing_keysets_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.controller_recovery_challenges
    ADD CONSTRAINT uq_controller_recovery_challenges_allocation_nonce UNIQUE (deployment_id, allocation_nonce);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT uq_mtls_trust_anchor_request_tenant UNIQUE (id, tenant_id);

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT uq_oauth_clients_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE ONLY public.openid4vc_trust_policy_clients
    ADD CONSTRAINT uq_openid4vc_trust_policy_client_history UNIQUE (policy_id, oauth_client_id);

ALTER TABLE ONLY public.openid4vc_trust_policies
    ADD CONSTRAINT uq_openid4vc_trust_policy_tenant_binding UNIQUE (tenant_id, id);

ALTER TABLE ONLY public.openid4vci_issuance_responses
    ADD CONSTRAINT uq_openid4vci_issuance_response_request UNIQUE (token_id, request_digest);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT uq_organizations_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE ONLY public.realms
    ADD CONSTRAINT uq_realms_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE ONLY public.recovery_invalidations
    ADD CONSTRAINT uq_recovery_invalidations_tenant_epoch UNIQUE (tenant_id, state_epoch);

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT uq_scim_tokens_token_hash UNIQUE (token_hash);

ALTER TABLE ONLY public.tenant_resource_bindings
    ADD CONSTRAINT uq_tenant_resource_binding_identity UNIQUE (tenant_id, resource_kind, resource_id);

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT uq_tenant_runtime_binding_host UNIQUE (external_host);

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT uq_tenant_runtime_binding_issuer UNIQUE (issuer);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT uq_user_client_grants_tenant_user_client UNIQUE (tenant_id, user_id, client_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uq_users_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT user_client_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_mfa_backup_codes
    ADD CONSTRAINT user_mfa_backup_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_mfa_remembered_devices
    ADD CONSTRAINT user_mfa_remembered_devices_pkey PRIMARY KEY (tenant_id, token_hash);

ALTER TABLE ONLY public.user_passkey_credentials
    ADD CONSTRAINT user_passkey_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_totp_credentials
    ADD CONSTRAINT user_totp_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT ux_mtls_trust_anchor_client_certificate UNIQUE (tenant_id, client_id, certificate_sha256);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT ux_oauth_refresh_families_current_digest UNIQUE (tenant_id, current_token_blake3);

CREATE UNIQUE INDEX idx_authorization_decision_par ON public.security_audit_events USING btree (authorization_tenant_id, authorization_par_uri) WHERE (((event_type)::text = 'authorization_decision_committed'::text) AND (authorization_par_uri IS NOT NULL));

CREATE INDEX idx_authorization_decision_reclaim ON public.security_audit_events USING btree (business_retain_until, event_id) WHERE (((event_type)::text = 'authorization_decision_committed'::text) AND (exported_at IS NOT NULL));

CREATE UNIQUE INDEX idx_authorization_decision_request ON public.security_audit_events USING btree (authorization_tenant_id, authorization_request_id) WHERE ((event_type)::text = 'authorization_decision_committed'::text);

CREATE INDEX idx_backchannel_logout_deliveries_client ON public.backchannel_logout_deliveries USING btree (tenant_id, client_id, created_at);

CREATE INDEX idx_backchannel_logout_deliveries_due ON public.backchannel_logout_deliveries USING btree (next_attempt_at, created_at) WHERE ((delivered_at IS NULL) AND (failed_at IS NULL));

CREATE INDEX idx_identity_security_events_actor_time ON public.identity_security_events USING btree (actor_id, occurred_at DESC) WHERE (actor_id IS NOT NULL);

CREATE INDEX idx_identity_security_events_target_time ON public.identity_security_events USING btree (target_user_id, occurred_at DESC) WHERE (target_user_id IS NOT NULL);

CREATE INDEX idx_identity_security_events_tenant_time ON public.identity_security_events USING btree (tenant_id, occurred_at DESC);

CREATE INDEX idx_oauth_refresh_families_contract ON public.oauth_refresh_families USING btree (tenant_id, contract_blake3);

CREATE INDEX idx_runtime_module_desired_states_updated_at ON public.runtime_module_desired_states USING btree (updated_at DESC);

CREATE INDEX idx_runtime_module_instance_states_module_state ON public.runtime_module_instance_states USING btree (tenant_id, module_id, actual_state);

CREATE INDEX idx_runtime_module_instance_states_updated_at ON public.runtime_module_instance_states USING btree (updated_at DESC);

CREATE INDEX idx_runtime_module_state_events_actor_time ON public.runtime_module_state_events USING btree (tenant_id, actor_id, occurred_at DESC) WHERE (actor_id IS NOT NULL);

CREATE INDEX idx_runtime_module_state_events_module_time ON public.runtime_module_state_events USING btree (tenant_id, module_id, occurred_at DESC, event_id DESC);

CREATE INDEX idx_runtime_module_state_events_occurred_at ON public.runtime_module_state_events USING btree (tenant_id, occurred_at DESC, event_id DESC);

CREATE INDEX idx_security_audit_events_pending_order ON public.security_audit_events USING btree (occurred_at, event_id) WHERE (exported_at IS NULL);

CREATE INDEX ix_access_token_revocations_expires_at ON public.access_token_revocations USING btree (expires_at);

CREATE INDEX ix_access_token_revocations_tenant_id ON public.access_token_revocations USING btree (tenant_id);

CREATE INDEX ix_client_access_requests_created_at ON public.client_access_requests USING btree (created_at DESC);

CREATE INDEX ix_client_access_requests_status ON public.client_access_requests USING btree (status);

CREATE INDEX ix_client_access_requests_status_created_at ON public.client_access_requests USING btree (status, created_at DESC);

CREATE INDEX ix_client_access_requests_tenant_id ON public.client_access_requests USING btree (tenant_id);

CREATE INDEX ix_client_access_requests_user_created_at ON public.client_access_requests USING btree (user_id, created_at DESC);

CREATE INDEX ix_client_access_requests_user_id ON public.client_access_requests USING btree (user_id);

CREATE INDEX ix_controller_identity_approvals_expiry ON public.controller_identity_approvals USING btree (expires_at, approval_id);

CREATE INDEX ix_external_identity_links_tenant_user ON public.external_identity_links USING btree (tenant_id, user_id);

CREATE INDEX ix_mtls_trust_anchor_active_bundle ON public.oauth_client_mtls_trust_anchor_requests USING btree (tenant_id, certificate_sha256) WHERE (status = 1);

CREATE INDEX ix_mtls_trust_anchor_events_request_created ON public.oauth_client_mtls_trust_anchor_events USING btree (tenant_id, request_id, created_at, id);

CREATE INDEX ix_mtls_trust_anchor_requester_created ON public.oauth_client_mtls_trust_anchor_requests USING btree (tenant_id, user_id, created_at DESC);

CREATE INDEX ix_mtls_trust_anchor_status_created ON public.oauth_client_mtls_trust_anchor_requests USING btree (tenant_id, status, created_at DESC);

CREATE INDEX ix_oauth_clients_created_at_desc ON public.oauth_clients USING btree (created_at DESC);

CREATE INDEX ix_oauth_clients_tenant_id ON public.oauth_clients USING btree (tenant_id);

CREATE INDEX ix_oauth_refresh_contract_scan ON public.oauth_refresh_contracts USING btree (created_at, tenant_id, contract_blake3);

CREATE INDEX ix_oauth_token_issuances_tenant_user ON public.oauth_token_issuances USING btree (tenant_id, user_id) WHERE (user_id IS NOT NULL);

CREATE INDEX ix_openid4vc_trust_policies_resource_history ON public.openid4vc_trust_policies USING btree (tenant_id, resource_id, resource_digest, created_at DESC);

CREATE INDEX ix_openid4vc_trust_policies_tenant_active ON public.openid4vc_trust_policies USING btree (tenant_id, active, updated_at DESC);

CREATE INDEX ix_openid4vc_trust_policy_clients_policy ON public.openid4vc_trust_policy_clients USING btree (tenant_id, policy_id, active);

CREATE INDEX ix_openid4vci_access_expiry_scan ON public.openid4vci_access_grants USING btree (expires_at, token_id);

CREATE INDEX ix_openid4vci_credential_dataset_events_actor ON public.openid4vci_credential_dataset_events USING btree (tenant_id, actor_user_id, created_at DESC);

CREATE INDEX ix_openid4vci_credential_dataset_events_subject ON public.openid4vci_credential_dataset_events USING btree (tenant_id, subject_id, credential_configuration_id, created_at DESC);

CREATE INDEX ix_openid4vci_credential_datasets_validity ON public.openid4vci_credential_datasets USING btree (tenant_id, subject_id, valid_until);

CREATE INDEX ix_openid4vci_deferred_claim_expiry ON public.openid4vci_deferred_transactions USING btree (claim_expires_at) WHERE (claim_id IS NOT NULL);

CREATE INDEX ix_openid4vci_deferred_expiry ON public.openid4vci_deferred_transactions USING btree (expires_at);

CREATE INDEX ix_openid4vci_deferred_token ON public.openid4vci_deferred_transactions USING btree (token_id);

CREATE INDEX ix_openid4vci_issuance_response_expiry ON public.openid4vci_issuance_responses USING btree (expires_at);

CREATE INDEX ix_openid4vci_nonce_claim_expiry ON public.openid4vci_nonces USING btree (claim_expires_at) WHERE (claim_id IS NOT NULL);

CREATE INDEX ix_openid4vci_nonce_expiry ON public.openid4vci_nonces USING btree (expires_at);

CREATE INDEX ix_openid4vci_notification_expiry ON public.openid4vci_notifications USING btree (expires_at);

CREATE INDEX ix_openid4vci_notification_token ON public.openid4vci_notifications USING btree (token_id);

CREATE INDEX ix_openid4vci_offer_expiry ON public.openid4vci_offers USING btree (expires_at);

CREATE INDEX ix_openid4vp_transaction_expiry ON public.openid4vp_transactions USING btree (expires_at);

CREATE INDEX ix_openid4vp_transactions_openid4vc_trust_policy ON public.openid4vp_transactions USING btree (tenant_id, openid4vc_trust_policy_binding_id) WHERE (openid4vc_trust_policy_binding_id IS NOT NULL);

CREATE INDEX ix_orf_client_active ON public.oauth_refresh_families USING btree (tenant_id, client_id) WHERE (revoked_at IS NULL);

CREATE INDEX ix_orf_expires ON public.oauth_refresh_families USING btree (current_expires_at);

CREATE INDEX ix_orf_revoked_cleanup ON public.oauth_refresh_families USING btree (revoked_at, tenant_id, token_family_id) WHERE (revoked_at IS NOT NULL);

CREATE INDEX ix_orf_scope_active ON public.oauth_refresh_families USING btree (tenant_id, user_id, client_id, current_issued_at, token_family_id) WHERE (revoked_at IS NULL);

CREATE INDEX ix_organizations_tenant_id ON public.organizations USING btree (tenant_id);

CREATE INDEX ix_orst_expires ON public.oauth_refresh_spent_tokens USING btree (expires_at);

CREATE INDEX ix_orst_family ON public.oauth_refresh_spent_tokens USING btree (tenant_id, token_family_id);

CREATE INDEX ix_realms_tenant_id ON public.realms USING btree (tenant_id);

CREATE INDEX ix_scim_audit_events_tenant_time ON public.scim_audit_events USING btree (tenant_id, created_at DESC);

CREATE INDEX ix_scim_audit_events_token_time ON public.scim_audit_events USING btree (scim_token_id, created_at DESC);

CREATE INDEX ix_scim_security_events_expiry ON public.scim_security_events USING btree (expires_at);

CREATE INDEX ix_scim_security_events_tenant_poll ON public.scim_security_events USING btree (tenant_id, occurred_at, id);

CREATE INDEX ix_scim_tokens_expires_at ON public.scim_tokens USING btree (expires_at) WHERE (expires_at IS NOT NULL);

CREATE INDEX ix_scim_tokens_tenant_active ON public.scim_tokens USING btree (tenant_id) WHERE (revoked_at IS NULL);

CREATE INDEX ix_tenant_resource_bindings_tenant_kind ON public.tenant_resource_bindings USING btree (tenant_id, resource_kind, active, updated_at DESC);

CREATE INDEX ix_user_client_grants_last_authorized_at ON public.user_client_grants USING btree (last_authorized_at);

CREATE INDEX ix_user_client_grants_tenant_id ON public.user_client_grants USING btree (tenant_id);

CREATE INDEX ix_user_client_grants_user_id ON public.user_client_grants USING btree (user_id);

CREATE INDEX ix_user_client_grants_user_last_authorized ON public.user_client_grants USING btree (user_id, last_authorized_at DESC);

CREATE INDEX ix_user_mfa_backup_codes_tenant_user_active ON public.user_mfa_backup_codes USING btree (tenant_id, user_id);

CREATE INDEX ix_user_mfa_remembered_devices_expiry ON public.user_mfa_remembered_devices USING btree (expires_at);

CREATE INDEX ix_user_mfa_remembered_devices_tenant_user_active ON public.user_mfa_remembered_devices USING btree (tenant_id, user_id, expires_at);

CREATE INDEX ix_user_passkey_credentials_tenant_user ON public.user_passkey_credentials USING btree (tenant_id, user_id);

CREATE INDEX ix_user_totp_credentials_user ON public.user_totp_credentials USING btree (user_id);

CREATE INDEX ix_users_created_at_desc ON public.users USING btree (created_at DESC);

CREATE INDEX ix_users_tenant_created_at_id ON public.users USING btree (tenant_id, created_at, id);

CREATE INDEX ix_users_tenant_id ON public.users USING btree (tenant_id);

CREATE INDEX oauth_subject_bindings_owner_idx ON public.oauth_subject_bindings USING btree (user_id, tenant_id);

CREATE INDEX oauth_token_issuances_retention_idx ON public.oauth_token_issuances USING btree (retain_until, issuance_id);

CREATE UNIQUE INDEX oauth_token_issuances_single_use_key_idx ON public.oauth_token_issuances USING btree (client_id, single_use_key_blake3) WHERE (single_use_key_blake3 IS NOT NULL);

CREATE UNIQUE INDEX oauth_token_issuances_tenant_jti_idx ON public.oauth_token_issuances USING btree (tenant_id, access_token_jti);

CREATE UNIQUE INDEX uq_admin_provision_receipts_user ON public.admin_provision_receipts USING btree (user_id);

CREATE UNIQUE INDEX uq_backchannel_logout_operation_client ON public.backchannel_logout_deliveries USING btree (tenant_id, operation_key, client_id) WHERE (operation_key IS NOT NULL);

CREATE UNIQUE INDEX uq_identity_security_event_admin_provision_request ON public.identity_security_events USING btree (request_id) WHERE ((event_type)::text = 'admin_user_created'::text);

CREATE UNIQUE INDEX uq_identity_security_event_bootstrap_request ON public.identity_security_events USING btree (request_id) WHERE ((event_type)::text = 'initial_admin_bootstrap'::text);

CREATE UNIQUE INDEX uq_oauth_clients_tenant_internal_id ON public.oauth_clients USING btree (tenant_id, id);

CREATE UNIQUE INDEX uq_oauth_clients_tenant_internal_public_id ON public.oauth_clients USING btree (tenant_id, id, client_id);

CREATE UNIQUE INDEX uq_openid4vc_trust_policy_active ON public.openid4vc_trust_policies USING btree (tenant_id, resource_id) WHERE active;

CREATE UNIQUE INDEX uq_openid4vc_trust_policy_client_active ON public.openid4vc_trust_policy_clients USING btree (tenant_id, oauth_client_id) WHERE active;

CREATE UNIQUE INDEX ux_client_access_requests_tenant_user_pending ON public.client_access_requests USING btree (tenant_id, user_id) WHERE (status = 0);

CREATE UNIQUE INDEX ux_controller_identity_approvals_token_hash ON public.controller_identity_approvals USING btree (token_hash);

CREATE UNIQUE INDEX ux_controller_recovery_challenges_pending_per_deployment ON public.controller_recovery_challenges USING btree (deployment_id) WHERE (consumed_at IS NULL);

CREATE UNIQUE INDEX ux_controller_registry_slots_active_slot_index ON public.controller_registry_slots USING btree (deployment_id, slot_index) WHERE ((status)::text = 'active'::text);

CREATE UNIQUE INDEX ux_controller_registry_slots_deployment_kid ON public.controller_registry_slots USING btree (deployment_id, kid);

CREATE UNIQUE INDEX ux_external_identity_links_tenant_provider_subject ON public.external_identity_links USING btree (tenant_id, provider_type, provider_id, subject);

CREATE UNIQUE INDEX ux_oauth_clients_registration_access_token_blake3 ON public.oauth_clients USING btree (registration_access_token_blake3) WHERE (registration_access_token_blake3 IS NOT NULL);

CREATE UNIQUE INDEX ux_oauth_clients_tenant_client_id ON public.oauth_clients USING btree (tenant_id, client_id);

CREATE UNIQUE INDEX ux_openid4vci_offer_issuer_state_hash ON public.openid4vci_offers USING btree (issuer_state_hash) WHERE (issuer_state_hash IS NOT NULL);

CREATE UNIQUE INDEX ux_openid4vci_offer_pre_authorized_code_hash ON public.openid4vci_offers USING btree (pre_authorized_code_hash) WHERE (pre_authorized_code_hash IS NOT NULL);

CREATE UNIQUE INDEX ux_openid4vp_create_request_jti ON public.openid4vp_transactions USING btree (tenant_id, create_request_jti);

CREATE UNIQUE INDEX ux_organizations_tenant_slug_lower ON public.organizations USING btree (tenant_id, lower((slug)::text));

CREATE UNIQUE INDEX ux_realms_tenant_slug_lower ON public.realms USING btree (tenant_id, lower((slug)::text));

CREATE UNIQUE INDEX ux_tenants_slug_lower ON public.tenants USING btree (lower((slug)::text));

CREATE UNIQUE INDEX ux_user_passkey_credentials_tenant_credential ON public.user_passkey_credentials USING btree (tenant_id, credential_id);

CREATE UNIQUE INDEX ux_user_totp_credentials_tenant_user ON public.user_totp_credentials USING btree (tenant_id, user_id);

CREATE UNIQUE INDEX ux_users_tenant_email ON public.users USING btree (tenant_id, email);

CREATE UNIQUE INDEX ux_users_tenant_email_lower ON public.users USING btree (tenant_id, lower((email)::text));

CREATE UNIQUE INDEX ux_users_tenant_username ON public.users USING btree (tenant_id, username);

ALTER TABLE ONLY public.access_token_revocations
    ADD CONSTRAINT access_token_revocations_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);

ALTER TABLE ONLY public.admin_provision_receipts
    ADD CONSTRAINT admin_provision_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.admin_provision_receipts
    ADD CONSTRAINT admin_provision_receipts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT client_access_requests_approved_client_id_fkey FOREIGN KEY (approved_client_id) REFERENCES public.oauth_clients(id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT client_access_requests_resolved_by_user_id_fkey FOREIGN KEY (resolved_by_user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT client_access_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.access_token_revocations
    ADD CONSTRAINT fk_access_token_revocations_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.access_token_revocations
    ADD CONSTRAINT fk_access_token_revocations_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.backchannel_logout_deliveries
    ADD CONSTRAINT fk_backchannel_logout_delivery_client_tenant FOREIGN KEY (tenant_id, client_id, client_public_id) REFERENCES public.oauth_clients(tenant_id, id, client_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT fk_client_access_requests_client_tenant FOREIGN KEY (approved_client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT fk_client_access_requests_resolver_tenant FOREIGN KEY (resolved_by_user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT fk_client_access_requests_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.client_access_requests
    ADD CONSTRAINT fk_client_access_requests_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.controller_recovery_challenges
    ADD CONSTRAINT fk_controller_recovery_challenges_recovered_slot FOREIGN KEY (deployment_id, recovered_controller_id) REFERENCES public.controller_registry_slots(deployment_id, controller_id);

ALTER TABLE ONLY public.controller_recovery_challenges
    ADD CONSTRAINT fk_controller_recovery_challenges_root FOREIGN KEY (deployment_id) REFERENCES public.controller_recovery_roots(deployment_id);

ALTER TABLE ONLY public.controller_recovery_root_key_history
    ADD CONSTRAINT fk_controller_recovery_root_key_history_deployment FOREIGN KEY (deployment_id) REFERENCES public.controller_recovery_roots(deployment_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.external_identity_links
    ADD CONSTRAINT fk_external_identity_links_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT fk_mtls_trust_anchor_client FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_events
    ADD CONSTRAINT fk_mtls_trust_anchor_event_actor FOREIGN KEY (actor_user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_events
    ADD CONSTRAINT fk_mtls_trust_anchor_event_request FOREIGN KEY (request_id, tenant_id) REFERENCES public.oauth_client_mtls_trust_anchor_requests(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT fk_mtls_trust_anchor_requester FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT fk_mtls_trust_anchor_resolver FOREIGN KEY (resolved_by_user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT fk_mtls_trust_anchor_revoker FOREIGN KEY (revoked_by_user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT fk_mtls_trust_anchor_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT fk_oauth_clients_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES public.organizations(id, tenant_id);

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT fk_oauth_clients_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES public.realms(id, tenant_id);

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT fk_oauth_clients_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_token_issuances
    ADD CONSTRAINT fk_oauth_token_issuances_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.oauth_token_issuances
    ADD CONSTRAINT fk_oauth_token_issuances_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.openid4vc_trust_policy_clients
    ADD CONSTRAINT fk_openid4vc_trust_policy_client_oauth_client FOREIGN KEY (tenant_id, oauth_client_id) REFERENCES public.oauth_clients(tenant_id, id);

ALTER TABLE ONLY public.openid4vc_trust_policy_clients
    ADD CONSTRAINT fk_openid4vc_trust_policy_client_policy FOREIGN KEY (tenant_id, policy_id) REFERENCES public.openid4vc_trust_policies(tenant_id, id);

ALTER TABLE ONLY public.openid4vci_credential_dataset_events
    ADD CONSTRAINT fk_openid4vci_dataset_event_actor_tenant FOREIGN KEY (actor_user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.openid4vci_credential_dataset_events
    ADD CONSTRAINT fk_openid4vci_dataset_event_subject_tenant FOREIGN KEY (subject_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_credential_datasets
    ADD CONSTRAINT fk_openid4vci_dataset_subject_tenant FOREIGN KEY (subject_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vp_transactions
    ADD CONSTRAINT fk_openid4vp_transactions_openid4vc_trust_policy FOREIGN KEY (tenant_id, openid4vc_trust_policy_binding_id) REFERENCES public.openid4vc_trust_policies(tenant_id, id);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT fk_orf_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT fk_orf_contract FOREIGN KEY (tenant_id, contract_blake3) REFERENCES public.oauth_refresh_contracts(tenant_id, contract_blake3);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT fk_orf_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.oauth_refresh_spent_tokens
    ADD CONSTRAINT fk_orst_family FOREIGN KEY (tenant_id, token_family_id) REFERENCES public.oauth_refresh_families(tenant_id, token_family_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.runtime_module_desired_states
    ADD CONSTRAINT fk_runtime_module_desired_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.runtime_module_state_events
    ADD CONSTRAINT fk_runtime_module_event_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.runtime_module_instance_states
    ADD CONSTRAINT fk_runtime_module_instance_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT fk_tenant_runtime_binding_organization FOREIGN KEY (organization_id, tenant_id) REFERENCES public.organizations(id, tenant_id);

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT fk_tenant_runtime_binding_realm FOREIGN KEY (realm_id, tenant_id) REFERENCES public.realms(id, tenant_id);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT fk_user_client_grants_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT fk_user_client_grants_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT fk_user_client_grants_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id);

ALTER TABLE ONLY public.user_mfa_backup_codes
    ADD CONSTRAINT fk_user_mfa_backup_codes_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_mfa_remembered_devices
    ADD CONSTRAINT fk_user_mfa_remembered_devices_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_passkey_credentials
    ADD CONSTRAINT fk_user_passkey_credentials_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_totp_credentials
    ADD CONSTRAINT fk_user_totp_credentials_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.users
    ADD CONSTRAINT fk_users_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES public.organizations(id, tenant_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT fk_users_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES public.realms(id, tenant_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.identity_security_events
    ADD CONSTRAINT identity_security_events_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.identity_security_events
    ADD CONSTRAINT identity_security_events_target_user_id_fkey FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.identity_security_events
    ADD CONSTRAINT identity_security_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.oauth_refresh_contracts
    ADD CONSTRAINT oauth_refresh_contracts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_refresh_families
    ADD CONSTRAINT oauth_refresh_families_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_subject_bindings
    ADD CONSTRAINT oauth_subject_bindings_user_id_tenant_id_fkey FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_token_issuances
    ADD CONSTRAINT oauth_token_issuances_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.openid4vc_trust_policies
    ADD CONSTRAINT openid4vc_trust_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.openid4vci_access_grants
    ADD CONSTRAINT openid4vci_access_grants_subject_id_fkey FOREIGN KEY (subject_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_access_grants
    ADD CONSTRAINT openid4vci_access_grants_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_credential_dataset_events
    ADD CONSTRAINT openid4vci_credential_dataset_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_credential_datasets
    ADD CONSTRAINT openid4vci_credential_datasets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_deferred_transactions
    ADD CONSTRAINT openid4vci_deferred_transactions_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.openid4vci_access_grants(token_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_issuance_responses
    ADD CONSTRAINT openid4vci_issuance_responses_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.openid4vci_access_grants(token_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_notifications
    ADD CONSTRAINT openid4vci_notifications_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.openid4vci_access_grants(token_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_offers
    ADD CONSTRAINT openid4vci_offers_subject_id_fkey FOREIGN KEY (subject_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vci_offers
    ADD CONSTRAINT openid4vci_offers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.openid4vp_transactions
    ADD CONSTRAINT openid4vp_transactions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.realms
    ADD CONSTRAINT realms_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.recovery_invalidations
    ADD CONSTRAINT recovery_invalidations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.runtime_module_desired_states
    ADD CONSTRAINT runtime_module_desired_states_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.runtime_module_state_events
    ADD CONSTRAINT runtime_module_state_events_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.scim_audit_events
    ADD CONSTRAINT scim_audit_events_scim_token_id_fkey FOREIGN KEY (scim_token_id) REFERENCES public.scim_tokens(id);

ALTER TABLE ONLY public.scim_audit_events
    ADD CONSTRAINT scim_audit_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.scim_security_event_receipts
    ADD CONSTRAINT scim_security_event_receipts_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.scim_security_events(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.scim_security_event_receipts
    ADD CONSTRAINT scim_security_event_receipts_scim_token_id_fkey FOREIGN KEY (scim_token_id) REFERENCES public.scim_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.scim_security_events
    ADD CONSTRAINT scim_security_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.security_audit_chain_entries
    ADD CONSTRAINT security_audit_chain_entries_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.security_audit_events(event_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.tenant_directory_control_operations
    ADD CONSTRAINT tenant_directory_control_operations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.tenant_resource_bindings
    ADD CONSTRAINT tenant_resource_bindings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.tenant_resource_control_operations
    ADD CONSTRAINT tenant_resource_control_operations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.tenant_resource_states
    ADD CONSTRAINT tenant_resource_states_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.tenant_runtime_bindings
    ADD CONSTRAINT tenant_runtime_bindings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.tenant_signing_keysets
    ADD CONSTRAINT tenant_signing_keysets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT user_client_grants_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);

ALTER TABLE ONLY public.user_client_grants
    ADD CONSTRAINT user_client_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

-- Initial facts are generated at installation, before directory-change triggers exist.
INSERT INTO public.tenants (id, slug, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default tenant', 'active');
INSERT INTO public.realms (id, tenant_id, slug, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'default', 'Default realm', 'active');
INSERT INTO public.organizations (id, tenant_id, slug, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', 'default', 'Default organization', 'active');

WITH modules(module_id, desired_mode) AS (
    VALUES
        ('device_authorization', 'enabled'), ('token_exchange', 'enabled'),
        ('jwt_bearer_grant', 'enabled'), ('ciba', 'enabled'),
        ('request_objects', 'enabled'), ('jarm', 'enabled'), ('scim', 'enabled'),
        ('frontchannel_logout', 'enabled'), ('session_management', 'enabled'),
        ('dynamic_client_registration', 'disabled'), ('authorization_details', 'disabled'),
        ('http_message_signatures', 'disabled'), ('scim_security_events', 'disabled'),
        ('openid4vci_issuer', 'disabled'), ('openid4vp_verifier', 'disabled'), ('native_sso', 'disabled')
), inserted AS (
    INSERT INTO public.runtime_module_desired_states
        (tenant_id, module_id, desired_mode, revision, reason)
    SELECT '00000000-0000-0000-0000-000000000001', module_id, desired_mode, 1, 'clean install baseline'
    FROM modules
    RETURNING tenant_id, module_id, desired_mode, revision, reason, updated_at
)
INSERT INTO public.runtime_module_state_events
    (event_id, tenant_id, module_id, event_type, revision, reason, after_state, occurred_at)
SELECT uuidv7(), tenant_id, module_id, 'desired_state_changed', revision, reason, desired_mode, updated_at
FROM inserted;

INSERT INTO public.tenant_runtime_directory_state (singleton, revision) VALUES (TRUE, 0);
INSERT INTO public.security_audit_chain_state (singleton, last_sequence, last_hash)
VALUES (TRUE, 0, decode(repeat('00', 32), 'hex'));

CREATE TRIGGER oauth_client_access_token_epoch BEFORE UPDATE OF is_active ON public.oauth_clients FOR EACH ROW EXECUTE FUNCTION public.nazo_advance_access_token_epoch();

CREATE TRIGGER oauth_client_public_refresh_invalidation AFTER UPDATE OF client_type ON public.oauth_clients FOR EACH ROW WHEN ((((old.client_type)::text = 'confidential'::text) AND ((new.client_type)::text = 'public'::text))) EXECUTE FUNCTION public.nazo_revoke_refresh_on_client_public();

CREATE TRIGGER security_audit_chain_entries_append_only BEFORE DELETE OR UPDATE ON public.security_audit_chain_entries FOR EACH ROW EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER security_audit_chain_entries_no_truncate BEFORE TRUNCATE ON public.security_audit_chain_entries FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER security_audit_events_append_only BEFORE DELETE OR UPDATE ON public.security_audit_events FOR EACH ROW EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER security_audit_events_no_truncate BEFORE TRUNCATE ON public.security_audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER trg_mtls_trust_event_actor BEFORE INSERT OR UPDATE ON public.oauth_client_mtls_trust_anchor_events FOR EACH ROW EXECUTE FUNCTION public.nazo_oauth_validate_mtls_trust_event_actor();

CREATE TRIGGER trg_oauth_clients_active_tenant_resource_owner BEFORE DELETE OR UPDATE ON public.oauth_clients FOR EACH ROW EXECUTE FUNCTION public.nazo_guard_active_tenant_resource_owner();

CREATE TRIGGER trg_openid4vc_trust_policy_client_generation BEFORE UPDATE ON public.openid4vc_trust_policy_clients FOR EACH ROW EXECUTE FUNCTION public.nazo_guard_openid4vc_trust_policy_client_generation();

CREATE TRIGGER trg_openid4vc_trust_policy_generation BEFORE UPDATE ON public.openid4vc_trust_policies FOR EACH ROW EXECUTE FUNCTION public.nazo_guard_openid4vc_trust_policy_generation();

CREATE TRIGGER trg_openid4vci_dataset_event_actor BEFORE INSERT OR UPDATE ON public.openid4vci_credential_dataset_events FOR EACH ROW EXECUTE FUNCTION public.nazo_oauth_validate_openid4vci_dataset_event_actor();

CREATE TRIGGER trg_openid4vp_transactions_trust_policy_binding BEFORE INSERT OR UPDATE ON public.openid4vp_transactions FOR EACH ROW EXECUTE FUNCTION public.nazo_validate_openid4vp_trust_policy_binding();

CREATE TRIGGER trg_organizations_runtime_status_revision AFTER UPDATE OF status ON public.organizations FOR EACH ROW WHEN (((old.status)::text IS DISTINCT FROM (new.status)::text)) EXECUTE FUNCTION public.nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_realms_runtime_status_revision AFTER UPDATE OF status ON public.realms FOR EACH ROW WHEN (((old.status)::text IS DISTINCT FROM (new.status)::text)) EXECUTE FUNCTION public.nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_recovery_invalidations_append_only BEFORE DELETE OR UPDATE ON public.recovery_invalidations FOR EACH ROW EXECUTE FUNCTION public.nazo_recovery_invalidations_append_only();

CREATE TRIGGER trg_tenant_directory_control_operations_append_only BEFORE DELETE OR UPDATE ON public.tenant_directory_control_operations FOR EACH ROW EXECUTE FUNCTION public.nazo_tenant_directory_control_operations_append_only();

CREATE TRIGGER trg_tenant_resource_control_operations_append_only BEFORE DELETE OR UPDATE ON public.tenant_resource_control_operations FOR EACH ROW EXECUTE FUNCTION public.nazo_tenant_resource_control_operations_append_only();

CREATE TRIGGER trg_tenant_runtime_bindings_revision AFTER INSERT OR DELETE OR UPDATE ON public.tenant_runtime_bindings FOR EACH ROW EXECUTE FUNCTION public.nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_tenant_runtime_bindings_truncate_revision AFTER TRUNCATE ON public.tenant_runtime_bindings FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_tenants_runtime_status_revision AFTER UPDATE OF status ON public.tenants FOR EACH ROW WHEN (((old.status)::text IS DISTINCT FROM (new.status)::text)) EXECUTE FUNCTION public.nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_users_active_tenant_resource_owner BEFORE DELETE OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.nazo_guard_active_tenant_resource_owner();

CREATE TRIGGER user_access_token_epoch BEFORE UPDATE OF is_active ON public.users FOR EACH ROW EXECUTE FUNCTION public.nazo_advance_access_token_epoch();

REVOKE ALL ON FUNCTION public.nazo_ack_security_audit_batch(p_generation bigint, p_first_sequence bigint, p_last_sequence bigint, p_event_count integer, p_last_hash bytea, p_batch_digest bytea, p_deployment_id text) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_bump_tenant_runtime_directory_revision() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_claim_security_audit_pending(p_limit bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_cleanup_authorization_decisions() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(p_tenant_id uuid, p_user_id uuid, p_client_id text, p_request_id text, p_par_uri text, p_valid_until timestamp with time zone, p_retain_until timestamp with time zone, p_decision text, p_event_id uuid, p_occurred_at timestamp with time zone, p_audit_fields jsonb, p_scopes jsonb, p_resources jsonb, p_authorization_details jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_create_refresh_family(p_tenant uuid, p_family uuid, p_client uuid, p_user uuid, p_contract_key bytea, p_contract jsonb, p_member uuid, p_token_digest bytea, p_audience jsonb, p_issued_at timestamp with time zone, p_expires_at timestamp with time zone, p_sid text, p_dpop text, p_mtls text, p_attestation text, p_scope_lock bigint, p_max_families bigint, p_issuance uuid, p_native_source uuid, p_audit_schema text) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_fail_security_audit_batch(p_generation bigint, p_available_at timestamp with time zone, p_last_error text, p_blocked boolean) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_finalize_security_audit_claim(p_previous_sequence bigint, p_previous_hash bytea, p_event_ids uuid[], p_event_hashes bytea[], p_first_sequence bigint, p_last_sequence bigint, p_event_count integer, p_batch_digest bytea, p_lock_timeout_seconds integer) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_lock_token_principals(p_tenant uuid, p_client uuid, p_client_epoch bigint, p_user uuid, p_user_epoch bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id text) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_persist_security_audit_event(p_event_id uuid, p_event_type text, p_event_category text, p_payload jsonb, p_occurred_at timestamp with time zone) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_reclaim_security_audit_batch(p_batch_digest bytea, p_lock_timeout_seconds integer) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_record_security_audit_genesis(p_deployment_id text, p_head_hash bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_reject_security_audit_event_mutation() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_security_audit_batch_members() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_security_audit_chain_head_for_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_security_audit_shared_anchor_health() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_security_audit_shared_privilege_preflight(p_require_least_privilege boolean, p_require_append boolean, p_require_exporter boolean) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_stage_security_audit_chain(p_previous_sequence bigint, p_previous_hash bytea, p_event_ids uuid[], p_event_hashes bytea[]) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_tenant_directory_control_operations_append_only() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.nazo_unblock_security_audit_batch() FROM PUBLIC;

-- These internal/receiver capabilities must not inherit deployment-wide
-- default EXECUTE grants. Provision the exporter and receiver explicitly.
FOR inherited_grant IN
    SELECT proc.oid::regprocedure AS signature, role.rolname
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(proc.proacl) AS acl
    JOIN pg_roles AS role ON role.oid = acl.grantee
    WHERE proc.oid IN (
        'public.nazo_stage_security_audit_chain(bigint,bytea,uuid[],bytea[])'::regprocedure,
        'public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)'::regprocedure,
        'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::regprocedure,
        'public.nazo_record_security_audit_genesis(text,bytea)'::regprocedure
    ) AND acl.grantee <> proc.proowner
LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I CASCADE', inherited_grant.signature, inherited_grant.rolname);
END LOOP;
END
$baseline$;
