-- A new family and its capacity retirements are one existing transaction
-- transition. Keep the ordered locks and per-retirement Required facts, but
-- execute their dependent statements beside the data instead of across the wire.
CREATE OR REPLACE FUNCTION public.nazo_create_refresh_family(
    p_tenant UUID, p_family UUID, p_client UUID, p_user UUID,
    p_contract_key BYTEA, p_contract JSONB, p_member UUID, p_token_digest BYTEA,
    p_audience JSONB, p_issued_at TIMESTAMPTZ, p_expires_at TIMESTAMPTZ,
    p_sid TEXT, p_dpop TEXT, p_mtls TEXT, p_attestation TEXT,
    p_scope_lock BIGINT, p_max_families BIGINT, p_issuance UUID,
    p_native_source UUID, p_audit_schema TEXT
) RETURNS TABLE(outcome TEXT, retired_source JSONB)
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
-- The previous uncached probes were planned against the current table size.
-- Do not freeze a miss-heavy family probe's empty-table sequential-scan plan.
SET plan_cache_mode = force_custom_plan
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
                gen_random_uuid(), 'refresh_family_capacity_retired', 'token_lifecycle',
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
REVOKE ALL ON FUNCTION public.nazo_create_refresh_family(
    UUID,UUID,UUID,UUID,BYTEA,JSONB,UUID,BYTEA,JSONB,TIMESTAMPTZ,TIMESTAMPTZ,
    TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,UUID,UUID,TEXT
) FROM PUBLIC;
