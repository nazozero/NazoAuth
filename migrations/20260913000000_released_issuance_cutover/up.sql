-- v0.2.16 already recorded the saga migration version. Rewriting that
-- historical file cannot upgrade its deployed table. Convert the recognized
-- terminal schema before later migrations consume the compact receipt shape.
-- Fresh/source-managed compact schemas need no conversion.
DO $upgrade$
DECLARE
    old_owner TEXT;
    grant_row RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'public.oauth_token_issuances'::regclass
                     AND attname = 'grant_key_blake3' AND NOT attisdropped) THEN
        IF NOT EXISTS (SELECT 1 FROM pg_attribute
                       WHERE attrelid = 'public.oauth_token_issuances'::regclass
                         AND attname = 'single_use_key_blake3' AND NOT attisdropped)
           OR NOT EXISTS (SELECT 1 FROM pg_attribute
                          WHERE attrelid = 'public.oauth_token_issuances'::regclass
                            AND attname = 'retain_until' AND NOT attisdropped) THEN
            RAISE EXCEPTION 'unrecognized token issuance schema';
        END IF;
        RETURN;
    END IF;

    LOCK TABLE public.oauth_token_issuances IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM public.oauth_token_issuances
               WHERE access_token_jti IS NULL OR access_token_expires_at IS NULL
                  OR grant_key_blake3 !~ '^[0-9a-f]{64}$') THEN
        RAISE EXCEPTION 'legacy issuance lacks terminal ownership/replay evidence';
    END IF;
    IF EXISTS (SELECT 1 FROM public.oauth_token_issuances
               WHERE response_ciphertext IS NOT NULL AND expires_at > clock_timestamp()) THEN
        RAISE EXCEPTION 'drain live legacy response receipts before issuance cutover';
    END IF;

    ALTER TABLE public.oauth_token_issuances
        ADD COLUMN single_use_key_blake3 BYTEA,
        ADD COLUMN retain_until TIMESTAMPTZ;
    UPDATE public.oauth_token_issuances
    SET single_use_key_blake3 = decode(grant_key_blake3, 'hex'),
        retain_until = GREATEST(expires_at, access_token_expires_at);
    ALTER TABLE public.oauth_token_issuances
        ALTER COLUMN access_token_jti SET NOT NULL,
        ALTER COLUMN access_token_expires_at SET NOT NULL,
        ALTER COLUMN retain_until SET NOT NULL,
        ADD CONSTRAINT fk_oauth_token_issuances_client_tenant
            FOREIGN KEY (client_id, tenant_id) REFERENCES public.oauth_clients(id, tenant_id),
        ADD CONSTRAINT oauth_token_issuances_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES public.tenants(id),
        ADD CONSTRAINT oauth_token_issuances_single_use_digest_check
            CHECK (single_use_key_blake3 IS NULL OR octet_length(single_use_key_blake3) = 32),
        ADD CONSTRAINT oauth_token_issuances_retention_check
            CHECK (retain_until >= access_token_expires_at),
        DROP COLUMN grant_key_blake3,
        DROP COLUMN request_digest,
        DROP COLUMN response_ciphertext,
        DROP COLUMN response_digest,
        DROP COLUMN response_envelope_version,
        DROP COLUMN response_key_id,
        DROP COLUMN expires_at,
        DROP COLUMN created_at,
        DROP COLUMN updated_at;
    CREATE UNIQUE INDEX oauth_token_issuances_single_use_key_idx
        ON public.oauth_token_issuances (tenant_id, client_id, single_use_key_blake3)
        WHERE single_use_key_blake3 IS NOT NULL;
    CREATE UNIQUE INDEX oauth_token_issuances_tenant_jti_idx
        ON public.oauth_token_issuances (tenant_id, access_token_jti);
    CREATE INDEX oauth_token_issuances_retention_idx
        ON public.oauth_token_issuances (retain_until, issuance_id);
    CREATE INDEX IF NOT EXISTS ix_oauth_tokens_rotated_from_id
        ON public.oauth_tokens (rotated_from_id) WHERE rotated_from_id IS NOT NULL;

    -- Changing OUT-column names changes the return type: replace the exact
    -- zero-argument function and preserve its owner and effective EXECUTE ACL.
    SELECT pg_get_userbyid(proowner) INTO STRICT old_owner FROM pg_proc
    WHERE oid = 'public.nazo_oauth_cleanup_expired_security_state()'::regprocedure;
    CREATE TEMP TABLE nazo_cleanup_cutover_grants ON COMMIT DROP AS
    SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                ELSE pg_get_userbyid(acl.grantee) END AS grantee,
           acl.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
    WHERE proc.oid = 'public.nazo_oauth_cleanup_expired_security_state()'::regprocedure
      AND acl.privilege_type = 'EXECUTE';
    DROP FUNCTION public.nazo_oauth_cleanup_expired_security_state();
    EXECUTE $definition$
CREATE FUNCTION public.nazo_oauth_cleanup_expired_security_state()
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

    $definition$;
    EXECUTE format('ALTER FUNCTION public.nazo_oauth_cleanup_expired_security_state() OWNER TO %I', old_owner);
    REVOKE ALL ON FUNCTION public.nazo_oauth_cleanup_expired_security_state() FROM PUBLIC;
    FOR grant_row IN SELECT * FROM nazo_cleanup_cutover_grants LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_oauth_cleanup_expired_security_state() TO %s%s',
            CASE WHEN grant_row.grantee = 'PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grant_row.grantee) END,
            CASE WHEN grant_row.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$upgrade$;
