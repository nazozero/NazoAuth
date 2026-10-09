-- Keep legacy append/open APIs; fresh claims finalize proof and lease together.
CREATE FUNCTION public.nazo_stage_security_audit_chain(
    p_previous_sequence BIGINT, p_previous_hash BYTEA, p_event_ids UUID[], p_event_hashes BYTEA[]
) RETURNS TABLE(last_sequence BIGINT, last_hash BYTEA)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
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
        PERFORM 1 FROM public.security_audit_events AS event
        WHERE event.event_id = v_entry.event_id AND event.exported_at IS NULL
        FOR SHARE OF event;
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

-- Preserve the legacy append signature, owner, ACL and non-empty contract.
-- Proof validation/insertion has one implementation shared with fresh claim.
CREATE OR REPLACE FUNCTION public.nazo_append_security_audit_chain(
    p_previous_sequence BIGINT, p_previous_hash BYTEA, p_event_ids UUID[], p_event_hashes BYTEA[]
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_head RECORD;
BEGIN
    IF p_event_ids IS NULL OR cardinality(p_event_ids) NOT BETWEEN 1 AND 256
       OR p_event_hashes IS NULL OR cardinality(p_event_ids) <> cardinality(p_event_hashes) THEN
        RAISE EXCEPTION 'audit chain batch bounds are invalid';
    END IF;
    SELECT * INTO STRICT v_head
    FROM public.nazo_stage_security_audit_chain(
        p_previous_sequence, p_previous_hash, p_event_ids, p_event_hashes
    );
    UPDATE public.security_audit_chain_state
    SET last_sequence = v_head.last_sequence, last_hash = v_head.last_hash
    WHERE singleton;
END;
$$;

-- The caller retains the exporter transaction/head lock while choosing the
-- envelope-fitting prefix and computing its canonical hashes/digest in Rust.
-- Empty paired arrays open already-chained leftovers without changing the head.
CREATE FUNCTION public.nazo_finalize_security_audit_claim(
    p_previous_sequence BIGINT, p_previous_hash BYTEA, p_event_ids UUID[], p_event_hashes BYTEA[],
    p_first_sequence BIGINT, p_last_sequence BIGINT, p_event_count INTEGER,
    p_batch_digest BYTEA, p_lock_timeout_seconds INTEGER
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- The proof helper is invoker-only and inaccessible to runtime roles.
-- An existing legacy definer may have a different owner from this migration.
REVOKE ALL ON FUNCTION public.nazo_stage_security_audit_chain(BIGINT, BYTEA, UUID[], BYTEA[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nazo_finalize_security_audit_claim(BIGINT, BYTEA, UUID[], BYTEA[], BIGINT, BIGINT, INTEGER, BYTEA, INTEGER) FROM PUBLIC;
DO $$
DECLARE
    v_owner TEXT;
    v_role RECORD;
    v_grant RECORD;
BEGIN
    -- New functions may inherit non-PUBLIC grants from ALTER DEFAULT
    -- PRIVILEGES. Remove every non-owner initial grant before regranting the
    -- precise capabilities below; old append/open ACLs are never rewritten.
    FOR v_grant IN
        SELECT DISTINCT proc.oid::REGPROCEDURE AS signature, role.rolname
        FROM pg_proc AS proc
        CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
        JOIN pg_roles AS role ON role.oid = acl.grantee
        WHERE proc.oid IN (
            'public.nazo_stage_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE,
            'public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)'::REGPROCEDURE
        ) AND acl.grantee <> proc.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I CASCADE', v_grant.signature, v_grant.rolname);
    END LOOP;
    SELECT role.rolname INTO STRICT v_owner
    FROM pg_proc AS proc JOIN pg_roles AS role ON role.oid = proc.proowner
    WHERE proc.oid = 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE;
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_stage_security_audit_chain(BIGINT,BYTEA,UUID[],BYTEA[]) TO %I', v_owner);
    FOR v_role IN
        SELECT role.rolname FROM pg_roles AS role
        WHERE has_function_privilege(role.oid, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
          AND has_function_privilege(role.oid, 'public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_finalize_security_audit_claim(BIGINT,BYTEA,UUID[],BYTEA[],BIGINT,BIGINT,INTEGER,BYTEA,INTEGER) TO %I', v_role.rolname);
    END LOOP;
END;
$$;

-- Traverse every membership edge before filtering roles the login can assume.
-- Privilege probes on each eligible role also cover its inheritance and PUBLIC.
-- CREATE OR REPLACE preserves the function identity, owner and existing ACL.
CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN, p_require_append BOOLEAN, p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
        AND has_function_privilege(session_user, 'public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reclaim_security_audit_batch(bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
    ))
    AND (NOT COALESCE(p_require_least_privilege, TRUE) OR (
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
