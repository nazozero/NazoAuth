-- Stop the old writers and exporters before this schema cut. Events remain
-- immutable; only the exporter assigns the global chain order after commit.
-- Preserve explicit role grants while removing the old writer's chain access.
CREATE TEMP TABLE nazo_audit_upgrade_grants ON COMMIT DROP AS
SELECT role.rolname,
       bool_or(proc.proname = 'nazo_append_security_audit_event') AS writer,
       bool_or(proc.proname = 'nazo_claim_security_audit_events') AS exporter
FROM pg_proc AS proc
JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
JOIN pg_roles AS role ON role.oid = acl.grantee
WHERE namespace.nspname = 'public'
  AND proc.proname IN ('nazo_append_security_audit_event', 'nazo_claim_security_audit_events')
  AND acl.privilege_type = 'EXECUTE' AND acl.grantee <> proc.proowner
GROUP BY role.rolname;

CREATE TABLE public.security_audit_chain_entries (
    event_id UUID PRIMARY KEY REFERENCES public.security_audit_events(event_id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL UNIQUE CHECK (sequence > 0),
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32)
);
INSERT INTO public.security_audit_chain_entries (event_id, sequence, previous_hash, event_hash)
SELECT event_id, sequence, previous_hash, event_hash FROM public.security_audit_events;

CREATE TRIGGER security_audit_chain_entries_append_only
BEFORE UPDATE OR DELETE ON public.security_audit_chain_entries
FOR EACH ROW EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();
CREATE TRIGGER security_audit_chain_entries_no_truncate
BEFORE TRUNCATE ON public.security_audit_chain_entries
FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

DROP FUNCTION public.nazo_append_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA);
DROP FUNCTION public.nazo_claim_security_audit_events(BIGINT, INTEGER);
DROP FUNCTION public.nazo_security_audit_chain_head_for_update();
DROP FUNCTION public.nazo_ack_security_audit_event(UUID, INTEGER);
DROP FUNCTION public.nazo_security_audit_anchor_freshness();
DROP FUNCTION public.nazo_security_audit_anchor_health();
DROP FUNCTION public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN);

ALTER TABLE public.security_audit_events
    DROP COLUMN sequence, DROP COLUMN previous_hash, DROP COLUMN event_hash;
CREATE INDEX idx_security_audit_events_occurred_at
    ON public.security_audit_events (occurred_at, event_id);
CREATE INDEX idx_security_audit_events_type_occurred_at
    ON public.security_audit_events (event_type, occurred_at, event_id);

CREATE FUNCTION public.nazo_persist_security_audit_event(
    p_event_id UUID, p_event_type TEXT, p_event_category TEXT,
    p_payload JSONB, p_occurred_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_inserted INTEGER;
BEGIN
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
    INSERT INTO public.security_audit_event_outbox (event_id) VALUES (p_event_id);
    RETURN TRUE;
END;
$$;

-- The exporter holds this lock only while claiming and chaining a batch.
-- Application transactions never read or lock this row during audit writes.
CREATE FUNCTION public.nazo_security_audit_chain_head_for_update()
RETURNS TABLE(last_sequence BIGINT, last_hash BYTEA)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT state.last_sequence, state.last_hash
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE
$$;

CREATE FUNCTION public.nazo_claim_security_audit_events(p_limit BIGINT, p_lock_timeout_seconds INTEGER)
RETURNS TABLE(
    event_id UUID, attempts INTEGER, sequence BIGINT, event_type TEXT, event_category TEXT,
    payload JSONB, payload_canonical TEXT, occurred_at TIMESTAMPTZ, previous_hash BYTEA, event_hash BYTEA
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256
       OR p_lock_timeout_seconds IS NULL OR p_lock_timeout_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'audit outbox claim bounds are invalid';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE;
    RETURN QUERY
    WITH pending AS MATERIALIZED (
        SELECT outbox.event_id, chain.sequence, outbox.created_at,
               outbox.available_at <= CURRENT_TIMESTAMP AND (
                   outbox.locked_at IS NULL OR outbox.locked_at < CURRENT_TIMESTAMP
                       - (p_lock_timeout_seconds * INTERVAL '1 second')
               ) AS eligible
        FROM public.security_audit_event_outbox AS outbox
        LEFT JOIN public.security_audit_chain_entries AS chain USING (event_id)
        WHERE outbox.exported_at IS NULL
        ORDER BY chain.sequence ASC NULLS LAST, outbox.created_at, outbox.event_id
        LIMIT p_limit
    ), ordered AS (
        SELECT pending.*, bool_and(eligible) OVER (
            ORDER BY pending.sequence ASC NULLS LAST, pending.created_at, pending.event_id
        ) AS eligible_prefix FROM pending
    ), claimed AS (
        UPDATE public.security_audit_event_outbox AS outbox
        SET attempts = outbox.attempts + 1, locked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        FROM ordered WHERE ordered.eligible_prefix AND outbox.event_id = ordered.event_id
        RETURNING outbox.event_id, outbox.attempts, outbox.created_at
    )
    SELECT claimed.event_id, claimed.attempts, chain.sequence,
           event.event_type::TEXT, event.event_category::TEXT, event.payload, event.payload::TEXT,
           event.occurred_at, chain.previous_hash, chain.event_hash
    FROM claimed
    JOIN public.security_audit_events AS event USING (event_id)
    LEFT JOIN public.security_audit_chain_entries AS chain USING (event_id)
    ORDER BY chain.sequence ASC NULLS LAST, claimed.created_at, claimed.event_id;
END;
$$;

-- Rust computes the unchanged BLAKE3 chain over the canonical PostgreSQL JSON.
-- Persist the entire newly chained part of a claim with one database call.
CREATE FUNCTION public.nazo_append_security_audit_chain(
    p_previous_sequence BIGINT, p_previous_hash BYTEA, p_event_ids UUID[], p_event_hashes BYTEA[]
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_sequence BIGINT;
    v_hash BYTEA;
    v_entry RECORD;
BEGIN
    IF p_event_ids IS NULL OR cardinality(p_event_ids) NOT BETWEEN 1 AND 256
       OR p_event_hashes IS NULL OR cardinality(p_event_ids) <> cardinality(p_event_hashes) THEN
        RAISE EXCEPTION 'audit chain batch bounds are invalid';
    END IF;
    SELECT state.last_sequence, state.last_hash INTO STRICT v_sequence, v_hash
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE;
    IF v_sequence IS DISTINCT FROM p_previous_sequence OR v_hash IS DISTINCT FROM p_previous_hash
       OR (v_sequence = 0 AND v_hash <> decode(repeat('00', 32), 'hex'))
       OR (v_sequence > 0 AND NOT EXISTS (
           SELECT 1 FROM public.security_audit_chain_entries AS chain
           WHERE chain.sequence = v_sequence AND chain.event_hash = v_hash
       )) THEN
        RAISE EXCEPTION 'security audit append head is stale or invalid';
    END IF;
    FOR v_entry IN SELECT * FROM unnest(p_event_ids, p_event_hashes) AS item(event_id, event_hash) LOOP
        v_sequence := v_sequence + 1;
        INSERT INTO public.security_audit_chain_entries (event_id, sequence, previous_hash, event_hash)
        VALUES (v_entry.event_id, v_sequence, v_hash, v_entry.event_hash);
        v_hash := v_entry.event_hash;
    END LOOP;
    UPDATE public.security_audit_chain_state SET last_sequence = v_sequence, last_hash = v_hash
    WHERE singleton;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_ack_security_audit_event(
    p_event_id UUID, p_expected_attempts INTEGER, p_deployment_id TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_exported_at TIMESTAMPTZ;
    v_sequence BIGINT;
    v_hash BYTEA;
    v_occurred_at TIMESTAMPTZ;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton AND (state.anchor_deployment_id IS NULL OR state.anchor_deployment_id = p_deployment_id)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    SELECT chain.sequence, chain.event_hash, event.occurred_at
    INTO v_sequence, v_hash, v_occurred_at
    FROM public.security_audit_chain_entries AS chain
    JOIN public.security_audit_events AS event USING (event_id)
    WHERE chain.event_id = p_event_id;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    UPDATE public.security_audit_event_outbox AS outbox
    SET exported_at = CURRENT_TIMESTAMP, locked_at = NULL, updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL AND outbox.exported_at IS NULL
    RETURNING outbox.exported_at INTO v_exported_at;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE public.security_audit_chain_state AS state
    SET anchor_deployment_id = p_deployment_id,
        anchor_sequence = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_sequence ELSE state.anchor_sequence END,
        anchor_hash = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_hash ELSE state.anchor_hash END,
        anchor_occurred_at = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_occurred_at ELSE state.anchor_occurred_at END,
        anchor_accepted_at = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_exported_at ELSE state.anchor_accepted_at END,
        anchor_observed_at = v_exported_at
    WHERE state.singleton;
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_anchor_health()
RETURNS TABLE(
    last_sequence BIGINT, last_hash BYTEA, chain_valid BOOLEAN,
    pending_count BIGINT, oldest_pending_occurred_at TIMESTAMPTZ,
    anchor_deployment_id TEXT, anchor_sequence BIGINT, anchor_hash BYTEA,
    anchor_occurred_at TIMESTAMPTZ, anchor_accepted_at TIMESTAMPTZ, anchor_observed_at TIMESTAMPTZ
) LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH head AS (
        SELECT chain.sequence, chain.event_hash FROM public.security_audit_chain_entries AS chain
        ORDER BY chain.sequence DESC LIMIT 1
    ), backlog AS (
        SELECT COUNT(*)::BIGINT AS pending_count, MIN(event.occurred_at) AS oldest_pending_occurred_at
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS event USING (event_id)
        WHERE outbox.exported_at IS NULL
    )
    SELECT state.last_sequence, state.last_hash,
           (head.sequence IS NULL AND state.last_sequence = 0 AND state.last_hash = decode(repeat('00',32),'hex'))
            OR (head.sequence = state.last_sequence AND head.event_hash = state.last_hash),
           backlog.pending_count, backlog.oldest_pending_occurred_at,
           state.anchor_deployment_id::TEXT, state.anchor_sequence, state.anchor_hash,
           state.anchor_occurred_at, state.anchor_accepted_at, state.anchor_observed_at
    FROM public.security_audit_chain_state AS state
    LEFT JOIN head ON TRUE CROSS JOIN backlog WHERE state.singleton
$$;

CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN, p_require_append BOOLEAN, p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (NOT COALESCE(p_require_append, FALSE) OR has_function_privilege(session_user,
        'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE, 'EXECUTE'))
    AND (NOT COALESCE(p_require_exporter, FALSE) OR (
        has_function_privilege(session_user, 'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_claim_security_audit_events(bigint,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_ack_security_audit_event(uuid,integer,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reschedule_security_audit_event(uuid,integer,timestamptz,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
    ))
    AND (NOT COALESCE(p_require_least_privilege, TRUE) OR (
        NOT EXISTS (SELECT 1 FROM pg_roles AS role WHERE role.rolsuper AND pg_has_role(session_user, role.oid, 'MEMBER'))
        AND NOT EXISTS (
            SELECT 1 FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public' AND relation.relname IN (
                'security_audit_chain_state', 'security_audit_events', 'security_audit_chain_entries', 'security_audit_event_outbox'
            ) AND (
                pg_has_role(session_user, relation.relowner, 'MEMBER')
                OR has_table_privilege(session_user, relation.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
            )
        )
    )) AS policy_satisfied
$$;

REVOKE ALL ON TABLE public.security_audit_chain_entries FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.nazo_persist_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ),
    public.nazo_security_audit_chain_head_for_update(),
    public.nazo_claim_security_audit_events(BIGINT, INTEGER),
    public.nazo_append_security_audit_chain(BIGINT, BYTEA, UUID[], BYTEA[])
FROM PUBLIC;

DO $$
DECLARE v_role RECORD;
BEGIN
    FOR v_role IN SELECT * FROM pg_temp.nazo_audit_upgrade_grants LOOP
        EXECUTE format('REVOKE ALL ON TABLE public.security_audit_chain_entries FROM %I', v_role.rolname);
        IF v_role.writer THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_persist_security_audit_event(UUID,TEXT,TEXT,JSONB,TIMESTAMPTZ) TO %I', v_role.rolname);
        END IF;
        IF v_role.exporter THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_security_audit_chain_head_for_update(), public.nazo_claim_security_audit_events(BIGINT,INTEGER), public.nazo_append_security_audit_chain(BIGINT,BYTEA,UUID[],BYTEA[]) TO %I', v_role.rolname);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON TABLE public.security_audit_events IS 'Immutable event facts, committed atomically with their business mutation and outbox entry.';
COMMENT ON TABLE public.security_audit_chain_entries IS 'Immutable global chain assigned only by the exporter after event commit.';
