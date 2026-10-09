-- Restore the pending-identity table exactly as it was: every pending event
-- gets its (event_id, occurred_at) outbox row back, then the pre-cutover
-- function bodies return. No unacknowledged event is lost — the pending set
-- is repopulated from the event table, which is the same set by contract.
CREATE TABLE public.security_audit_event_outbox (
    event_id UUID PRIMARY KEY REFERENCES public.security_audit_events(event_id) ON DELETE RESTRICT,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_security_audit_outbox_order
    ON public.security_audit_event_outbox (occurred_at, event_id);
INSERT INTO public.security_audit_event_outbox (event_id, occurred_at)
    SELECT event_id, occurred_at FROM public.security_audit_events;

ALTER TABLE public.security_audit_events
    SET (autovacuum_vacuum_scale_factor = 0,
         autovacuum_vacuum_threshold = 10000,
         autovacuum_vacuum_cost_delay = 0);
DROP INDEX public.idx_security_audit_events_pending_order;

CREATE OR REPLACE FUNCTION public.nazo_persist_security_audit_event(
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
    INSERT INTO public.security_audit_event_outbox (event_id, occurred_at)
    VALUES (p_event_id, p_occurred_at);
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_security_audit_batch_members()
RETURNS TABLE(
    event_id UUID, sequence BIGINT, event_type TEXT, event_category TEXT,
    payload_canonical TEXT, occurred_at TIMESTAMPTZ,
    previous_hash BYTEA, event_hash BYTEA
)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT event.event_id, chain.sequence, event.event_type::TEXT, event.event_category::TEXT,
           event.payload::TEXT, event.occurred_at,
           chain.previous_hash, chain.event_hash
    FROM public.security_audit_chain_state AS state
    JOIN public.security_audit_chain_entries AS chain
      ON chain.sequence > COALESCE(state.anchor_sequence, 0)
     AND chain.sequence <= state.batch_last_sequence
    JOIN public.security_audit_event_outbox AS outbox ON outbox.event_id = chain.event_id
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
    ORDER BY chain.sequence
$$;

CREATE OR REPLACE FUNCTION public.nazo_claim_security_audit_pending(p_limit BIGINT)
RETURNS TABLE(
    event_id UUID, sequence BIGINT, event_type TEXT, event_category TEXT,
    payload_canonical TEXT, occurred_at TIMESTAMPTZ,
    previous_hash BYTEA, event_hash BYTEA
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET enable_seqscan = off
SET enable_bitmapscan = off
AS $$
DECLARE
    v_claimed INTEGER;
    v_anchor BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'audit outbox claim bounds are invalid';
    END IF;
    SELECT COALESCE(
        (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
         WHERE state.singleton), 0)
    INTO v_anchor;
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
    JOIN public.security_audit_event_outbox AS outbox
        ON outbox.event_id = chained.event_id
    JOIN public.security_audit_events AS event
        ON event.event_id = chained.event_id
    ORDER BY chained.sequence;
    GET DIAGNOSTICS v_claimed = ROW_COUNT;
    IF v_claimed > 0 THEN RETURN; END IF;
    RETURN QUERY
    WITH pending AS MATERIALIZED (
        SELECT outbox.event_id, outbox.occurred_at
        FROM public.security_audit_event_outbox AS outbox
        ORDER BY outbox.occurred_at, outbox.event_id
        LIMIT p_limit
    )
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM pending
    JOIN public.security_audit_events AS event
        ON event.event_id = pending.event_id
    ORDER BY pending.occurred_at, pending.event_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_ack_security_audit_batch(
    p_generation BIGINT, p_first_sequence BIGINT, p_last_sequence BIGINT,
    p_event_count INTEGER, p_last_hash BYTEA, p_batch_digest BYTEA,
    p_deployment_id TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_anchor BIGINT;
    v_members BIGINT;
    v_deleted INTEGER;
    v_ids UUID[];
    v_occurred_at TIMESTAMPTZ;
    v_exported_at TIMESTAMPTZ := CURRENT_TIMESTAMP;
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
    SELECT COUNT(*), COALESCE(array_agg(chain.event_id), '{}'::UUID[]) INTO v_members, v_ids
    FROM public.security_audit_chain_entries AS chain
    JOIN public.security_audit_event_outbox AS outbox ON outbox.event_id = chain.event_id
    WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence;
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
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
    DELETE FROM public.security_audit_event_outbox AS outbox
    WHERE outbox.event_id = ANY(v_ids);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement deleted an unexpected member count';
    END IF;
    DELETE FROM public.security_audit_chain_entries AS chain
    WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement reclaimed an unexpected chain count';
    END IF;
    DELETE FROM public.security_audit_events AS event
    WHERE event.event_id = ANY(v_ids);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
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

CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_anchor_health()
RETURNS TABLE(
    last_sequence BIGINT, last_hash BYTEA, chain_valid BOOLEAN,
    pending_exists BOOLEAN, pending_estimate BIGINT,
    pending_orphan_exists BOOLEAN,
    oldest_pending_occurred_at TIMESTAMPTZ,
    anchor_deployment_id TEXT, anchor_sequence BIGINT, anchor_hash BYTEA,
    anchor_occurred_at TIMESTAMPTZ, anchor_accepted_at TIMESTAMPTZ, anchor_observed_at TIMESTAMPTZ,
    batch_first_sequence BIGINT, batch_last_sequence BIGINT, batch_event_count INTEGER,
    batch_generation BIGINT, batch_attempts INTEGER,
    batch_available_at TIMESTAMPTZ, batch_locked_until TIMESTAMPTZ,
    batch_last_error TEXT, batch_blocked_reason TEXT
) LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH head AS (
        SELECT chain.sequence, chain.event_hash FROM public.security_audit_chain_entries AS chain
        ORDER BY chain.sequence DESC LIMIT 1
    ), backlog AS (
        SELECT EXISTS (SELECT 1 FROM public.security_audit_event_outbox) AS pending_exists,
               (SELECT outbox.occurred_at FROM public.security_audit_event_outbox AS outbox
                ORDER BY outbox.occurred_at, outbox.event_id LIMIT 1) AS oldest_pending_occurred_at,
               EXISTS (
                   SELECT 1 FROM public.security_audit_chain_entries AS chain
                   WHERE chain.sequence <= COALESCE(
                       (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
                        WHERE state.singleton), -1)
                     AND EXISTS (
                         SELECT 1 FROM public.security_audit_event_outbox AS outbox
                         WHERE outbox.event_id = chain.event_id)
               ) AS pending_orphan_exists,
               GREATEST(relation.reltuples, 0)::BIGINT AS pending_estimate
        FROM pg_class AS relation
        WHERE relation.oid = 'public.security_audit_event_outbox'::REGCLASS
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

CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN, p_require_append BOOLEAN, p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (NOT COALESCE(p_require_append, FALSE) OR has_function_privilege(session_user,
        'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE, 'EXECUTE'))
    AND (NOT COALESCE(p_require_exporter, FALSE) OR (
        has_function_privilege(session_user, 'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_batch_members()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_claim_security_audit_pending(bigint)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reclaim_security_audit_batch(bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
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

ALTER TABLE public.security_audit_event_outbox
    SET (autovacuum_vacuum_scale_factor = 0,
         autovacuum_vacuum_threshold = 2000,
         autovacuum_vacuum_cost_delay = 0,
         autovacuum_analyze_scale_factor = 0,
         autovacuum_analyze_threshold = 500);

COMMENT ON TABLE public.security_audit_event_outbox IS
    'Pending export identities and their occurred_at ordering only; scheduling lives on the batch lease and acknowledgement deletes the row inside the anchor transaction.';
COMMENT ON TABLE public.security_audit_events IS
    'Immutable event facts, committed atomically with their business mutation and outbox entry.';
