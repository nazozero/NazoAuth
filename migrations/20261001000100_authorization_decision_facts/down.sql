-- Never discard live facts/fences to make an older binary start. Drain and
-- reclaim all committed decisions through the supported lifecycle first.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM public.security_audit_events
               WHERE event_type = 'authorization_decision_committed') THEN
        RAISE EXCEPTION 'authorization decision facts remain; refusing unsafe downgrade';
    END IF;
END $$;
DROP FUNCTION public.nazo_commit_authorization_decision(UUID,UUID,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,UUID,TIMESTAMPTZ,JSONB,JSONB,JSONB,JSONB);
DROP FUNCTION public.nazo_cleanup_authorization_decisions();


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
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_reject_security_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE'
        AND current_setting('nazo.audit_reclaim', true) IS NOT DISTINCT FROM 'on'
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security audit ledger is append-only';
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
        WHERE candidate.event_id = chained.event_id
        LIMIT 1
    ) AS event
    ORDER BY chained.sequence;
    GET DIAGNOSTICS v_claimed = ROW_COUNT;
    IF v_claimed > 0 THEN RETURN; END IF;
    -- No chained prefix: every remaining event row is a new unchained event
    -- (delivered rows were deleted at ack, chained rows are handled above).
    -- Read full rows directly through the ordered index. A bounded ID CTE
    -- followed by a self-join adds no information and can scan the backlog.
    RETURN QUERY
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM public.security_audit_events AS event
    ORDER BY event.occurred_at, event.event_id
    LIMIT p_limit;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_append_security_audit_chain(
    p_previous_sequence BIGINT, p_previous_hash BYTEA, p_event_ids UUID[], p_event_hashes BYTEA[]
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_sequence BIGINT;
    v_hash BYTEA;
    v_anchor BIGINT;
    v_entry RECORD;
BEGIN
    IF p_event_ids IS NULL OR cardinality(p_event_ids) NOT BETWEEN 1 AND 256
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
        v_sequence := v_sequence + 1;
        INSERT INTO public.security_audit_chain_entries (event_id, sequence, previous_hash, event_hash)
        VALUES (v_entry.event_id, v_sequence, v_hash, v_entry.event_hash);
        v_hash := v_entry.event_hash;
    END LOOP;
    UPDATE public.security_audit_chain_state SET last_sequence = v_sequence, last_hash = v_hash
    WHERE singleton;
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
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
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

    -- The receiver durably holds these events; the OLTP copies were delivery
    -- state only. chain_entries reference the events with RESTRICT, so the
    -- child rows leave first.
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
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
        SELECT EXISTS (SELECT 1 FROM public.security_audit_events) AS pending_exists,
               (SELECT event.occurred_at FROM public.security_audit_events AS event
                ORDER BY event.occurred_at, event.event_id LIMIT 1) AS oldest_pending_occurred_at,
               EXISTS (
                   SELECT 1 FROM public.security_audit_chain_entries AS chain
                   WHERE chain.sequence <= COALESCE(
                       (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
                        WHERE state.singleton), -1)
               ) AS pending_orphan_exists,
               GREATEST(relation.reltuples, 0)::BIGINT AS pending_estimate
        FROM pg_class AS relation
        WHERE relation.oid = 'public.security_audit_events'::REGCLASS
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
DROP INDEX public.idx_authorization_decision_request;
DROP INDEX public.idx_authorization_decision_par;
DROP INDEX public.idx_authorization_decision_reclaim;
DROP INDEX public.idx_security_audit_events_pending_order;
ALTER TABLE public.security_audit_events
    DROP CONSTRAINT ck_security_audit_authorization_decision,
    DROP COLUMN authorization_tenant_id, DROP COLUMN authorization_request_id,
    DROP COLUMN authorization_par_uri, DROP COLUMN authorization_decision,
    DROP COLUMN authorization_valid_until, DROP COLUMN business_retain_until,
    DROP COLUMN exported_at;
CREATE INDEX idx_security_audit_events_pending_order
    ON public.security_audit_events (occurred_at, event_id);
COMMENT ON TABLE public.security_audit_events IS
    'Immutable event facts; each row is the pending-delivery identity until acknowledgement deletes it inside the anchor transaction.';
