-- Restore prior query plans without changing function identity or privileges.
-- Keep legacy append/open APIs; fresh claims finalize proof and lease together.
CREATE OR REPLACE FUNCTION public.nazo_stage_security_audit_chain(
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

-- Preserve the existing function identity, owner and grants.
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
    SELECT COUNT(*), COALESCE(array_agg(chain.event_id), '{}'::UUID[]) INTO v_members, v_ids
    FROM public.security_audit_chain_entries AS chain
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
    WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence
      AND event.exported_at IS NULL;
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
    -- retain them and mark export complete inside this same ACK transaction.
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
    DELETE FROM public.security_audit_chain_entries AS chain
    WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement reclaimed an unexpected chain count';
    END IF;
    PERFORM set_config('nazo.audit_ack', 'on', true);
    UPDATE public.security_audit_events AS event
    SET exported_at = v_exported_at
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
