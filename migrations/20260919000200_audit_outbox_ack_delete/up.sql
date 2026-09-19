-- Corrective migration: retire exported-at outbox retention entirely.
--
-- The 20260919000100 migration introduced a 1-day grace before reclaiming
-- exported delivery rows. At production event rates that keeps hundreds of
-- millions of already-delivered bookkeeping rows online for no reader: once
-- the exporter's checkpoint is accepted, only the durable anchor checkpoint
-- in security_audit_chain_state and the immutable event/chain records carry
-- evidence. No runtime path reads a delivered outbox row again.
--
-- Instead, acknowledgement now deletes the outbox delivery row inside the
-- same transaction that advances the anchor checkpoint: either the whole
-- acknowledgement commits (checkpoint advanced + delivery row gone) or it
-- rolls back and the row stays claimable. Pending, locked or rescheduled
-- rows are untouched, and there is no grace backlog for a sweeper to drain.

CREATE OR REPLACE FUNCTION public.nazo_ack_security_audit_event(
    p_event_id UUID, p_expected_attempts INTEGER, p_deployment_id TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_exported_at TIMESTAMPTZ := CURRENT_TIMESTAMP;
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

    -- The acknowledgement and the delivery-row removal are one transaction:
    -- a stale or already-terminal claim deletes nothing and returns FALSE.
    DELETE FROM public.security_audit_event_outbox AS outbox
    WHERE outbox.event_id = p_event_id AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL;
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

-- Delivery rows now disappear on acknowledgement, so pending is the only
-- remaining state and the exported_at predicate is gone from every read.
CREATE OR REPLACE FUNCTION public.nazo_claim_security_audit_events(p_limit BIGINT, p_lock_timeout_seconds INTEGER)
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

CREATE OR REPLACE FUNCTION public.nazo_reschedule_security_audit_event(
    p_event_id UUID,
    p_expected_attempts INTEGER,
    p_available_at TIMESTAMPTZ,
    p_last_error TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    IF p_available_at IS NULL
       OR p_available_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes'
       OR p_last_error IS NULL OR char_length(p_last_error) > 128 THEN
        RAISE EXCEPTION 'audit outbox reschedule bounds are invalid';
    END IF;
    UPDATE public.security_audit_event_outbox AS outbox
    SET available_at = p_available_at,
        locked_at = NULL,
        last_error = p_last_error,
        updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id
      AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
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

DROP FUNCTION IF EXISTS public.nazo_cleanup_exported_security_audit_outbox();
DROP INDEX IF EXISTS public.idx_security_audit_outbox_exported;
ALTER TABLE public.security_audit_event_outbox DROP COLUMN exported_at;

COMMENT ON TABLE public.security_audit_event_outbox IS
    'Delivery bookkeeping for pending export only; the acknowledgement transaction deletes the row while advancing the durable anchor checkpoint.';
