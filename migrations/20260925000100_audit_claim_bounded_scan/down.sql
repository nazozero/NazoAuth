-- Restore the pre-bounded claim shape (single join + NOT EXISTS proof) and
-- return analyze scheduling to defaults.
CREATE OR REPLACE FUNCTION public.nazo_claim_security_audit_pending(p_limit BIGINT)
RETURNS TABLE(
    event_id UUID, sequence BIGINT, event_type TEXT, event_category TEXT,
    payload_canonical TEXT, occurred_at TIMESTAMPTZ,
    previous_hash BYTEA, event_hash BYTEA
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_claimed INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'audit outbox claim bounds are invalid';
    END IF;
    RETURN QUERY
    SELECT event.event_id, chain.sequence, event.event_type::TEXT, event.event_category::TEXT,
           event.payload::TEXT, event.occurred_at,
           chain.previous_hash, chain.event_hash
    FROM public.security_audit_event_outbox AS outbox
    JOIN public.security_audit_chain_entries AS chain ON chain.event_id = outbox.event_id
    JOIN public.security_audit_events AS event ON event.event_id = outbox.event_id
    WHERE chain.sequence > COALESCE(
        (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
         WHERE state.singleton), 0)
    ORDER BY chain.sequence
    LIMIT p_limit;
    GET DIAGNOSTICS v_claimed = ROW_COUNT;
    IF v_claimed >= p_limit THEN RETURN; END IF;
    RETURN QUERY
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT, event.event_category::TEXT,
           event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM public.security_audit_event_outbox AS outbox
    JOIN public.security_audit_events AS event ON event.event_id = outbox.event_id
    WHERE NOT EXISTS (
        SELECT 1 FROM public.security_audit_chain_entries AS chain
        WHERE chain.event_id = outbox.event_id
    )
    ORDER BY outbox.occurred_at, outbox.event_id
    LIMIT p_limit - v_claimed;
END;
$$;

ALTER TABLE public.security_audit_event_outbox
    RESET (autovacuum_analyze_scale_factor, autovacuum_analyze_threshold);
ALTER TABLE public.security_audit_events
    RESET (autovacuum_analyze_scale_factor, autovacuum_analyze_threshold);
ALTER TABLE public.security_audit_chain_entries
    RESET (autovacuum_analyze_scale_factor, autovacuum_analyze_threshold);
