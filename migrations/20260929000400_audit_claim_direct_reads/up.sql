-- Bound the work of each event read, not only the candidate count.
-- CREATE OR REPLACE preserves the existing owner and EXECUTE privileges.
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
