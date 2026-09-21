-- Bounded audit claim planning. The exporter's hot-path candidate read must
-- stay O(batch limit) at any backlog depth, including cold starts where the
-- planner has no usable statistics yet.
--
-- The previous shape joined outbox/chain/events in one query and relied on
-- the planner picking the sequence index with a correlated NOT EXISTS proof
-- for unchained rows. With absent statistics that degrades to a
-- backlog-proportional nested-loop/anti-join; the 6h soak measured a cold
-- claim pinning xmin for ~12 minutes. This rewrite materializes the bounded
-- identity set (<= p_limit rows) from the driving index FIRST, then joins
-- outbox/events by primary key:
--
--   * chained prefix branch: identity comes straight from the
--     security_audit_chain_entries sequence index (sequence > anchor
--     ORDER BY sequence LIMIT p_limit). If this branch returns ANY row the
--     function returns immediately — an open in-flight batch claims
--     exclusively and new unchained rows are never mixed into the same read.
--   * no chained prefix: the fixed in-flight batch state machine guarantees
--     every pending outbox row is a new event, so the unchained identity set
--     comes straight from the (occurred_at, event_id) order index
--     (ORDER BY ... LIMIT p_limit) with no NOT EXISTS proof against the
--     chain. "chain <= anchor + outbox" remains enforced by the orphan
--     invariant, which fails closed on violation — the hot path does not
--     re-prove it per row.
--
-- Neither branch paginates, sorts the full table, or runs a
-- backlog-proportional anti-join; boundedness comes from the LIMIT inside
-- MATERIALIZED CTEs plus function-scoped planner pinning
-- (enable_seqscan/enable_bitmapscan off): without statistics a table looks
-- near-empty to the planner and a full scan + sort can win on cost even
-- though it is backlog-proportional, so the function forbids scan shapes
-- that cannot use the driving index. Statistics are therefore only a
-- performance aid, never a precondition for boundedness.
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
    -- In-flight batch prefix: bound identities on the sequence index first,
    -- then resolve each row through the outbox/events primary keys.
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
    -- No chained prefix: pending outbox rows are all new events. The order
    -- index materializes the bounded identity set; no anti-join is needed.
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

-- Planner-statistics aid only: a fixed small analyze threshold gives the
-- planner usable row estimates shortly after a cold start instead of waiting
-- for 20% of the table to change. This is not what bounds the claim — the
-- query above is bounded by construction at any statistics state.
ALTER TABLE public.security_audit_event_outbox
    SET (autovacuum_analyze_scale_factor = 0,
         autovacuum_analyze_threshold = 500);
ALTER TABLE public.security_audit_events
    SET (autovacuum_analyze_scale_factor = 0,
         autovacuum_analyze_threshold = 500);
ALTER TABLE public.security_audit_chain_entries
    SET (autovacuum_analyze_scale_factor = 0,
         autovacuum_analyze_threshold = 500);
