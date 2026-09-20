-- Delivery-scoped audit retention: delivered events are reclaimed inside the
-- acknowledgement transaction instead of being copied into a permanent OLTP
-- archive and swept later.
--
-- Measured basis (statemin-v2 post-soak diagnostics, 128MB shared_buffers):
--   * security_audit_archive had no reader. The external receiver already is
--     the authoritative durable copy (verify + fsync + signed receipt), so the
--     OLTP duplicate cost ~6.5KB WAL per event on a multi-GB indexed table.
--   * nazo_archive_security_audit_prefix held the chain-state row FOR UPDATE
--     for the entire copy+delete transaction, serializing against exporter
--     claim/ack (observed Lock:transactionid stalls).
--   * Deleting at ack leaves chain_entries holding only chained-but-
--     undelivered rows, which also collapses the per-iteration orphan probe
--     from a multi-million-row falsifying scan to a single index probe.
--
-- Invariants kept:
--   * undelivered events still fail closed in the outbox; nothing is removed
--     before the receiver's signed acknowledgement commits;
--   * the singleton chain head (last_sequence/last_hash) and the anchor
--     checkpoint still fence replays and attest the delivered prefix;
--   * the append-only trigger still rejects ledger mutation outside the
--     transaction-local reclaim permit, now `nazo.audit_reclaim`.

-- Acknowledge a committed batch: delete its outbox, chain-entry and event
-- rows, and advance the durable anchor in the same transaction. The batch is
-- still verified first (generation, contiguous prefix range, count, digest,
-- last-hash link); a failed check rolls everything back.
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

    -- The receiver durably holds these events; the OLTP copies were delivery
    -- state only. outbox and chain_entries reference events with RESTRICT, so
    -- the children leave first.
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

-- The delivery-time reclaim permit replaces the archival one.
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

-- Anchor observation is freshness bookkeeping only: while delivery is active
-- the acknowledgement already refreshes anchor_observed_at, so the separate
-- per-iteration UPDATE becomes a no-op until the row goes stale.
CREATE OR REPLACE FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = COALESCE(anchor_deployment_id, p_deployment_id),
        anchor_observed_at = CURRENT_TIMESTAMP
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id)
      AND (anchor_deployment_id IS NULL
           OR anchor_observed_at IS NULL
           OR anchor_observed_at < CURRENT_TIMESTAMP - INTERVAL '30 seconds');
    RETURN EXISTS (
        SELECT 1 FROM public.security_audit_chain_state AS state
        WHERE state.singleton AND state.anchor_deployment_id = p_deployment_id
    );
END;
$$;

-- The append-side head check is the mirror of the health clause above: once
-- a fully delivered prefix is reclaimed, the head row no longer sits in
-- chain_entries. The anchor already attests that head, so the proof is only
-- required while undelivered entries exist (head beyond the anchor).
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

-- The health projection is unchanged in shape; two clauses get cheaper
-- because delivered rows are now reclaimed at ack:
--   * pending_orphan_exists — chain entries at or below the anchor can no
--     longer exist, so the falsifying probe resolves on the first index row;
--   * chain_valid — an empty chain is valid whenever the head was fully
--     delivered (last_sequence = anchor_sequence), not only at genesis.
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

-- One-time sweep: rows already acknowledged under the old model but not yet
-- archived (sequence at or below the durable anchor) are delivered state;
-- reclaim them once so nothing pre-dating this cut stays resident forever.
CREATE TEMP TABLE nazo_audit_reclaim_ids ON COMMIT DROP AS
SELECT chain.event_id
FROM public.security_audit_chain_entries AS chain
WHERE chain.sequence <= COALESCE(
    (SELECT state.anchor_sequence
     FROM public.security_audit_chain_state AS state WHERE state.singleton), -1);

SELECT set_config('nazo.audit_reclaim', 'on', true);
DELETE FROM public.security_audit_event_outbox AS outbox
WHERE outbox.event_id IN (SELECT event_id FROM nazo_audit_reclaim_ids);
DELETE FROM public.security_audit_chain_entries AS chain
WHERE chain.event_id IN (SELECT event_id FROM nazo_audit_reclaim_ids);
DELETE FROM public.security_audit_events AS event
WHERE event.event_id IN (SELECT event_id FROM nazo_audit_reclaim_ids);
SELECT set_config('nazo.audit_reclaim', 'off', true);
DROP TABLE nazo_audit_reclaim_ids;

-- The permanent OLTP archive and the online-window indexes go away: the
-- receiver is the sole complete history, and no reader queries the hot
-- ledger by occurred_at or event_type.
DROP FUNCTION IF EXISTS public.nazo_archive_security_audit_prefix(BIGINT, TIMESTAMPTZ);
DROP TABLE IF EXISTS public.security_audit_archive;
DROP TABLE IF EXISTS public.security_audit_archive_state;
DROP INDEX IF EXISTS public.idx_security_audit_events_occurred_at;
DROP INDEX IF EXISTS public.idx_security_audit_events_type_occurred_at;

-- Queue-discipline vacuuming: ack deletes at the head of
-- idx_security_audit_outbox_order, so the default scale factor (20% of a
-- multi-million-row backlog) lets a dead prefix accumulate between vacuums
-- and every ordered claim/oldest-pending probe must walk it. Bounded
-- thresholds keep the dead prefix small; the probes themselves kill entries
-- between visits, so this is a lifecycle bound, not a throughput knob.
ALTER TABLE public.security_audit_event_outbox
    SET (autovacuum_vacuum_scale_factor = 0,
         autovacuum_vacuum_threshold = 2000,
         autovacuum_vacuum_cost_delay = 0);
ALTER TABLE public.security_audit_events
    SET (autovacuum_vacuum_scale_factor = 0,
         autovacuum_vacuum_threshold = 10000,
         autovacuum_vacuum_cost_delay = 0);
ALTER TABLE public.security_audit_chain_entries
    SET (autovacuum_vacuum_scale_factor = 0,
         autovacuum_vacuum_threshold = 500,
         autovacuum_vacuum_cost_delay = 0);
