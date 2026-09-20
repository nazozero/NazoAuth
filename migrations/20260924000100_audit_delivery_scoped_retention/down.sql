-- Restore the online-window archive model: ack releases only the outbox
-- bookkeeping, and the maintenance sweeper moves the aged delivered prefix
-- into security_audit_archive again. Rows already reclaimed by
-- delivery-scoped acks cannot be re-materialized — the receiver is their
-- only remaining copy, which is the intended durable store either way.

CREATE TABLE public.security_audit_archive (
    event_id UUID NOT NULL,
    sequence BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    previous_hash BYTEA NOT NULL,
    event_hash BYTEA NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT security_audit_archive_pkey PRIMARY KEY (event_id),
    CONSTRAINT security_audit_archive_sequence_key UNIQUE (sequence),
    CONSTRAINT security_audit_archive_hash_key UNIQUE (event_hash),
    CONSTRAINT ck_security_audit_archive_sequence_positive CHECK (sequence > 0),
    CONSTRAINT ck_security_audit_archive_event_type CHECK (
        char_length(event_type) BETWEEN 1 AND 64
        AND event_type ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT ck_security_audit_archive_event_category CHECK (
        char_length(event_category) BETWEEN 1 AND 64
        AND event_category ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT ck_security_audit_archive_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_security_audit_archive_previous_hash_length CHECK (octet_length(previous_hash) = 32),
    CONSTRAINT ck_security_audit_archive_hash_length CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX idx_security_audit_archive_occurred_at
    ON public.security_audit_archive (occurred_at, sequence);

CREATE TRIGGER security_audit_archive_append_only
BEFORE UPDATE OR DELETE ON public.security_audit_archive
FOR EACH ROW EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER security_audit_archive_no_truncate
BEFORE TRUNCATE ON public.security_audit_archive
FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TABLE public.security_audit_archive_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_archived_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_archived_sequence >= 0),
    last_archived_hash BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(last_archived_hash) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO public.security_audit_archive_state (singleton)
VALUES (TRUE);

CREATE INDEX idx_security_audit_events_occurred_at
    ON public.security_audit_events (occurred_at, event_id);
CREATE INDEX idx_security_audit_events_type_occurred_at
    ON public.security_audit_events (event_type, occurred_at, event_id);

CREATE OR REPLACE FUNCTION public.nazo_reject_security_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE'
        AND current_setting('nazo.audit_archive', true) IS NOT DISTINCT FROM 'on'
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security audit ledger is append-only';
END;
$$;

CREATE FUNCTION public.nazo_archive_security_audit_prefix(
    p_limit BIGINT,
    p_older_than TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_anchor BIGINT;
    v_watermark BIGINT;
    v_watermark_hash BYTEA;
    v_count BIGINT;
    v_last_sequence BIGINT;
    v_last_hash BYTEA;
    v_broken BOOLEAN;
BEGIN
    IF p_limit IS NULL OR p_limit <= 0 THEN
        RAISE EXCEPTION 'archive batch limit must be positive';
    END IF;
    SELECT state.anchor_sequence INTO v_anchor
    FROM public.security_audit_chain_state AS state
    WHERE state.singleton
    FOR UPDATE OF state;
    SELECT archive.last_archived_sequence, archive.last_archived_hash
      INTO v_watermark, v_watermark_hash
    FROM public.security_audit_archive_state AS archive
    WHERE archive.singleton
    FOR UPDATE OF archive;
    WITH ordered AS (
        SELECT chain.event_id, chain.sequence, chain.previous_hash, chain.event_hash,
               events.occurred_at,
               ROW_NUMBER() OVER (ORDER BY chain.sequence) AS rn,
               LAG(chain.event_hash) OVER (ORDER BY chain.sequence) AS prior_hash
        FROM public.security_audit_chain_entries AS chain
        JOIN public.security_audit_events AS events
          ON events.event_id = chain.event_id
        WHERE chain.sequence > v_watermark
        ORDER BY chain.sequence
        LIMIT p_limit
    ),
    boundary AS (
        SELECT COALESCE(MIN(ordered.rn) - 1, p_limit) AS stop_rn
        FROM ordered
        WHERE ordered.sequence <> v_watermark + ordered.rn
           OR ordered.sequence > COALESCE(v_anchor, 0)
           OR ordered.occurred_at >= p_older_than
    ),
    slice AS (
        SELECT ordered.* FROM ordered
        WHERE ordered.rn <= COALESCE((SELECT boundary.stop_rn FROM boundary), p_limit)
    )
    SELECT COUNT(*),
           COALESCE(MAX(slice.sequence), v_watermark),
           (SELECT tail.event_hash FROM slice AS tail
             ORDER BY tail.rn DESC LIMIT 1),
           COALESCE(BOOL_OR(
               (slice.rn = 1 AND slice.previous_hash <> v_watermark_hash)
               OR (slice.rn > 1 AND slice.previous_hash <> slice.prior_hash)),
               FALSE)
      INTO v_count, v_last_sequence, v_last_hash, v_broken
    FROM slice;

    IF v_broken THEN
        RAISE EXCEPTION 'security audit archive boundary chain mismatch above sequence %', v_watermark;
    END IF;
    IF v_count IS NULL OR v_count = 0 THEN
        RETURN 0;
    END IF;

    PERFORM set_config('nazo.audit_archive', 'on', true);

    INSERT INTO public.security_audit_archive (
        event_id, sequence, event_type, event_category, payload,
        occurred_at, previous_hash, event_hash
    )
    SELECT chain.event_id, chain.sequence, events.event_type,
           events.event_category, events.payload, events.occurred_at,
           chain.previous_hash, chain.event_hash
    FROM public.security_audit_chain_entries AS chain
    JOIN public.security_audit_events AS events
      ON events.event_id = chain.event_id
    WHERE chain.sequence > v_watermark
      AND chain.sequence <= v_last_sequence
    ORDER BY chain.sequence;

    DELETE FROM public.security_audit_chain_entries AS chain
    WHERE chain.sequence > v_watermark
      AND chain.sequence <= v_last_sequence;

    DELETE FROM public.security_audit_events AS events
    WHERE events.event_id IN (
        SELECT archive.event_id FROM public.security_audit_archive AS archive
        WHERE archive.sequence > v_watermark
          AND archive.sequence <= v_last_sequence);

    PERFORM set_config('nazo.audit_archive', 'off', true);

    UPDATE public.security_audit_archive_state AS archive
    SET last_archived_sequence = v_last_sequence,
        last_archived_hash = v_last_hash,
        updated_at = CURRENT_TIMESTAMP
    WHERE archive.singleton;

    RETURN v_count;
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
    SELECT COUNT(*) INTO v_members
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
    DELETE FROM public.security_audit_event_outbox AS outbox
    WHERE outbox.event_id IN (
        SELECT chain.event_id FROM public.security_audit_chain_entries AS chain
        WHERE chain.sequence > COALESCE(v_anchor, 0) AND chain.sequence <= p_last_sequence
    );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> p_event_count THEN
        RAISE EXCEPTION 'audit batch acknowledgement deleted an unexpected member count';
    END IF;
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

CREATE OR REPLACE FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = COALESCE(anchor_deployment_id, p_deployment_id),
        anchor_observed_at = CURRENT_TIMESTAMP
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE OR REPLACE FUNCTION public.nazo_append_security_audit_chain(
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
                   SELECT 1 FROM public.security_audit_event_outbox AS outbox
                   JOIN public.security_audit_chain_entries AS chain ON chain.event_id = outbox.event_id
                   WHERE chain.sequence <= COALESCE(
                       (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
                        WHERE state.singleton), -1)
               ) AS pending_orphan_exists,
               GREATEST(relation.reltuples, 0)::BIGINT AS pending_estimate
        FROM pg_class AS relation
        WHERE relation.oid = 'public.security_audit_event_outbox'::REGCLASS
    )
    SELECT state.last_sequence, state.last_hash,
           (head.sequence IS NULL AND state.last_sequence = 0 AND state.last_hash = decode(repeat('00',32),'hex'))
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
