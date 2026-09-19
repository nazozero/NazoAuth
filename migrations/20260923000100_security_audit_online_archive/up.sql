-- Security audit ledger online retention: sequence-prefix archive.
--
-- `security_audit_events` and `security_audit_chain_entries` are append-only,
-- so without a boundary they grow at the event rate forever. The hot tables
-- only need to serve the exporter (events above the anchor) and recent
-- forensic reads; delivered evidence older than the online window moves to
-- `security_audit_archive`, which keeps the complete event payload plus its
-- chain link so the archived prefix remains independently verifiable.
--
-- Archival rules (enforced inside `nazo_archive_security_audit_prefix`):
--   * only the contiguous chain prefix may move: sequence numbering must be
--     gap-free above the archive watermark, the first archived row's
--     `previous_hash` must equal the stored watermark hash, and every link
--     inside the archived slice must chain;
--   * only sequences at or below `anchor_sequence` — rows the exporter has
--     delivered and the receiver has durably acknowledged — are eligible;
--     an in-flight batch is above the anchor by construction and can never
--     be archived mid-flight;
--   * only events older than the online window move, keeping the hot tables
--     useful for recent inspection;
--   * each call is bounded by `p_limit` so the worker drains backlog across
--     batches instead of one unbounded transaction.
--
-- The append-only trigger keeps rejecting application writes. The archive
-- function alone bypasses it by setting the `nazo.audit_archive` GUC inside
-- its own transaction; table ACLs remain the real boundary (the runtime role
-- has no DELETE on the ledger tables at all).

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

-- Archive watermark: the last archived sequence and its event hash form the
-- verification anchor for the archived prefix (genesis-initialized to the
-- same zero hash the chain state starts from).
CREATE TABLE public.security_audit_archive_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_archived_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_archived_sequence >= 0),
    last_archived_hash BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(last_archived_hash) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO public.security_audit_archive_state (singleton)
VALUES (TRUE);

-- Let the archival function — and only a DELETE under its session GUC —
-- pass the append-only guard. UPDATE and TRUNCATE stay forbidden for every
-- session; table ACLs still decide who may delete at all.
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

-- Move the eligible contiguous chain prefix into the archive.
-- Returns the number of archived events (0 when nothing qualifies).
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

    -- Serialize against the exporter's claim/ack, which takes the same
    -- chain-state row lock, and against concurrent archivers through the
    -- archive-state row.
    SELECT state.anchor_sequence INTO v_anchor
    FROM public.security_audit_chain_state AS state
    WHERE state.singleton
    FOR UPDATE OF state;
    SELECT archive.last_archived_sequence, archive.last_archived_hash
      INTO v_watermark, v_watermark_hash
    FROM public.security_audit_archive_state AS archive
    WHERE archive.singleton
    FOR UPDATE OF archive;

    -- Candidates in chain order above the watermark; stop at the first
    -- sequence gap, the first not-yet-acked row, or the first row still
    -- inside the online window — whichever comes first. The archived slice
    -- is therefore always a contiguous delivered prefix.
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
        -- No ineligible row in this window means the whole window archives.
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

    -- The slice is the contiguous range (v_watermark, v_watermark + v_count].
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

    -- chain_entries references events with ON DELETE RESTRICT: remove the
    -- chain rows first, then the events (located through the archive copy).
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

COMMENT ON FUNCTION public.nazo_archive_security_audit_prefix(BIGINT, TIMESTAMPTZ) IS
    'Moves the delivered, contiguous audit-chain prefix older than the online window into security_audit_archive. Bounded per call; fail-closed on chain-boundary mismatch.';
COMMENT ON TABLE public.security_audit_archive IS
    'Archived security audit evidence: delivered events below the online window with their chain links, immutable like the hot ledger.';
