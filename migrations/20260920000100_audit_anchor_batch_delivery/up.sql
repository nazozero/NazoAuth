-- Batched audit-anchor delivery: one fixed in-flight batch per chain.
--
-- Per-event delivery bookkeeping (attempts, locks, error and scheduling
-- columns) is replaced by a single batch lease on the chain control row. A
-- batch is always the contiguous unacknowledged chain prefix after the
-- durable anchor checkpoint, so its members are identified by the sequence
-- range alone: (anchor_sequence, batch_last_sequence]. Batch bounds are
-- fixed at commit time and can only move forward by acknowledgement; a
-- stale claim only loses its fencing generation.
--
-- Stop the old exporter before this schema cut. In-flight chained pending
-- events are wrapped into the initial batch lease; their content digest is
-- backfilled on the first re-claim.

CREATE TEMP TABLE nazo_audit_upgrade_grants ON COMMIT DROP AS
SELECT role.rolname,
       bool_or(proc.proname = 'nazo_persist_security_audit_event') AS writer,
       bool_or(proc.proname = 'nazo_claim_security_audit_events') AS exporter
FROM pg_proc AS proc
JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
JOIN pg_roles AS role ON role.oid = acl.grantee
WHERE namespace.nspname = 'public'
  AND proc.proname IN ('nazo_persist_security_audit_event', 'nazo_claim_security_audit_events')
  AND acl.privilege_type = 'EXECUTE' AND acl.grantee <> proc.proowner
GROUP BY role.rolname;

ALTER TABLE public.security_audit_chain_state
    ADD COLUMN batch_first_sequence BIGINT,
    ADD COLUMN batch_last_sequence BIGINT,
    ADD COLUMN batch_event_count INTEGER,
    ADD COLUMN batch_digest BYTEA,
    ADD COLUMN batch_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN batch_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN batch_available_at TIMESTAMPTZ,
    ADD COLUMN batch_locked_until TIMESTAMPTZ,
    ADD COLUMN batch_last_error VARCHAR(128),
    ADD COLUMN batch_blocked_reason VARCHAR(128),
    ADD CONSTRAINT ck_security_audit_batch_shape CHECK (
        (batch_first_sequence IS NULL AND batch_last_sequence IS NULL
         AND batch_event_count IS NULL AND batch_digest IS NULL)
        OR
        (batch_first_sequence IS NOT NULL AND batch_first_sequence > 0
         AND batch_last_sequence IS NOT NULL AND batch_last_sequence >= batch_first_sequence
         AND batch_event_count IS NOT NULL
         AND batch_event_count = batch_last_sequence - batch_first_sequence + 1
         AND batch_event_count BETWEEN 1 AND 256)
    ),
    ADD CONSTRAINT ck_security_audit_batch_digest_length CHECK (
        batch_digest IS NULL OR octet_length(batch_digest) = 32
    ),
    ADD CONSTRAINT ck_security_audit_batch_attempts_non_negative CHECK (batch_attempts >= 0);

-- Chained-but-unacknowledged deliveries from the retired protocol become the
-- initial in-flight batch. The digest is recomputed and stored on re-claim.
WITH chained AS (
    SELECT MIN(chain.sequence) AS first_sequence, MAX(chain.sequence) AS last_sequence,
           COUNT(*)::INTEGER AS event_count
    FROM public.security_audit_event_outbox AS outbox
    JOIN public.security_audit_chain_entries AS chain ON chain.event_id = outbox.event_id
    WHERE chain.sequence > COALESCE(
        (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
         WHERE state.singleton), 0)
)
UPDATE public.security_audit_chain_state AS state
SET batch_first_sequence = chained.first_sequence,
    batch_last_sequence = chained.last_sequence,
    batch_event_count = chained.event_count,
    batch_available_at = CURRENT_TIMESTAMP
FROM chained
WHERE state.singleton AND chained.event_count > 0;

-- The outbox keeps only the pending event identity and its reader-visible
-- occurred_at ordering/health projection. Scheduling state is batch-scoped.
ALTER TABLE public.security_audit_event_outbox
    ADD COLUMN occurred_at TIMESTAMPTZ;
UPDATE public.security_audit_event_outbox AS outbox
SET occurred_at = event.occurred_at
FROM public.security_audit_events AS event
WHERE event.event_id = outbox.event_id;
ALTER TABLE public.security_audit_event_outbox
    ALTER COLUMN occurred_at SET NOT NULL,
    DROP COLUMN attempts,
    DROP COLUMN available_at,
    DROP COLUMN locked_at,
    DROP COLUMN last_error,
    DROP COLUMN created_at,
    DROP COLUMN updated_at;
CREATE INDEX idx_security_audit_outbox_order
    ON public.security_audit_event_outbox (occurred_at, event_id);

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

-- The exporter holds the control-row lock only inside the claim transaction;
-- HTTPS never happens under this lock. The returned row carries the whole
-- lease so the caller can classify the batch state without another roundtrip.
-- The row shape changes, so the function is replaced wholesale; the upgrade
-- grant block below restores EXECUTE to the roles that held it.
DROP FUNCTION public.nazo_security_audit_chain_head_for_update();
CREATE FUNCTION public.nazo_security_audit_chain_head_for_update()
RETURNS TABLE(
    last_sequence BIGINT, last_hash BYTEA,
    anchor_sequence BIGINT, anchor_hash BYTEA, anchor_deployment_id TEXT,
    batch_first_sequence BIGINT, batch_last_sequence BIGINT, batch_event_count INTEGER,
    batch_digest BYTEA, batch_generation BIGINT, batch_attempts INTEGER,
    batch_available_at TIMESTAMPTZ, batch_locked_until TIMESTAMPTZ,
    batch_last_error TEXT, batch_blocked_reason TEXT
)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT state.last_sequence, state.last_hash,
           state.anchor_sequence, state.anchor_hash, state.anchor_deployment_id::TEXT,
           state.batch_first_sequence, state.batch_last_sequence, state.batch_event_count,
           state.batch_digest, state.batch_generation, state.batch_attempts,
           state.batch_available_at, state.batch_locked_until,
           state.batch_last_error, state.batch_blocked_reason
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE
$$;

-- Members of the committed in-flight batch: the contiguous sequence prefix
-- after the durable anchor checkpoint. Re-claiming never reorders, splits
-- or merges these bounds.
CREATE FUNCTION public.nazo_security_audit_batch_members()
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

-- Candidates for a new batch: chained leftovers first (defensive; normally
-- empty), then pending rows in occurred_at order. Each pass is bounded by
-- its own LIMIT so claiming never sorts or scans the whole backlog.
CREATE FUNCTION public.nazo_claim_security_audit_pending(p_limit BIGINT)
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

-- Commit a new batch lease inside the claim transaction. The batch is always
-- the contiguous prefix (anchor_sequence, batch_last_sequence]; members are
-- the outbox rows whose chain entries fall inside that range.
CREATE FUNCTION public.nazo_open_security_audit_batch(
    p_first_sequence BIGINT, p_last_sequence BIGINT, p_event_count INTEGER,
    p_batch_digest BYTEA, p_lock_timeout_seconds INTEGER
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_generation BIGINT;
BEGIN
    IF p_first_sequence IS NULL OR p_last_sequence IS NULL
       OR p_event_count IS NULL OR p_batch_digest IS NULL
       OR octet_length(p_batch_digest) <> 32
       OR p_lock_timeout_seconds IS NULL OR p_lock_timeout_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'audit batch open arguments are invalid';
    END IF;
    UPDATE public.security_audit_chain_state AS state
    SET batch_first_sequence = p_first_sequence,
        batch_last_sequence = p_last_sequence,
        batch_event_count = p_event_count,
        batch_digest = p_batch_digest,
        batch_generation = state.batch_generation + 1,
        batch_attempts = 0,
        batch_available_at = CURRENT_TIMESTAMP,
        batch_locked_until = CURRENT_TIMESTAMP + (p_lock_timeout_seconds * INTERVAL '1 second'),
        batch_last_error = NULL,
        batch_blocked_reason = NULL
    WHERE state.singleton AND state.batch_last_sequence IS NULL
      AND p_first_sequence = COALESCE(state.anchor_sequence, 0) + 1
      AND p_last_sequence >= p_first_sequence
      AND p_last_sequence <= state.last_sequence
      AND p_event_count = p_last_sequence - p_first_sequence + 1
      AND p_event_count BETWEEN 1 AND 256
    RETURNING state.batch_generation INTO v_generation;
    IF v_generation IS NULL THEN
        RAISE EXCEPTION 'audit batch open conflicts with the committed chain state';
    END IF;
    RETURN v_generation;
END;
$$;

-- Re-claim the committed batch after its lease or backoff expired. Only the
-- fencing generation and the lock deadline change; range, count and content
-- digest stay exactly as committed. A stored digest mismatch means the chain
-- content changed under the lease and fails closed.
CREATE FUNCTION public.nazo_reclaim_security_audit_batch(
    p_batch_digest BYTEA, p_lock_timeout_seconds INTEGER
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_generation BIGINT;
BEGIN
    IF p_batch_digest IS NULL OR octet_length(p_batch_digest) <> 32
       OR p_lock_timeout_seconds IS NULL OR p_lock_timeout_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'audit batch reclaim arguments are invalid';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no in-flight audit batch to re-claim';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton
      AND (state.batch_digest IS NULL OR state.batch_digest = p_batch_digest);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit batch content digest changed under the lease';
    END IF;
    UPDATE public.security_audit_chain_state AS state
    SET batch_generation = state.batch_generation + 1,
        batch_digest = p_batch_digest,
        batch_locked_until = CURRENT_TIMESTAMP + (p_lock_timeout_seconds * INTERVAL '1 second')
    WHERE state.singleton
      AND (state.batch_locked_until IS NULL OR state.batch_locked_until <= CURRENT_TIMESTAMP)
      AND (state.batch_available_at IS NULL OR state.batch_available_at <= CURRENT_TIMESTAMP)
      AND state.batch_blocked_reason IS NULL
    RETURNING state.batch_generation INTO v_generation;
    IF v_generation IS NULL THEN
        RAISE EXCEPTION 'audit batch lease is not claimable';
    END IF;
    RETURN v_generation;
END;
$$;

-- Whole-batch acknowledgement: verify the fencing generation and the
-- receiver-bound range/content, verify the members still form the complete
-- contiguous prefix, then delete exactly those outbox rows and advance the
-- anchor checkpoint in the same transaction. Stale generations return FALSE;
-- content mismatches raise because they can never self-heal.
CREATE FUNCTION public.nazo_ack_security_audit_batch(
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

-- Whole-batch failure: release the lease so a re-claim can pick the identical
-- range up after the backoff, count the attempt and record the bounded
-- reason. A blocked batch stops being claimable until an operator clears it.
CREATE FUNCTION public.nazo_fail_security_audit_batch(
    p_generation BIGINT, p_available_at TIMESTAMPTZ,
    p_last_error TEXT, p_blocked BOOLEAN
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_available_at IS NULL
       OR p_available_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes'
       OR p_last_error IS NULL OR char_length(p_last_error) > 128 THEN
        RAISE EXCEPTION 'audit batch failure arguments are invalid';
    END IF;
    UPDATE public.security_audit_chain_state AS state
    SET batch_locked_until = NULL,
        batch_available_at = p_available_at,
        batch_attempts = state.batch_attempts + 1,
        batch_last_error = left(p_last_error, 128),
        batch_blocked_reason = CASE WHEN p_blocked THEN left(p_last_error, 128) ELSE NULL END
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND state.batch_generation = p_generation;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

-- Operator recovery for a permanently rejected batch. Not granted to the
-- exporter role: only the control-plane owner may clear a block.
CREATE FUNCTION public.nazo_unblock_security_audit_batch()
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    UPDATE public.security_audit_chain_state AS state
    SET batch_blocked_reason = NULL, batch_locked_until = NULL,
        batch_available_at = CURRENT_TIMESTAMP
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND state.batch_blocked_reason IS NOT NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

-- Cheap health projection: pending existence and oldest pending occurred_at
-- stay exact through the outbox ordering index; the backlog size is only an
-- estimate so the hot path never counts the whole outbox. The row shape
-- changes, so the function is replaced wholesale and EXECUTE is restored to
-- every role that held it.
DROP FUNCTION public.nazo_security_audit_shared_anchor_health();
CREATE FUNCTION public.nazo_security_audit_shared_anchor_health()
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

DROP FUNCTION public.nazo_claim_security_audit_events(BIGINT, INTEGER);
DROP FUNCTION public.nazo_ack_security_audit_event(UUID, INTEGER, TEXT);
DROP FUNCTION public.nazo_reschedule_security_audit_event(UUID, INTEGER, TIMESTAMPTZ, TEXT);

REVOKE ALL ON FUNCTION
    public.nazo_security_audit_chain_head_for_update(),
    public.nazo_security_audit_shared_anchor_health(),
    public.nazo_security_audit_batch_members(),
    public.nazo_claim_security_audit_pending(BIGINT),
    public.nazo_open_security_audit_batch(BIGINT, BIGINT, INTEGER, BYTEA, INTEGER),
    public.nazo_reclaim_security_audit_batch(BYTEA, INTEGER),
    public.nazo_ack_security_audit_batch(BIGINT, BIGINT, BIGINT, INTEGER, BYTEA, BYTEA, TEXT),
    public.nazo_fail_security_audit_batch(BIGINT, TIMESTAMPTZ, TEXT, BOOLEAN),
    public.nazo_unblock_security_audit_batch()
FROM PUBLIC;

-- The two DROPped functions lose their grants; restore them and grant the
-- new batch functions to the roles that held exporter privileges.
DO $$
DECLARE v_role RECORD;
BEGIN
    FOR v_role IN SELECT * FROM pg_temp.nazo_audit_upgrade_grants LOOP
        IF v_role.exporter THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_security_audit_chain_head_for_update(), public.nazo_security_audit_batch_members(), public.nazo_claim_security_audit_pending(BIGINT), public.nazo_open_security_audit_batch(BIGINT,BIGINT,INTEGER,BYTEA,INTEGER), public.nazo_reclaim_security_audit_batch(BYTEA,INTEGER), public.nazo_ack_security_audit_batch(BIGINT,BIGINT,BIGINT,INTEGER,BYTEA,BYTEA,TEXT), public.nazo_fail_security_audit_batch(BIGINT,TIMESTAMPTZ,TEXT,BOOLEAN), public.nazo_security_audit_shared_anchor_health() TO %I', v_role.rolname);
        END IF;
        IF v_role.writer THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_security_audit_shared_anchor_health() TO %I', v_role.rolname);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON TABLE public.security_audit_event_outbox IS
    'Pending export identities and their occurred_at ordering only; scheduling lives on the batch lease and acknowledgement deletes the row inside the anchor transaction.';
