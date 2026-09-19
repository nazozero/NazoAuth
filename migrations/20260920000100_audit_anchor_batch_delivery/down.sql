-- Restore per-event delivery scheduling. An in-flight batch is unfolded
-- back into per-row locked claims so the retired protocol can resume.

CREATE TEMP TABLE nazo_audit_downgrade_grants ON COMMIT DROP AS
SELECT role.rolname,
       bool_or(proc.proname = 'nazo_persist_security_audit_event') AS writer,
       bool_or(proc.proname = 'nazo_claim_security_audit_pending'
            OR proc.proname = 'nazo_reclaim_security_audit_batch') AS exporter
FROM pg_proc AS proc
JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
JOIN pg_roles AS role ON role.oid = acl.grantee
WHERE namespace.nspname = 'public'
  AND proc.proname IN ('nazo_persist_security_audit_event', 'nazo_claim_security_audit_pending',
                       'nazo_reclaim_security_audit_batch')
  AND acl.privilege_type = 'EXECUTE' AND acl.grantee <> proc.proowner
GROUP BY role.rolname;

DROP FUNCTION public.nazo_unblock_security_audit_batch();
DROP FUNCTION public.nazo_fail_security_audit_batch(BIGINT, TIMESTAMPTZ, TEXT, BOOLEAN);
DROP FUNCTION public.nazo_ack_security_audit_batch(BIGINT, BIGINT, BIGINT, INTEGER, BYTEA, BYTEA, TEXT);
DROP FUNCTION public.nazo_reclaim_security_audit_batch(BYTEA, INTEGER);
DROP FUNCTION public.nazo_open_security_audit_batch(BIGINT, BIGINT, INTEGER, BYTEA, INTEGER);
DROP FUNCTION public.nazo_claim_security_audit_pending(BIGINT);
DROP FUNCTION public.nazo_security_audit_batch_members();
DROP FUNCTION public.nazo_security_audit_shared_anchor_health();
DROP FUNCTION public.nazo_security_audit_chain_head_for_update();

ALTER TABLE public.security_audit_event_outbox
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN locked_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT,
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT ck_security_audit_outbox_attempts_non_negative CHECK (attempts >= 0);

-- Mark the still-committed batch members as claimed at their lease deadline
-- so the old claim path redelivers them instead of double-exporting.
UPDATE public.security_audit_event_outbox AS outbox
SET attempts = 1,
    locked_at = state.batch_locked_until,
    available_at = COALESCE(state.batch_available_at, CURRENT_TIMESTAMP),
    last_error = state.batch_last_error,
    created_at = outbox.occurred_at
FROM public.security_audit_chain_state AS state
JOIN public.security_audit_chain_entries AS chain
  ON chain.sequence > COALESCE(state.anchor_sequence, 0)
 AND chain.sequence <= state.batch_last_sequence
WHERE state.singleton AND chain.event_id = outbox.event_id;

ALTER TABLE public.security_audit_event_outbox DROP COLUMN occurred_at;
CREATE INDEX idx_security_audit_outbox_due
    ON public.security_audit_event_outbox (available_at, created_at);

ALTER TABLE public.security_audit_chain_state
    DROP COLUMN batch_first_sequence, DROP COLUMN batch_last_sequence,
    DROP COLUMN batch_event_count, DROP COLUMN batch_digest,
    DROP COLUMN batch_generation, DROP COLUMN batch_attempts,
    DROP COLUMN batch_available_at, DROP COLUMN batch_locked_until,
    DROP COLUMN batch_last_error, DROP COLUMN batch_blocked_reason;

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
    INSERT INTO public.security_audit_event_outbox (event_id) VALUES (p_event_id);
    RETURN TRUE;
END;
$$;

CREATE FUNCTION public.nazo_security_audit_chain_head_for_update()
RETURNS TABLE(last_sequence BIGINT, last_hash BYTEA)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT state.last_sequence, state.last_hash
    FROM public.security_audit_chain_state AS state WHERE state.singleton FOR UPDATE
$$;

CREATE FUNCTION public.nazo_claim_security_audit_events(p_limit BIGINT, p_lock_timeout_seconds INTEGER)
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

CREATE FUNCTION public.nazo_ack_security_audit_event(
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

CREATE FUNCTION public.nazo_reschedule_security_audit_event(
    p_event_id UUID, p_expected_attempts INTEGER, p_available_at TIMESTAMPTZ, p_last_error TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_available_at IS NULL
       OR p_available_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes'
       OR p_last_error IS NULL OR char_length(p_last_error) > 128 THEN
        RAISE EXCEPTION 'audit outbox reschedule bounds are invalid';
    END IF;
    UPDATE public.security_audit_event_outbox AS outbox
    SET locked_at = NULL, available_at = p_available_at, last_error = left(p_last_error, 128),
        updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id AND outbox.attempts = p_expected_attempts;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_security_audit_shared_anchor_health()
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

CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN, p_require_append BOOLEAN, p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (NOT COALESCE(p_require_append, FALSE) OR has_function_privilege(session_user,
        'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE, 'EXECUTE'))
    AND (NOT COALESCE(p_require_exporter, FALSE) OR (
        has_function_privilege(session_user, 'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_claim_security_audit_events(bigint,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_ack_security_audit_event(uuid,integer,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reschedule_security_audit_event(uuid,integer,timestamptz,text)'::REGPROCEDURE, 'EXECUTE')
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

DO $$
DECLARE v_role RECORD;
BEGIN
    FOR v_role IN SELECT * FROM pg_temp.nazo_audit_downgrade_grants LOOP
        IF v_role.exporter THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_security_audit_chain_head_for_update(), public.nazo_claim_security_audit_events(BIGINT,INTEGER), public.nazo_append_security_audit_chain(BIGINT,BYTEA,UUID[],BYTEA[]), public.nazo_ack_security_audit_event(UUID,INTEGER,TEXT), public.nazo_observe_security_audit_anchor(TEXT), public.nazo_record_security_audit_genesis(TEXT,BYTEA), public.nazo_reschedule_security_audit_event(UUID,INTEGER,TIMESTAMPTZ,TEXT), public.nazo_security_audit_shared_anchor_health() TO %I', v_role.rolname);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON TABLE public.security_audit_event_outbox IS
    'Delivery bookkeeping for pending export only; the acknowledgement transaction deletes the row while advancing the durable anchor checkpoint.';
