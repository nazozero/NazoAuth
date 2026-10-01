-- A decision fact is simultaneously business authority and a pending audit
-- event. Export acknowledgement cannot erase its request/PAR consumption fence.
-- This migration requires coordinated activation after old prepared material
-- drains; old Valkey-only consumers cannot safely overlap the new writers.
ALTER TABLE public.security_audit_events
    ADD COLUMN authorization_tenant_id UUID,
    ADD COLUMN authorization_request_id TEXT,
    ADD COLUMN authorization_par_uri TEXT,
    ADD COLUMN authorization_decision TEXT,
    ADD COLUMN authorization_valid_until TIMESTAMPTZ,
    ADD COLUMN business_retain_until TIMESTAMPTZ,
    ADD COLUMN exported_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_security_audit_authorization_decision CHECK (
        CASE WHEN event_type = 'authorization_decision_committed' THEN
            authorization_tenant_id IS NOT NULL
            AND authorization_tenant_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND authorization_request_id IS NOT NULL
            AND octet_length(authorization_request_id) BETWEEN 1 AND 512
            AND (authorization_par_uri IS NULL OR octet_length(authorization_par_uri) BETWEEN 1 AND 1024)
            AND authorization_decision IS NOT NULL
            AND authorization_decision IN ('approve', 'deny', 'prompt_none')
            AND authorization_valid_until IS NOT NULL AND isfinite(authorization_valid_until)
            AND business_retain_until IS NOT NULL AND isfinite(business_retain_until)
            AND business_retain_until >= authorization_valid_until
            AND business_retain_until >= occurred_at
            AND event_category = 'authorization'
        ELSE
            authorization_tenant_id IS NULL AND authorization_request_id IS NULL
            AND authorization_par_uri IS NULL AND authorization_decision IS NULL
            AND authorization_valid_until IS NULL AND business_retain_until IS NULL
            AND exported_at IS NULL
        END
    );

-- Independent fences: changing the consent/request identity never frees a PAR.
CREATE UNIQUE INDEX idx_authorization_decision_request
    ON public.security_audit_events (authorization_tenant_id, authorization_request_id)
    WHERE event_type = 'authorization_decision_committed';
CREATE UNIQUE INDEX idx_authorization_decision_par
    ON public.security_audit_events (authorization_tenant_id, authorization_par_uri)
    WHERE event_type = 'authorization_decision_committed' AND authorization_par_uri IS NOT NULL;
DROP INDEX public.idx_security_audit_events_pending_order;
CREATE INDEX idx_security_audit_events_pending_order
    ON public.security_audit_events (occurred_at, event_id) WHERE exported_at IS NULL;
CREATE INDEX idx_authorization_decision_reclaim
    ON public.security_audit_events (business_retain_until, event_id)
    WHERE event_type = 'authorization_decision_committed' AND exported_at IS NOT NULL;

-- The caller holds the same transaction open while validating prompt-none
-- coverage with the core's canonical policy under a SHARE lock on the grant.
-- This function owns the durable fact plus explicit-grant mutation. Principals
-- are rechecked/locked here too, so neither deactivation nor deletion can race
-- the final effect. Payload authority fields always override caller extras.
CREATE FUNCTION public.nazo_commit_authorization_decision(
    p_tenant_id UUID, p_user_id UUID, p_client_id TEXT,
    p_request_id TEXT, p_par_uri TEXT, p_valid_until TIMESTAMPTZ,
    p_retain_until TIMESTAMPTZ, p_decision TEXT, p_event_id UUID,
    p_occurred_at TIMESTAMPTZ, p_audit_fields JSONB, p_scopes JSONB,
    p_resources JSONB, p_authorization_details JSONB
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_client_id UUID;
    v_active BOOLEAN;
    v_payload JSONB;
    v_inserted INTEGER;
    v_digest_key TEXT;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_user_id IS NULL OR p_user_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_event_id IS NULL OR p_event_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_client_id IS NULL OR octet_length(p_client_id) NOT BETWEEN 1 AND 512
       OR p_request_id IS NULL OR octet_length(p_request_id) NOT BETWEEN 1 AND 512
       OR (p_par_uri IS NOT NULL AND octet_length(p_par_uri) NOT BETWEEN 1 AND 1024)
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'deny', 'prompt_none')
       OR p_valid_until IS NULL OR NOT isfinite(p_valid_until)
       OR p_retain_until IS NULL OR NOT isfinite(p_retain_until)
       OR p_occurred_at IS NULL OR NOT isfinite(p_occurred_at)
       OR p_retain_until < p_valid_until OR p_retain_until < p_occurred_at
       OR jsonb_typeof(p_audit_fields) IS DISTINCT FROM 'object'
       OR jsonb_typeof(p_scopes) IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_resources) IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_authorization_details) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid authorization decision';
    END IF;
    IF p_decision IN ('approve', 'prompt_none') AND (
        jsonb_typeof(p_audit_fields -> 'code_id') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_id', '') = ''
        OR jsonb_typeof(p_audit_fields -> 'code_hash') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_hash', '') !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(p_audit_fields -> 'code_payload_digest') IS DISTINCT FROM 'string'
        OR COALESCE(p_audit_fields ->> 'code_payload_digest', '') !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'authorization code binding is missing or invalid';
    END IF;
    IF p_decision = 'deny' AND p_audit_fields ?| ARRAY['code_id', 'code_hash', 'code_payload_digest'] THEN
        RAISE EXCEPTION 'denial cannot bind an authorization code';
    END IF;
    -- Digest preparation belongs to the Rust adapter (BLAKE3); validate their
    -- shape here. Export only this allowlist: raw request/PAR handles live in
    -- the fence columns, and full resources/details live in the grant alone.
    IF COALESCE(p_audit_fields ->> 'request_id_hash', '') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'authorization request digest is missing or invalid';
    END IF;
    FOREACH v_digest_key IN ARRAY ARRAY[
        'request_id_hash', 'source_ip_hash', 'resource_digest',
        'authorization_details_digest', 'pushed_request_digest', 'pushed_request_uri_hash'
    ] LOOP
        IF p_audit_fields ? v_digest_key AND (
            jsonb_typeof(p_audit_fields -> v_digest_key) IS DISTINCT FROM 'string'
            OR (p_audit_fields ->> v_digest_key) !~ '^[0-9a-f]{64}$'
        ) THEN
            RAISE EXCEPTION 'authorization audit digest is invalid';
        END IF;
    END LOOP;
    v_payload := jsonb_strip_nulls(jsonb_build_object(
        'schema_version', 'nazo.audit.v1', 'event_category', 'authorization',
        'tenant_id', p_tenant_id, 'user_id', p_user_id, 'client_id', p_client_id,
        'decision', p_decision, 'valid_until', p_valid_until, 'retain_until', p_retain_until,
        'scope', (SELECT string_agg(scope.value, ' ' ORDER BY scope.position)
                  FROM jsonb_array_elements_text(p_scopes) WITH ORDINALITY AS scope(value, position)),
        'request_id_hash', p_audit_fields -> 'request_id_hash',
        'source_ip_hash', p_audit_fields -> 'source_ip_hash',
        'resource_digest', p_audit_fields -> 'resource_digest',
        'authorization_details_digest', p_audit_fields -> 'authorization_details_digest',
        'pushed_request_digest', p_audit_fields -> 'pushed_request_digest',
        'pushed_request_uri_hash', p_audit_fields -> 'pushed_request_uri_hash',
        'code_id', p_audit_fields -> 'code_id',
        'code_hash', p_audit_fields -> 'code_hash',
        'code_payload_digest', p_audit_fields -> 'code_payload_digest'
    ));
    IF octet_length(convert_to(v_payload::TEXT, 'UTF8')) > 65536 THEN
        RAISE EXCEPTION 'authorization decision payload is too large';
    END IF;
    SELECT client.id, client.is_active INTO v_client_id, v_active
    FROM public.oauth_clients AS client
    WHERE client.tenant_id = p_tenant_id AND client.client_id = p_client_id
    FOR SHARE OF client;
    IF NOT FOUND OR NOT v_active THEN RETURN 'client_unavailable'; END IF;
    SELECT actor.is_active INTO v_active FROM public.users AS actor
    WHERE actor.tenant_id = p_tenant_id AND actor.id = p_user_id
    FOR SHARE OF actor;
    IF NOT FOUND OR NOT v_active THEN RETURN 'client_unavailable'; END IF;
    -- Both explicit approval and prompt-none lock an existing grant BEFORE
    -- claiming either unique fence. The opposite order can deadlock when an
    -- approval holds the PAR fence while waiting for prompt-none's grant lock.
    IF p_decision = 'approve' THEN
        PERFORM 1 FROM public.user_client_grants AS grant_row
        WHERE grant_row.tenant_id = p_tenant_id AND grant_row.user_id = p_user_id
          AND grant_row.client_id = v_client_id
        FOR UPDATE OF grant_row;
    END IF;
    IF clock_timestamp() >= p_valid_until THEN RETURN 'expired'; END IF;

    -- The exception block is a subtransaction: a deadline that passes while
    -- awaiting a unique/grant lock rolls back BOTH the fact and grant mutation.
    BEGIN
        INSERT INTO public.security_audit_events (
            event_id, event_type, event_category, payload, occurred_at,
            authorization_tenant_id, authorization_request_id, authorization_par_uri,
            authorization_decision, authorization_valid_until, business_retain_until
        ) VALUES (
            p_event_id, 'authorization_decision_committed', 'authorization', v_payload, p_occurred_at,
            p_tenant_id, p_request_id, p_par_uri, p_decision, p_valid_until, p_retain_until
        ) ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 0 THEN RETURN 'conflict'; END IF;
        IF p_decision = 'approve' THEN
            INSERT INTO public.user_client_grants (
                tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,
                last_scopes, last_resource_indicators, last_authorization_details, authorization_count
            ) VALUES (
                p_tenant_id, p_user_id, v_client_id, p_occurred_at, p_occurred_at,
                p_scopes, p_resources, p_authorization_details, 1
            ) ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE SET
                last_authorized_at = EXCLUDED.last_authorized_at,
                last_scopes = EXCLUDED.last_scopes,
                last_resource_indicators = EXCLUDED.last_resource_indicators,
                last_authorization_details = EXCLUDED.last_authorization_details,
                authorization_count = public.user_client_grants.authorization_count + 1;
        END IF;
        IF clock_timestamp() >= p_valid_until THEN
            RAISE EXCEPTION 'authorization decision expired during commit' USING ERRCODE = 'PZA01';
        END IF;
        RETURN 'committed';
    EXCEPTION WHEN SQLSTATE 'PZA01' THEN
        RETURN 'expired';
    END;
END;
$$;
REVOKE ALL ON FUNCTION public.nazo_commit_authorization_decision(
    UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT,
    UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB
) FROM PUBLIC;

-- Grant mutation is the only producer of the reserved authority event.


CREATE OR REPLACE FUNCTION public.nazo_persist_security_audit_event(
    p_event_id UUID, p_event_type TEXT, p_event_category TEXT,
    p_payload JSONB, p_occurred_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_inserted INTEGER;
BEGIN
    IF p_event_type = 'authorization_decision_committed' THEN
        RAISE EXCEPTION 'authorization decision requires its atomic commit API';
    END IF;
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
    RETURN TRUE;
END;
$$;

-- Only ACK may change NULL exported_at to a timestamp. Every other column,
-- including future columns, must remain byte-for-byte equal as JSON values.
-- DELETE of a decision additionally requires both completed export and elapsed
-- business retention; the GUC never relaxes that authority lifetime.
CREATE OR REPLACE FUNCTION public.nazo_reject_security_audit_event_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'security_audit_events' THEN
        IF current_setting('nazo.audit_ack', true) IS NOT DISTINCT FROM 'on'
           AND OLD.event_type = 'authorization_decision_committed'
           AND OLD.exported_at IS NULL AND NEW.exported_at IS NOT NULL
           AND isfinite(NEW.exported_at)
           AND (to_jsonb(OLD) - 'exported_at') = (to_jsonb(NEW) - 'exported_at')
           AND convert_to(OLD.payload::TEXT, 'UTF8') = convert_to(NEW.payload::TEXT, 'UTF8') THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' AND current_setting('nazo.audit_reclaim', true) IS NOT DISTINCT FROM 'on' THEN
        IF TG_TABLE_NAME = 'security_audit_events' THEN
            IF OLD.event_type = 'authorization_decision_committed'
               AND (OLD.exported_at IS NULL OR OLD.business_retain_until > clock_timestamp()) THEN
                RAISE EXCEPTION 'authorization decision still owns a live consumption fence';
            END IF;
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security audit ledger is append-only';
END;
$$;


CREATE OR REPLACE FUNCTION public.nazo_security_audit_batch_members()
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
    JOIN public.security_audit_events AS event ON event.event_id = chain.event_id
    WHERE state.singleton AND state.batch_last_sequence IS NOT NULL
      AND event.exported_at IS NULL
    ORDER BY chain.sequence
$$;

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
        WHERE candidate.event_id = chained.event_id AND candidate.exported_at IS NULL
        LIMIT 1
    ) AS event
    ORDER BY chained.sequence;
    GET DIAGNOSTICS v_claimed = ROW_COUNT;
    IF v_claimed > 0 THEN RETURN; END IF;
    -- Only unexported rows participate; retained business facts are not pending.
    -- Read full rows directly through the ordered index. A bounded ID CTE
    -- followed by a self-join adds no information and can scan the backlog.
    RETURN QUERY
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM public.security_audit_events AS event
    WHERE event.exported_at IS NULL
    ORDER BY event.occurred_at, event.event_id
    LIMIT p_limit;
END;
$$;

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
    UPDATE public.security_audit_chain_state SET last_sequence = v_sequence, last_hash = v_hash
    WHERE singleton;
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
    v_retained INTEGER;
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
        SELECT EXISTS (SELECT 1 FROM public.security_audit_events WHERE exported_at IS NULL) AS pending_exists,
               (SELECT event.occurred_at FROM public.security_audit_events AS event
                WHERE event.exported_at IS NULL
                ORDER BY event.occurred_at, event.event_id LIMIT 1) AS oldest_pending_occurred_at,
               EXISTS (
                   SELECT 1 FROM public.security_audit_chain_entries AS chain
                   WHERE chain.sequence <= COALESCE(
                       (SELECT state.anchor_sequence FROM public.security_audit_chain_state AS state
                        WHERE state.singleton), -1)
               ) AS pending_orphan_exists,
               GREATEST(relation.reltuples, 0)::BIGINT AS pending_estimate
        FROM pg_class AS relation
        WHERE relation.oid = 'public.idx_security_audit_events_pending_order'::REGCLASS
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

-- Bounded business-authority reclamation. An exporter outage never releases
-- a consumption fence, irrespective of how old its original request becomes.
CREATE FUNCTION public.nazo_cleanup_authorization_decisions() RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_deleted BIGINT;
BEGIN
    PERFORM set_config('nazo.audit_reclaim', 'on', true);
    WITH due AS MATERIALIZED (
        SELECT event.event_id FROM public.security_audit_events AS event
        WHERE event.event_type = 'authorization_decision_committed'
          AND event.exported_at IS NOT NULL
          AND event.business_retain_until <= CURRENT_TIMESTAMP
        ORDER BY event.business_retain_until, event.event_id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.security_audit_events AS event USING due
    WHERE event.event_id = due.event_id
      AND event.exported_at IS NOT NULL
      AND event.business_retain_until <= CURRENT_TIMESTAMP;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    PERFORM set_config('nazo.audit_reclaim', 'off', true);
    RETURN v_deleted;
END;
$$;
REVOKE ALL ON FUNCTION public.nazo_cleanup_authorization_decisions() FROM PUBLIC;

-- Existing application writers receive the domain commit and bounded cleanup
-- APIs only if they already own the underlying grant-mutation capabilities.
-- An audit-only append role must never acquire business authority implicitly.
-- No direct audit-table privilege is added, and no exporter API expands.
DO $$
DECLARE v_role RECORD;
BEGIN
    FOR v_role IN
        SELECT DISTINCT role.rolname
        FROM pg_proc AS proc
        CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
        JOIN pg_roles AS role ON role.oid = acl.grantee
        WHERE proc.oid = 'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE
          AND acl.privilege_type = 'EXECUTE' AND acl.grantee <> proc.proowner
          AND has_table_privilege(role.oid, 'public.users', 'SELECT')
          AND has_table_privilege(role.oid, 'public.oauth_clients', 'SELECT')
          AND has_table_privilege(role.oid, 'public.user_client_grants', 'INSERT')
          AND has_table_privilege(role.oid, 'public.user_client_grants', 'UPDATE')
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_commit_authorization_decision(UUID,UUID,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,UUID,TIMESTAMPTZ,JSONB,JSONB,JSONB,JSONB), public.nazo_cleanup_authorization_decisions() TO %I', v_role.rolname);
    END LOOP;
END $$;
COMMENT ON TABLE public.security_audit_events IS
    'Canonical immutable audit facts and pending deliveries. Authorization decisions remain after ACK until business retention expires; other events leave at ACK.';
