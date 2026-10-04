-- The approval points to its canonical outcome; no second audit copy/outbox.
-- Existing approvals lack this evidence and cannot activate a staged secret.
ALTER TABLE public.client_access_requests
    ADD COLUMN required_approval_event_id uuid
        REFERENCES public.security_audit_events(event_id) ON DELETE SET NULL,
    ADD CONSTRAINT ck_access_request_required_approval
        CHECK (required_approval_event_id IS NULL OR status = 1);
CREATE INDEX ix_access_request_required_approval_event
    ON public.client_access_requests(required_approval_event_id)
    WHERE required_approval_event_id IS NOT NULL;

-- A business-specific boolean capability: caller cannot select an audit event,
-- list payloads, or bypass current client/request/secret-generation predicates.
CREATE FUNCTION public.nazo_access_request_required_approval_matches(
    p_tenant_id uuid, p_user_id uuid, p_request_id uuid,
    p_client_id uuid, p_public_client_id text, p_secret_binding text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.client_access_requests AS request
        JOIN public.oauth_clients AS client
          ON client.id = request.approved_client_id AND client.tenant_id = request.tenant_id
        JOIN public.security_audit_events AS event
          ON event.event_id = request.required_approval_event_id
        WHERE request.tenant_id = p_tenant_id AND request.user_id = p_user_id
          AND request.id = p_request_id AND request.status = 1
          AND client.id = p_client_id AND client.client_id = p_public_client_id
          AND client.is_active AND client.client_secret_hash IS NOT DISTINCT FROM p_secret_binding
          AND event.event_type = 'client_created' AND event.event_category = 'client_lifecycle'
          AND event.payload->>'tenant_id' = request.tenant_id::text
          AND event.payload->>'request_id' = request.id::text
          AND event.payload->>'request_user_id' = request.user_id::text
          AND event.payload->>'admin_user_id' = request.resolved_by_user_id::text
          AND event.payload->>'approved_client_id' = client.id::text
          AND event.payload->>'client_id' = client.client_id
          AND event.payload->>'outcome' = 'success'
    );
$$;
REVOKE ALL ON FUNCTION public.nazo_access_request_required_approval_matches(uuid,uuid,uuid,uuid,text,text) FROM PUBLIC;
DO $$
DECLARE writer record;
BEGIN
    FOR writer IN SELECT rolname FROM pg_roles WHERE has_function_privilege(
        oid, 'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::regprocedure, 'EXECUTE')
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.nazo_access_request_required_approval_matches(uuid,uuid,uuid,uuid,text,text) TO %I', writer.rolname);
    END LOOP;
END;
$$;
