-- Restoring this foreign key is possible only while every referenced event
-- is still present. Do not erase durable approval markers to force downgrade;
-- after audit reclamation use a matching backup instead.
ALTER TABLE public.client_access_requests
    ADD CONSTRAINT client_access_requests_required_approval_event_id_fkey
    FOREIGN KEY (required_approval_event_id)
    REFERENCES public.security_audit_events(event_id) ON DELETE SET NULL;
CREATE INDEX ix_access_request_required_approval_event
    ON public.client_access_requests(required_approval_event_id)
    WHERE required_approval_event_id IS NOT NULL;
COMMENT ON COLUMN public.client_access_requests.required_approval_event_id IS NULL;

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
