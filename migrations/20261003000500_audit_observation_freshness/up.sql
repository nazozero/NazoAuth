-- Every successful worker observation records its real completion time.
-- Background poll cadence owns this write; request admission adds no heartbeat.
-- Replacing the existing signature preserves its owner and role grants.
CREATE OR REPLACE FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    -- Sample observation time after the shared row lock has been acquired.
    -- Wrong deployment identity cannot lock an observation into another owner.
    PERFORM 1 FROM public.security_audit_chain_state
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id)
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = COALESCE(anchor_deployment_id, p_deployment_id),
        anchor_observed_at = clock_timestamp()
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    RETURN FOUND;
END;
$$;
