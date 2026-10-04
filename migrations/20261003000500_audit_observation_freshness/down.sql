-- Restore the previous observation write throttle on explicit downgrade.
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
