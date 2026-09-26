-- Refresh-contract reference in one narrow database operation: an existing
-- (tenant_id, contract_blake3) key is safely referenced with a transaction-
-- scoped FOR KEY SHARE row lock instead of re-running the speculative
-- INSERT; a missing key takes the original validated INSERT and a genuine
-- create/reclaim race loops back to the safe reference. Bounded per call;
-- the caller's transaction keeps the lock so the families' foreign key can
-- never dangle.
--
-- SECURITY INVOKER is deliberate: the runtime role holds the refresh tables'
-- DML, and no least-privilege boundary exists here (unlike the audit API).
CREATE FUNCTION public.nazo_oauth_refresh_contract_ensure(
    p_tenant_id UUID, p_contract_blake3 BYTEA, p_contract JSONB
) RETURNS VOID
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_inserted INTEGER;
    v_marker INTEGER;
BEGIN
    IF p_tenant_id IS NULL OR p_contract_blake3 IS NULL
       OR octet_length(p_contract_blake3) <> 32 OR p_contract IS NULL THEN
        RAISE EXCEPTION 'refresh contract reference arguments are invalid';
    END IF;
    FOR attempt IN 1..3 LOOP
        SELECT 1 INTO v_marker FROM public.oauth_refresh_contracts AS contract
        WHERE contract.tenant_id = p_tenant_id
          AND contract.contract_blake3 = p_contract_blake3
        FOR KEY SHARE OF contract;
        IF FOUND THEN RETURN; END IF;
        INSERT INTO public.oauth_refresh_contracts (tenant_id, contract_blake3, contract)
        VALUES (p_tenant_id, p_contract_blake3, p_contract)
        ON CONFLICT (tenant_id, contract_blake3) DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 1 THEN RETURN; END IF;
        -- A genuine create/reclaim race on this key: loop back to acquire the
        -- safe reference instead of retrying the whole OAuth request.
    END LOOP;
    RAISE EXCEPTION 'oauth refresh contract could not be safely referenced';
END;
$$;

COMMENT ON FUNCTION public.nazo_oauth_refresh_contract_ensure(UUID, BYTEA, JSONB) IS
    'Single-call contract reference: FOR KEY SHARE on an existing key, validated INSERT on a missing key, bounded retry on a create/reclaim race.';
