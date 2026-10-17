-- New-family keys and payloads are produced together by persisted_contract.
-- Reuse the content-addressed row without fetching/serializing its JSON again.
-- KEY SHARE still fences orphan reclamation until the family INSERT commits;
-- table constraints own validation of a newly inserted row.
CREATE OR REPLACE FUNCTION public.nazo_oauth_refresh_contract_ensure(
    p_tenant_id UUID, p_contract_blake3 BYTEA, p_contract JSONB
) RETURNS VOID
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_inserted INTEGER;
BEGIN
    FOR attempt IN 1..3 LOOP
        PERFORM 1 FROM public.oauth_refresh_contracts AS contract
        WHERE contract.tenant_id = p_tenant_id
          AND contract.contract_blake3 = p_contract_blake3
        FOR KEY SHARE OF contract;
        IF FOUND THEN RETURN; END IF;
        INSERT INTO public.oauth_refresh_contracts (tenant_id, contract_blake3, contract)
        VALUES (p_tenant_id, p_contract_blake3, p_contract)
        ON CONFLICT (tenant_id, contract_blake3) DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 1 THEN RETURN; END IF;
        -- A concurrent creator or reclaimer changed the row; obtain its lock
        -- or create the missing row in the next statement snapshot.
    END LOOP;
    RAISE EXCEPTION 'oauth refresh contract could not be safely referenced';
END;
$$;

COMMENT ON FUNCTION public.nazo_oauth_refresh_contract_ensure(UUID, BYTEA, JSONB) IS
    'Content-addressed contract reference with KEY SHARE reclamation protection and bounded create/reclaim retry.';
