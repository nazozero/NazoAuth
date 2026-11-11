-- Earlier public refresh rotations may already have extended the original
-- deadline, which cannot be reconstructed after spent proofs expire. Retire
-- those families before admitting writers with the fixed deadline policy.
LOCK TABLE public.oauth_clients IN EXCLUSIVE MODE;
LOCK TABLE public.oauth_refresh_families IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    v_family RECORD;
    v_occurred_at TIMESTAMPTZ := CURRENT_TIMESTAMP;
BEGIN
    FOR v_family IN
        UPDATE public.oauth_refresh_families AS family
        SET revoked_at = v_occurred_at
        FROM public.oauth_clients AS client
        WHERE client.tenant_id = family.tenant_id AND client.id = family.client_id
          AND client.client_type = 'public'
          AND family.revoked_at IS NULL
        RETURNING family.tenant_id, family.token_family_id, family.client_id
    LOOP
        PERFORM public.nazo_persist_security_audit_event(
            gen_random_uuid(), 'refresh_family_security_revoked', 'token_lifecycle',
            jsonb_build_object(
                'schema_version', 'nazo.audit.v1',
                'tenant_id', v_family.tenant_id,
                'token_family_id', v_family.token_family_id,
                'client_id', v_family.client_id,
                'event_category', 'token_lifecycle',
                'reason', 'public_refresh_deadline_cutover',
                'migration', '20261111000100'
            ), v_occurred_at
        );
    END LOOP;
END;
$$;
