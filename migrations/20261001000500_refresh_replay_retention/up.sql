-- Unbound public clients must keep every unexpired rotation relationship.
-- Earlier releases may already have deleted these opaque-token proofs; their
-- absence cannot prove a family safe. One-time revocation establishes the new
-- guarantee without pretending lost history can be reconstructed.
-- Run transactionally before admitting traffic from the new release. The
-- client-first lock order matches token issuance's principal -> family order.
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
          AND family.dpop_jkt IS NULL AND family.mtls_x5t_s256 IS NULL
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
                'reason', 'public_replay_retention_cutover',
                'migration', '20261001000500'
            ), v_occurred_at
        );
    END LOOP;
END;
$$;

-- Adapter implementation of the client-mutation port's atomic downgrade
-- contract. OLD/NEW avoid a second lookup and cover every update/upsert writer.
-- UPDATE already owns the client row lock; issuance takes FOR SHARE on that
-- same row before touching a family. A winning issuance can finish, after
-- which this mutation revokes its successor; a winning mutation prevents an
-- old source from committing. Family row locks fence maintenance/revocation.
CREATE FUNCTION public.nazo_revoke_refresh_on_client_public()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_family RECORD;
    v_occurred_at TIMESTAMPTZ := CURRENT_TIMESTAMP;
BEGIN
    FOR v_family IN
        UPDATE public.oauth_refresh_families AS family
        SET revoked_at = v_occurred_at
        WHERE family.tenant_id = NEW.tenant_id AND family.client_id = NEW.id
          AND family.revoked_at IS NULL
        RETURNING family.token_family_id
    LOOP
        -- Required evidence shares the client UPDATE transaction. An audit
        -- failure rolls back the class change and every family revocation.
        PERFORM public.nazo_persist_security_audit_event(
            gen_random_uuid(), 'refresh_family_security_revoked', 'token_lifecycle',
            jsonb_build_object(
                'schema_version', 'nazo.audit.v1',
                'tenant_id', NEW.tenant_id,
                'token_family_id', v_family.token_family_id,
                'client_id', NEW.id,
                'event_category', 'token_lifecycle',
                'reason', 'client_authentication_class_downgrade'
            ), v_occurred_at
        );
    END LOOP;
    RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_client_public_refresh_invalidation
AFTER UPDATE OF client_type ON public.oauth_clients
FOR EACH ROW
WHEN (OLD.client_type = 'confidential' AND NEW.client_type = 'public')
EXECUTE FUNCTION public.nazo_revoke_refresh_on_client_public();

COMMENT ON TABLE public.oauth_refresh_spent_tokens IS
    'Minimal reuse/lost-response proofs without authorization payload. Unbound public families retain every unexpired proof; confidential or DPoP/mTLS-bound families retain at most the newest 64. All proofs expire at their original token expiry or with family retirement.';
