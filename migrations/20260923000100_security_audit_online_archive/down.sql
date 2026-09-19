DROP FUNCTION public.nazo_archive_security_audit_prefix(BIGINT, TIMESTAMPTZ);

-- Restore the unconditional append-only guard.
CREATE OR REPLACE FUNCTION public.nazo_reject_security_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'security audit ledger is append-only';
END;
$$;

DROP TABLE public.security_audit_archive_state;
DROP TABLE public.security_audit_archive;
