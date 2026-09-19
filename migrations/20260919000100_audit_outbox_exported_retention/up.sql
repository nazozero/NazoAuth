-- Exported audit-outbox delivery rows are bookkeeping for the exporter, not
-- evidence: the immutable security_audit_events record stays. Without
-- reclamation the outbox grows by one row per audited event forever.
--
-- nazo_cleanup_exported_security_audit_outbox() deletes delivery rows whose
-- export is older than a short observability grace period (1 day), bounded to
-- 256 rows per call like the other security-state cleanup categories.
-- Pending, locked or rescheduled rows are never touched.
--
-- The function is SECURITY DEFINER owned by the migration owner because
-- runtime roles hold no direct privilege on audit-ledger tables; the role
-- provisioning in persistence-postgres grants EXECUTE to the runtime role.

CREATE INDEX IF NOT EXISTS idx_security_audit_outbox_exported
    ON public.security_audit_event_outbox (exported_at, event_id)
    WHERE exported_at IS NOT NULL;

CREATE FUNCTION public.nazo_cleanup_exported_security_audit_outbox()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    WITH due AS (
        SELECT event_id
        FROM public.security_audit_event_outbox
        WHERE exported_at IS NOT NULL
          AND exported_at <= clock_timestamp() - INTERVAL '1 day'
        ORDER BY exported_at, event_id
        LIMIT 256 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.security_audit_event_outbox AS target
    USING due
    WHERE target.event_id = due.event_id;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

REVOKE ALL ON FUNCTION public.nazo_cleanup_exported_security_audit_outbox()
FROM PUBLIC;

COMMENT ON FUNCTION public.nazo_cleanup_exported_security_audit_outbox() IS
    'Bounded reclaim of exported audit-outbox delivery rows past the 1-day observability grace; evidence lives in security_audit_events.';
