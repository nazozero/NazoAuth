-- Dropping the function and index stops future outbox reclamation. Delivery
-- rows already deleted cannot be restored; that is the intent of the
-- retention change and matches how other cleanup downgrades keep no backup.
DROP FUNCTION IF EXISTS public.nazo_cleanup_exported_security_audit_outbox();
DROP INDEX IF EXISTS public.idx_security_audit_outbox_exported;
