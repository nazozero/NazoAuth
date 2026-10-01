-- Schema rollback does not restore revoked credentials. The one-time public
-- cutover and client-authentication downgrade revocations are irreversible
-- security decisions; preserve revoked_at, all rows and their audit evidence.
DROP TRIGGER IF EXISTS oauth_client_public_refresh_invalidation ON public.oauth_clients;
DROP FUNCTION IF EXISTS public.nazo_revoke_refresh_on_client_public();
-- Deliberately no UPDATE of refresh authority and no deletion of audit events.
-- Rolling application code back also forfeits the new public retention
-- guarantee; do not resume public refresh traffic with the older writer.
