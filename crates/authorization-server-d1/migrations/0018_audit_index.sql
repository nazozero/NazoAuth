-- The grant-activity backfill in 0009 is complete. Current grant statistics
-- read nazo_grant_activity; their write triggers look up audit events by key.
DROP INDEX IF EXISTS nazo_audit_authorizations;
