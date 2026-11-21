-- The native repository permits one pending request per tenant and user.
-- Existing duplicates intentionally make this migration fail: only an
-- authorized reviewer may resolve an application, never schema backfill.
CREATE UNIQUE INDEX IF NOT EXISTS nazo_access_requests_tenant_user_pending
ON nazo_access_requests(tenant_id,user_id) WHERE status=0;
