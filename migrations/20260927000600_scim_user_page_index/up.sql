-- Match the tenant filter and deterministic SCIM/admin user page order.
-- Keep ix_users_tenant_id: exact tenant-wide counts still benefit from its
-- narrower entries; replacing that path requires a separate plan comparison.
CREATE INDEX ix_users_tenant_created_at_id
    ON users (tenant_id, created_at, id);
