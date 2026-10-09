-- Bounded terminal-family cleanup scans revoked families by revocation time.
CREATE INDEX ix_orf_revoked_cleanup
    ON oauth_refresh_families (revoked_at, tenant_id, token_family_id)
    WHERE revoked_at IS NOT NULL;
