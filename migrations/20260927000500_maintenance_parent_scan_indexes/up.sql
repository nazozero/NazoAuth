-- Order complete, bounded parent pages before checking child references.
-- Tiebreakers let keyset scans advance without re-sorting an expiry bucket.
CREATE INDEX ix_oauth_refresh_contract_scan
    ON oauth_refresh_contracts (created_at, tenant_id, contract_blake3);
CREATE INDEX ix_openid4vci_access_expiry_scan
    ON openid4vci_access_grants (expires_at, token_id);
DROP INDEX ix_openid4vci_access_expiry;
