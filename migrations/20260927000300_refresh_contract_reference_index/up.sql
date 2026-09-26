-- The orphan sweep probes this key for each candidate contract.
CREATE INDEX idx_oauth_refresh_families_contract
    ON oauth_refresh_families (tenant_id, contract_blake3);
