DROP INDEX oauth_token_issuances_single_use_key_idx;
CREATE UNIQUE INDEX oauth_token_issuances_single_use_key_idx
    ON oauth_token_issuances (tenant_id, client_id, single_use_key_blake3)
    WHERE single_use_key_blake3 IS NOT NULL;
