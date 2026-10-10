-- oauth_clients.id is globally unique. The existing (client_id, tenant_id)
-- foreign key binds each receipt to that client's tenant, so repeating the
-- tenant in the one-use key adds storage without another uniqueness fact.
-- Tenant predicates and the composite foreign key remain unchanged.
DROP INDEX oauth_token_issuances_single_use_key_idx;
CREATE UNIQUE INDEX oauth_token_issuances_single_use_key_idx
    ON oauth_token_issuances (client_id, single_use_key_blake3)
    WHERE single_use_key_blake3 IS NOT NULL;
